package sshagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

const maxControlRequests = 16
const maxControlBytes = 64 << 10
const controlTimeout = 30 * time.Second

var errControlUnavailable = errors.New("ssh: control unavailable; native agent must support session environment injection")

// No project, session, registry or grant fields cross the connection. The
// gateway's callback captures the original conversation and is authoritative.
type controlArgs struct {
	Action  string `json:"action"`
	Backend string `json:"backend,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
}
type controlCancel struct {
	ID uint64 `json:"id"`
}

func strictDecode(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("invalid trailing data")
	}
	return nil
}
func validControl(args controlArgs) bool {
	if hasControl(args.Backend) || hasControl(args.Cwd) {
		return false
	}
	switch args.Action {
	case "list", "status":
		return args.Backend == "" && args.Cwd == ""
	case "test":
		return agentPattern.MatchString(args.Backend) && args.Cwd == ""
	case "use":
		return agentPattern.MatchString(args.Backend)
	default:
		return false
	}
}

// Dispatch outside readLoop: a callback may itself request metadata or Stop
// this agent. Close must never wait for its caller. Handlers receive a bounded
// lifetime context and must honor cancellation; outstanding callbacks remain
// counted until they actually return (even after individual request cancel).
func (c *connection) dispatchControl(p packet) bool {
	var args controlArgs
	if c.control == nil || p.Method != "ssh_control" || p.Error != nil || len(p.Result) != 0 || len(p.Params) > maxControlBytes || strictDecode(p.Params, &args) != nil || !validControl(args) {
		return false
	}
	c.mu.Lock()
	if p.ID <= c.controlLastID || len(c.controls) >= maxControlRequests {
		c.mu.Unlock()
		return false
	}
	ctx, cancel := context.WithTimeout(c.ctx, controlTimeout)
	c.controlLastID = p.ID
	c.controls[p.ID] = cancel
	c.mu.Unlock()
	go func() {
		defer cancel()
		defer func() { c.mu.Lock(); delete(c.controls, p.ID); c.mu.Unlock() }()
		r, err := c.control(ctx, args.Action, args.Backend, args.Cwd)
		reply := packet{ID: p.ID}
		if err == nil && ctx.Err() == nil {
			switch r.Status {
			case "ok", "approval_required", "switch_pending":
				reply.Result, err = encode(r)
			default:
				err = errors.New("invalid control status")
			}
		} else {
			err = errDisconnected
		}
		if err != nil {
			reply.Result = nil
			reply.Error = &rpcError{Code: -32000, Message: "ssh: control request failed"}
		}
		if c.writer.write(reply) != nil {
			c.cancel()
		}
	}()
	return true
}
func (c *connection) cancelControl(data []byte) bool {
	var args controlCancel
	if strictDecode(data, &args) != nil || args.ID == 0 {
		return false
	}
	c.mu.Lock()
	cancel := c.controls[args.ID]
	valid := args.ID <= c.controlLastID
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return valid // a cancellation may race a completed response
}

type workerControl struct {
	ctx       context.Context
	writer    *packetWriter
	dir       string
	server    *http.Server
	serveDone chan struct{}
	mu        sync.Mutex
	nextID    uint64
	pending   map[uint64]chan packet
	closed    bool
	handlers  sync.WaitGroup
}

func newWorkerControl(ctx context.Context, writer *packetWriter) (*workerControl, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("ssh worker: control home unavailable")
	}
	root := os.Getenv("CHATARCH_HOME")
	if root == "" {
		root = filepath.Join(home, ".chatarch")
	}
	if !filepath.IsAbs(root) || hasControl(root) {
		return nil, errors.New("ssh worker: invalid control runtime root")
	}
	root = filepath.Join(root, "cc-connect", "run")
	// MkdirTemp uses up to ten decimal suffix digits. Leave room for the NUL
	// terminator on Unix platforms with a 104-byte sockaddr_un.sun_path.
	if len(filepath.Join(root, "s1234567890", "run", "api.sock")) >= 104 {
		return nil, errors.New("ssh worker: control runtime path too long")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, errors.New("ssh worker: cannot create control runtime root")
	}
	dir, err := os.MkdirTemp(root, "s")
	if err != nil {
		return nil, errors.New("ssh worker: cannot create private control directory")
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := os.Mkdir(filepath.Join(dir, "run"), 0700); err != nil {
		return nil, errors.New("ssh worker: cannot create control socket directory")
	}
	path := filepath.Join(dir, "run", "api.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("ssh worker: cannot listen on private control socket")
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, errors.New("ssh worker: cannot protect control socket")
	}
	c := &workerControl{ctx: ctx, writer: writer, dir: dir, pending: make(map[uint64]chan packet), serveDone: make(chan struct{})}
	c.server = &http.Server{Handler: http.HandlerFunc(c.serveHTTP), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: controlTimeout + 5*time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { defer close(c.serveDone); _ = c.server.Serve(listener) }()
	keep = true
	return c, nil
}
func (c *workerControl) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	_ = c.server.Close()
	<-c.serveDone
	c.handlers.Wait()
	_ = os.RemoveAll(c.dir) // only the directory created by this worker
}
func (c *workerControl) serveHTTP(out http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		http.Error(out, "control closed", http.StatusServiceUnavailable)
		return
	}
	c.handlers.Add(1)
	c.mu.Unlock()
	defer c.handlers.Done()
	// Do not use ServeMux: its redirects would normalize unauthorized routes.
	if req.URL.Path != "/ssh" || req.URL.RawPath != "" || req.URL.RawQuery != "" || req.URL.ForceQuery {
		http.Error(out, "not found", http.StatusNotFound)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(out, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var args struct {
		Project    string `json:"project"`
		SessionKey string `json:"session_key"`
		controlArgs
	}
	body, err := io.ReadAll(http.MaxBytesReader(out, req.Body, maxControlBytes))
	if err != nil || strictDecode(body, &args) != nil || !validControl(args.controlArgs) {
		http.Error(out, "invalid SSH request", http.StatusBadRequest)
		return
	}
	if args.Project != "ssh-worker" || args.SessionKey != "remote" {
		http.Error(out, "foreign conversation", http.StatusForbidden)
		return
	}
	r, err := c.call(req.Context(), args.controlArgs)
	if err != nil {
		http.Error(out, "SSH control request failed", http.StatusBadGateway)
		return
	}
	out.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(out).Encode(r)
}
func (c *workerControl) call(parent context.Context, args controlArgs) (core.SSHResponse, error) {
	ctx, cancel := context.WithTimeout(parent, controlTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return core.SSHResponse{}, err
	}
	data, err := encode(args)
	if err != nil {
		return core.SSHResponse{}, err
	}
	c.mu.Lock()
	if c.closed || len(c.pending) >= maxControlRequests {
		c.mu.Unlock()
		return core.SSHResponse{}, errors.New("ssh worker: control busy")
	}
	c.nextID++
	id := c.nextID
	response := make(chan packet, 1)
	c.pending[id] = response
	// Hold the ID mutex through write so concurrent requests cannot arrive out
	// of order relative to the gateway's monotonic anti-replay check.
	err = c.writer.write(packet{ID: id, Method: "ssh_control", Params: data})
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }()
	if err != nil {
		return core.SSHResponse{}, err
	}
	var p packet
	select {
	case p = <-response:
	case <-ctx.Done():
		data, _ := encode(controlCancel{ID: id})
		_ = c.writer.write(packet{Method: "ssh_control_cancel", Params: data})
		return core.SSHResponse{}, ctx.Err()
	case <-c.ctx.Done():
		return core.SSHResponse{}, errDisconnected
	}
	if p.Error != nil {
		return core.SSHResponse{}, errors.New("ssh worker: control request failed")
	}
	var r core.SSHResponse
	if json.Unmarshal(p.Result, &r) != nil {
		return r, errors.New("ssh worker: invalid control response")
	}
	return r, nil
}
func (c *workerControl) deliver(p packet) bool {
	if p.ID == 0 || p.Method != "" || len(p.Params) != 0 || (p.Error == nil) == (len(p.Result) == 0) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	response := c.pending[p.ID]
	if response == nil {
		return p.ID <= c.nextID
	} // ignore late canceled replies
	select {
	case response <- p:
		return true
	default:
		return false
	}
}
