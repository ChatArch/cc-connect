package sshagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

const shutdownGrace = time.Second
const writeTimeout = 5 * time.Second

// connection owns one child, its pipes, reader and waiter. Only readLoop closes
// events. Lifecycle waits for all owned goroutines before closing finished.
type connection struct {
	ctx           context.Context
	cancel        context.CancelFunc
	writer        packetWriter
	stdin         io.WriteCloser
	stdout        io.ReadCloser
	cmd           *exec.Cmd
	mu            sync.Mutex
	nextID        uint64
	pending       map[uint64]chan packet
	control       func(context.Context, string, string, string) (core.SSHResponse, error)
	controls      map[uint64]context.CancelFunc
	controlLastID uint64
	sessionID     string
	alive         bool
	events        chan core.Event
	readDone      chan struct{}
	finished      chan struct{}
}

func newConnection(parent context.Context, o Options, launch func(context.Context) *exec.Cmd, control func(context.Context, string, string, string) (core.SSHResponse, error)) (*connection, error) {
	ctx, cancel := context.WithCancel(context.Background())
	procCtx, kill := context.WithCancel(context.Background())
	var cmd *exec.Cmd
	if launch != nil {
		cmd = launch(procCtx)
	} else {
		tmp := &Agent{opts: o}
		cmd = tmp.command(procCtx)
	}
	configureCommandProcess(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		kill()
		return nil, errors.New("ssh: cannot create worker input")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		cancel()
		kill()
		return nil, errors.New("ssh: cannot create worker output")
	}
	// Never expose SSH diagnostics: they may contain local private paths or
	// credential-bearing ProxyCommand output. stdout belongs only to NDJSON.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		cancel()
		kill()
		return nil, errors.New("ssh: worker could not start")
	}
	c := &connection{ctx: ctx, cancel: cancel, stdin: stdin, stdout: stdout, cmd: cmd, pending: make(map[uint64]chan packet), control: control, controls: make(map[uint64]context.CancelFunc), events: make(chan core.Event, 256), readDone: make(chan struct{}), finished: make(chan struct{})}
	c.writer = packetWriter{out: stdin, ctx: ctx, cancel: cancel}
	go c.readLoop()
	go func() {
		defer close(c.finished)
		defer kill()
		select {
		case <-parent.Done():
		case <-ctx.Done():
		case <-c.readDone:
		}
		cancel()
		// EOF gives the worker a chance to cancel native sessions and reap children.
		_ = stdin.Close()
		waited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(waited) }()
		timer := time.NewTimer(shutdownGrace)
		select {
		case <-waited:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			kill()
			<-waited
		}
		_ = stdout.Close()
		<-c.readDone
	}()
	return c, nil
}
func (c *connection) close() { c.cancel(); <-c.finished }
func (c *connection) setState(id string, alive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id != "" {
		c.sessionID = id
	}
	c.alive = alive
}
func requestPacket(id uint64, method string, args requestArgs) (packet, error) {
	b, err := encode(args)
	if err != nil {
		return packet{}, err
	}
	p := packet{JSONRPC: "2.0", ID: id, Method: method, Params: b}
	if _, err := encode(p); err != nil {
		return packet{}, err
	}
	return p, nil
}
func (c *connection) call(ctx context.Context, method string, args requestArgs) (result, error) {
	// Use the largest possible ID for a precise preflight including the envelope.
	p, err := requestPacket(^uint64(0), method, args)
	if err != nil {
		return result{}, err
	}
	if err := ctx.Err(); err != nil {
		return result{}, err
	}
	c.mu.Lock()
	if len(c.pending) >= 64 {
		c.mu.Unlock()
		return result{}, errors.New("ssh: too many pending requests")
	}
	c.nextID++
	p.ID = c.nextID
	response := make(chan packet, 1)
	c.pending[p.ID] = response
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, p.ID); c.mu.Unlock() }()
	if err := c.writer.write(p); err != nil {
		return result{}, err
	}
	var reply packet
	select {
	case reply = <-response:
	case <-ctx.Done():
		select {
		case reply = <-response:
		default:
			c.cancel()
			return result{}, ctx.Err()
		}
	case <-c.ctx.Done():
		select {
		case reply = <-response:
		default:
			return result{}, errDisconnected
		}
	}
	if reply.Error != nil {
		if reply.Error.Code == -32001 {
			return result{}, errControlUnavailable
		}
		return result{}, errors.New("ssh: remote operation failed")
	}
	var r result
	if json.Unmarshal(reply.Result, &r) != nil {
		c.cancel()
		return result{}, errors.New("ssh: invalid worker response")
	}
	return r, nil
}
func (c *connection) readLoop() {
	defer close(c.readDone)
	eventsClosed := false
	closeEvents := func() {
		if !eventsClosed {
			close(c.events)
			eventsClosed = true
		}
	}
	defer closeEvents()
	var drainTimer *time.Timer
	defer func() {
		if drainTimer != nil {
			drainTimer.Stop()
		}
	}()
	defer c.cancel()
	scan := scanner(c.stdout)
	for scan.Scan() {
		var p packet
		if json.Unmarshal(scan.Bytes(), &p) != nil || p.JSONRPC != "2.0" {
			return
		}
		if p.ID != 0 {
			if p.Method != "" {
				if !c.dispatchControl(p) {
					return
				}
				continue
			}
			if len(p.Params) != 0 || (p.Error == nil) == (len(p.Result) == 0) {
				return
			}
			c.mu.Lock()
			ch := c.pending[p.ID]
			delete(c.pending, p.ID)
			pendingCount := len(c.pending)
			c.mu.Unlock()
			if ch == nil {
				return
			}
			select {
			case ch <- p:
				if eventsClosed && pendingCount == 0 {
					return
				}
			default:
				return
			}
			continue
		}
		if p.Error != nil || len(p.Result) != 0 {
			return
		}
		switch p.Method {
		case "ssh_control_cancel":
			if !c.cancelControl(p.Params) {
				return
			}
		case "session_closed":
			c.setState("", false)
			// Expose native EOF immediately, but allow already-in-flight RPC
			// acknowledgements to drain so cleanup cannot mask a real result.
			if eventsClosed {
				return
			}
			closeEvents()
			c.mu.Lock()
			pendingCount := len(c.pending)
			c.mu.Unlock()
			if pendingCount == 0 {
				return
			}
			drainTimer = time.AfterFunc(time.Second, c.cancel)
		case "event":
			if eventsClosed {
				return
			}
			var e eventMessage
			if json.Unmarshal(p.Params, &e) != nil {
				return
			}
			if e.ErrorText != "" {
				e.Event.Error = errors.New("ssh: native agent reported an error")
			}
			c.setState(e.SessionID, e.Alive)
			select {
			case c.events <- e.Event:
			default:
				return
			} // bounded backpressure: fail closed
		default:
			return
		}
	}
}
