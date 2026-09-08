package sshagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sync"

	"github.com/chenhg5/cc-connect/core"
)

// ServeWorker serves exactly one connection. The executable must import its
// native agent plugins before calling this function; no platform/config is
// loaded here. Authentication and CLI installation belong to the target.
// For cancellable blocking input, in must implement io.Closer (as stdin does).
// On cancellation the owned stream is closed to unblock reads. EOF closes all
// sessions and stops the agent before return. No local env is reconstructed.
func ServeWorker(parent context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	w := &worker{ctx: ctx, cancel: cancel, writer: packetWriter{out: out, ctx: ctx, cancel: cancel}}
	watchDone := make(chan struct{})
	watchExited := make(chan struct{})
	go func() {
		defer close(watchExited)
		select {
		case <-ctx.Done():
			if c, ok := in.(io.Closer); ok {
				_ = c.Close()
			}
		case <-watchDone:
		}
	}()
	defer func() { close(watchDone); <-watchExited }()
	defer w.close()
	scan := scanner(in)
	if !scan.Scan() {
		if scan.Err() != nil {
			return errors.New("ssh worker: invalid input")
		}
		return parent.Err()
	}
	p, args, err := decodeRequest(scan.Bytes())
	if err != nil || p.Method != "initialize" {
		return errors.New("ssh worker: initialization required")
	}
	if !agentPattern.MatchString(args.AgentType) || hasControl(args.WorkDir) {
		w.reply(p.ID, result{}, errors.New("invalid initialization"))
		return errors.New("ssh worker: invalid initialization")
	}
	safe, err := safeAgentOptions(args.Options)
	if err != nil || len(safe) != len(args.Options) {
		w.reply(p.ID, result{}, errors.New("invalid initialization options"))
		return errors.New("ssh worker: invalid initialization options")
	}
	args.Options = safe
	if cmd, ok := args.Options["cmd"].(string); ok {
		args.Options["cmd"], err = expandHome(cmd)
		if err != nil {
			w.reply(p.ID, result{}, errors.New("invalid native command path"))
			return errors.New("ssh worker: invalid native command path")
		}
	}
	args.WorkDir, err = expandHome(args.WorkDir)
	if err != nil {
		w.reply(p.ID, result{}, errors.New("invalid work directory"))
		return errors.New("ssh worker: invalid work directory")
	}
	// Only the explicitly supplied remote directory is authoritative.
	args.Options["work_dir"] = args.WorkDir
	agent, err := core.CreateAgent(args.AgentType, args.Options)
	if err != nil {
		w.reply(p.ID, result{}, errors.New("agent initialization failed; install and authorize the native agent on the target"))
		return errors.New("ssh worker: agent initialization failed")
	}
	w.agent = agent
	w.workDir = args.WorkDir
	if args.ControlEnabled {
		injector, ok := agent.(core.SessionEnvInjector)
		if !ok {
			w.reply(p.ID, result{}, errControlUnavailable)
			return errControlUnavailable
		}
		w.control, err = newWorkerControl(ctx, &w.writer)
		if err != nil {
			w.reply(p.ID, result{}, err)
			return err
		}
		injector.SetSessionEnv([]string{"CC_PROJECT=ssh-worker", "CC_SESSION_KEY=remote", "CC_DATA_DIR=" + w.control.dir})
	}
	w.reply(p.ID, result{}, nil)
	slots := make(chan struct{}, 64)
	for scan.Scan() {
		var envelope packet
		if json.Unmarshal(scan.Bytes(), &envelope) != nil || envelope.JSONRPC != "2.0" {
			return errors.New("ssh worker: invalid packet")
		}
		if envelope.Method == "" {
			if w.control == nil || !w.control.deliver(envelope) {
				return errors.New("ssh worker: invalid control response")
			}
			continue
		}
		p, args, err := decodeRequest(scan.Bytes())
		if err != nil {
			return errors.New("ssh worker: invalid request")
		}
		// Never block the response reader behind handlers waiting for control RPC.
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		default:
			return errors.New("ssh worker: too many requests")
		}
		w.requests.Add(1)
		go func(p packet, args requestArgs) {
			defer w.requests.Done()
			defer func() { <-slots }()
			r, err := w.handle(p.Method, args)
			w.reply(p.ID, r, err)
		}(p, args)
	}
	if scan.Err() != nil && ctx.Err() == nil {
		return errors.New("ssh worker: invalid input")
	}
	return parent.Err()
}

func decodeRequest(b []byte) (packet, requestArgs, error) {
	var p packet
	var args requestArgs
	if json.Unmarshal(b, &p) != nil || p.JSONRPC != "2.0" || p.ID == 0 || p.Method == "" || p.Error != nil || len(p.Result) != 0 {
		return p, args, errors.New("invalid request")
	}
	if len(p.Params) > 0 && json.Unmarshal(p.Params, &args) != nil {
		return p, args, errors.New("invalid parameters")
	}
	return p, args, nil
}

type worker struct {
	ctx      context.Context
	cancel   context.CancelFunc
	writer   packetWriter
	agent    core.Agent
	control  *workerControl
	workDir  string
	mu       sync.Mutex
	session  core.AgentSession
	starting bool
	requests sync.WaitGroup
	events   sync.WaitGroup
}

func (w *worker) close() {
	w.cancel()
	if w.control != nil {
		w.control.close()
	}
	w.mu.Lock()
	s := w.session
	w.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
	w.requests.Wait()
	w.events.Wait()
	if w.agent != nil {
		_ = w.agent.Stop()
	}
}
func (w *worker) reply(id uint64, r result, err error) {
	p := packet{ID: id}
	if err != nil {
		code := -32000
		if errors.Is(err, errControlUnavailable) {
			code = -32001
		}
		p.Error = &rpcError{Code: code, Message: "ssh worker: " + err.Error()}
	} else {
		var e error
		p.Result, e = encode(r)
		if e != nil {
			p.Error = &rpcError{Code: -32000, Message: "ssh worker: response exceeds size limit"}
		}
	}
	if w.writer.write(p) != nil {
		w.cancel()
	}
}
func (w *worker) state() (core.AgentSession, result) {
	w.mu.Lock()
	s := w.session
	w.mu.Unlock()
	if s == nil {
		return nil, result{}
	}
	return s, result{SessionID: s.CurrentSessionID(), Alive: s.Alive()}
}
func (w *worker) handle(method string, args requestArgs) (result, error) {
	switch method {
	case "start":
		return w.start(args.SessionID)
	case "list":
		sessions, err := w.agent.ListSessions(w.ctx)
		if err != nil {
			return result{}, errors.New("session listing failed")
		}
		return result{Sessions: sessions}, nil
	case "metadata":
		r := result{}
		if a, ok := w.agent.(core.ModelSwitcher); ok {
			r.Models = a.AvailableModels(w.ctx)
		}
		if a, ok := w.agent.(core.ModeSwitcher); ok {
			r.Modes = a.PermissionModes()
		}
		return r, nil
	case "exec":
		return w.runCommand(args.Command)
	case "send", "permission", "state", "close":
		s, r := w.state()
		if s == nil {
			return r, errors.New("session not started")
		}
		var err error
		switch method {
		case "send":
			err = s.Send(args.Prompt, args.Images, args.Files)
		case "permission":
			err = s.RespondPermission(args.RequestID, args.Permission)
		case "close":
			err = s.Close()
		}
		if err != nil {
			return result{}, errors.New("session operation failed")
		}
		_, r = w.state()
		return r, nil
	default:
		return result{}, errors.New("unknown method")
	}
}
func (w *worker) start(id string) (result, error) {
	w.mu.Lock()
	if w.starting || w.session != nil {
		w.mu.Unlock()
		return result{}, errors.New("session already started")
	}
	w.starting = true
	w.mu.Unlock()
	s, err := w.agent.StartSession(w.ctx, id)
	w.mu.Lock()
	w.starting = false
	if err != nil {
		w.mu.Unlock()
		return result{}, errors.New("session start failed")
	}
	if w.ctx.Err() != nil {
		w.mu.Unlock()
		_ = s.Close()
		return result{}, errors.New("session start canceled")
	}
	w.session = s
	w.events.Add(1)
	w.mu.Unlock()
	go w.forwardEvents(s)
	return result{SessionID: s.CurrentSessionID(), Alive: s.Alive()}, nil
}
func (w *worker) forwardEvents(s core.AgentSession) {
	defer w.events.Done()
	for {
		select {
		case <-w.ctx.Done():
			return
		case e, ok := <-s.Events():
			if !ok {
				if w.writer.write(packet{Method: "session_closed"}) != nil {
					w.cancel()
				}
				return
			}
			text := ""
			if e.Error != nil || e.Type == core.EventError {
				text = "ssh worker: native agent reported an error"
				e.Error = nil
				e.Content = ""
			}
			args, err := encode(eventMessage{Event: e, ErrorText: text, SessionID: s.CurrentSessionID(), Alive: s.Alive()})
			if err != nil || w.writer.write(packet{Method: "event", Params: args}) != nil {
				w.cancel()
				return
			}
		}
	}
}

// cappedOutput always consumes writes so output floods cannot deadlock a child.
type cappedOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	left := maxCommandOutput - len(b.data)
	if len(p) > left {
		p = p[:left]
		b.truncated = true
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (b *cappedOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := string(b.data)
	if b.truncated {
		s += "\n[output truncated]\n"
	}
	return s
}
func (w *worker) runCommand(command string) (result, error) {
	cmd := exec.CommandContext(w.ctx, "sh", "-c", command)
	cmd.Dir = w.workDir
	configureCommandProcess(cmd)
	output := &cappedOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if w.ctx.Err() != nil {
		return result{}, errors.New("command canceled")
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return result{}, errors.New("command could not start")
		}
		code = exit.ExitCode()
	}
	return result{Output: output.String(), ExitCode: code}, nil
}
