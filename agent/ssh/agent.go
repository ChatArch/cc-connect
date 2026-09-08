package sshagent

import (
	"context"

	"os/exec"
	"sync"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

// Agent is a transport, not a local native-agent instance. Option changes apply
// to future connections only; every session owns a separate SSH worker.
type Agent struct {
	mu          sync.Mutex
	opts        Options
	launch      func(context.Context) *exec.Cmd // subprocess seam; production uses command
	connections map[*connection]struct{}
	stopped     bool
	control     func(context.Context, string, string, string) (core.SSHResponse, error)
}

func New(opts Options) (core.Agent, error) {
	o, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	return &Agent{opts: o, connections: make(map[*connection]struct{})}, nil
}
func (a *Agent) Name() string { return a.opts.AgentType }

// SetSSHControl binds model requests to the caller's conversation scope.
// Changes apply to future connections; no gateway identifiers cross the wire.
func (a *Agent) SetSSHControl(handler func(context.Context, string, string, string) (core.SSHResponse, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.control = handler
}
func (a *Agent) SetWorkDir(v string)   { a.mu.Lock(); defer a.mu.Unlock(); a.opts.WorkDir = v }
func (a *Agent) GetWorkDir() string    { a.mu.Lock(); defer a.mu.Unlock(); return a.opts.WorkDir }
func (a *Agent) setOption(k, v string) { a.mu.Lock(); defer a.mu.Unlock(); a.opts.AgentOptions[k] = v }
func (a *Agent) getOption(k string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, _ := a.opts.AgentOptions[k].(string)
	return v
}
func (a *Agent) SetModel(v string) { a.setOption("model", v) }
func (a *Agent) GetModel() string  { return a.getOption("model") }
func (a *Agent) SetMode(v string)  { a.setOption("mode", v) }
func (a *Agent) GetMode() string   { return a.getOption("mode") }

func (a *Agent) connect(ctx context.Context) (*connection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return nil, errDisconnected
	}
	o, err := normalizeOptions(a.opts)
	launch := a.launch
	control := a.control
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	safe, err := safeAgentOptions(o.AgentOptions)
	if err != nil {
		return nil, err
	}
	c, err := newConnection(ctx, o, launch, control)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		c.close()
		return nil, errDisconnected
	}
	a.connections[c] = struct{}{}
	a.mu.Unlock()
	go func() { <-c.finished; a.mu.Lock(); delete(a.connections, c); a.mu.Unlock() }()
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err = c.call(initCtx, "initialize", requestArgs{AgentType: o.AgentType, Options: safe, WorkDir: o.WorkDir, ControlEnabled: control != nil})
	if err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}
func (a *Agent) StartSession(ctx context.Context, id string) (core.AgentSession, error) {
	// Reject oversized IDs before spawning a worker.
	if _, err := requestPacket(1, "start", requestArgs{SessionID: id}); err != nil {
		return nil, err
	}
	c, err := a.connect(ctx)
	if err != nil {
		return nil, err
	}
	startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.call(startCtx, "start", requestArgs{SessionID: id})
	if err != nil {
		c.close()
		return nil, err
	}
	c.setState(r.SessionID, r.Alive)
	return &session{conn: c}, nil
}
func (a *Agent) once(ctx context.Context, method string, args requestArgs) (result, error) {
	if _, err := requestPacket(1, method, args); err != nil {
		return result{}, err
	}
	c, err := a.connect(ctx)
	if err != nil {
		return result{}, err
	}
	defer c.close()
	return c.call(ctx, method, args)
}
func (a *Agent) ListSessions(ctx context.Context) ([]core.AgentSessionInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := a.once(ctx, "list", requestArgs{})
	return r.Sessions, err
}
func (a *Agent) AvailableModels(ctx context.Context) []core.ModelOption {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, _ := a.once(ctx, "metadata", requestArgs{})
	return r.Models
}
func (a *Agent) PermissionModes() []core.PermissionModeInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, _ := a.once(ctx, "metadata", requestArgs{})
	return r.Modes
}
func (a *Agent) RunCommand(ctx context.Context, command string) (string, int, error) {
	r, err := a.once(ctx, "exec", requestArgs{Command: command})
	if err != nil {
		return "", -1, err
	}
	return r.Output, r.ExitCode, nil
}
func (a *Agent) Stop() error {
	a.mu.Lock()
	a.stopped = true
	cs := make([]*connection, 0, len(a.connections))
	for c := range a.connections {
		cs = append(cs, c)
	}
	a.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range cs {
		wg.Add(1)
		go func(c *connection) { defer wg.Done(); c.close() }(c)
	}
	wg.Wait()
	return nil
}

type session struct {
	conn      *connection
	closeOnce sync.Once
}

func (s *session) Send(prompt string, images []core.ImageAttachment, files []core.FileAttachment) error {
	// Attachments are raw bytes in core, never local filesystem paths. Native
	// agents materialize them on the target through their normal Send path.
	if !s.Alive() {
		return errDisconnected
	}
	_, err := s.conn.call(s.conn.ctx, "send", requestArgs{Prompt: prompt, Images: images, Files: files})
	return err
}
func (s *session) RespondPermission(id string, r core.PermissionResult) error {
	if !s.Alive() {
		return errDisconnected
	}
	ctx, cancel := context.WithTimeout(s.conn.ctx, 30*time.Second)
	defer cancel()
	_, err := s.conn.call(ctx, "permission", requestArgs{RequestID: id, Permission: r})
	return err
}
func (s *session) Events() <-chan core.Event { return s.conn.events }
func (s *session) CurrentSessionID() string {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	return s.conn.sessionID
}
func (s *session) Alive() bool {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	return s.conn.alive && s.conn.ctx.Err() == nil
}
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(s.conn.ctx, time.Second)
		defer cancel()
		if s.Alive() {
			_, _ = s.conn.call(ctx, "close", requestArgs{})
		}
		s.conn.close()
	})
	return nil
}

var _ core.Agent = (*Agent)(nil)
var _ core.WorkDirSwitcher = (*Agent)(nil)
var _ core.ModelSwitcher = (*Agent)(nil)
var _ core.ModeSwitcher = (*Agent)(nil)
var _ core.AgentSession = (*session)(nil)
var _ core.SSHControlAgent = (*Agent)(nil)
