package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SSHControlAgent exposes only the model control plane, bound by the engine to
// the original conversation. The model cannot supply another session key.
type SSHControlAgent interface {
	SetSSHControl(func(context.Context, string, string, string) (SSHResponse, error))
}

// SSHCommandRunner executes on the selected target, never on the gateway.
type SSHCommandRunner interface {
	RunCommand(context.Context, string) (string, int, error)
}

type SSHBackendView struct {
	Backend    string `json:"backend"`
	Type       string `json:"type"`
	Current    bool   `json:"current"`
	AutoSwitch bool   `json:"auto_switch"`
	Cwd        string `json:"cwd,omitempty"`
}

type SSHResponse struct {
	Status           string           `json:"status"`
	CurrentBackend   string           `json:"current_backend"`
	Message          string           `json:"message"`
	Backends         []SSHBackendView `json:"backends,omitempty"`
	Cwd              string           `json:"cwd,omitempty"`
	PendingBackend   string           `json:"pending_backend,omitempty"`
	ApprovalRequired bool             `json:"approval_required,omitempty"`
}

type sshAgentKey struct{ session, backend, cwd string }
type sshReplyRoute struct {
	platform Platform
	replyCtx any
}

// SetSSHMode is startup configuration. Each Engine/project owns a distinct
// store; every entry within it uses the full platform/conversation/thread key.
func (e *Engine) SetSSHMode(mode *SSHMode, factory func(SSHTarget, string) (Agent, error)) {
	e.sshMu.Lock()
	defer e.sshMu.Unlock()
	e.sshMode = mode
	e.sshFactory = factory
	e.sshAgents = make(map[sshAgentKey]Agent)
	e.sshPending = make(map[string]SSHBinding)
	e.sshRoutes = make(map[string]sshReplyRoute)
	e.sshManagers = make(map[string]*SessionManager)
}

func (e *Engine) sshRemote(key string) bool {
	return e.sshMode != nil && e.sshMode.CurrentBackend(key) != "local"
}

func sshNativeScope(binding SSHBinding) string {
	if binding.Alias == "" || binding.Alias == "local" {
		return ""
	}
	return fmt.Sprintf("ssh:%x", sha256.Sum256([]byte(binding.Alias+"\x00"+binding.Cwd)))
}

// Caller holds sshMu. Factories must not start a process; StartSession owns it.
func (e *Engine) sshAgentLocked(key string, binding SSHBinding) (Agent, error) {
	target, ok := e.sshMode.Target(binding.Alias)
	if !ok || e.sshFactory == nil {
		return nil, errors.New(e.i18n.T(MsgSSHUnavailable))
	}
	cacheKey := sshAgentKey{key, binding.Alias, binding.Cwd}
	if agent := e.sshAgents[cacheKey]; agent != nil {
		return agent, nil
	}
	agent, err := e.sshFactory(target, binding.Cwd)
	if err != nil || agent == nil {
		return nil, errors.New(e.i18n.T(MsgSSHUnavailable))
	}
	if control, ok := agent.(SSHControlAgent); ok {
		control.SetSSHControl(func(ctx context.Context, action, backend, cwd string) (SSHResponse, error) {
			return e.SSHRequest(ctx, key, action, backend, cwd)
		})
	}
	e.sshAgents[cacheKey] = agent
	return agent, nil
}

func (e *Engine) sshContext(key string) (Agent, *SessionManager, string, error) {
	e.sshMu.Lock()
	defer e.sshMu.Unlock()
	binding, ok := e.sshMode.Binding(key)
	if !ok {
		return nil, nil, "", errors.New(e.i18n.T(MsgSSHUnavailable))
	}
	agent, err := e.sshAgentLocked(key, binding)
	sessions := e.sshManagers[key]
	if sessions == nil {
		_, sessions = e.localSessionContextForKey(key)
		e.sshManagers[key] = sessions
	}
	return agent, sessions, binding.Cwd, err
}

func (e *Engine) sshSnapshotLocked(key string) SSHResponse {
	r := SSHResponse{Status: "ok", CurrentBackend: e.sshMode.CurrentBackend(key)}
	binding, _ := e.sshMode.Binding(key)
	r.Cwd = binding.Cwd
	r.Backends = append(r.Backends, SSHBackendView{Backend: "local", Type: "local", Current: r.CurrentBackend == "local", AutoSwitch: e.sshMode.AutoEnabled(key, "local")})
	for _, target := range e.sshMode.Targets() {
		cwd := target.Cwd
		if target.Alias == r.CurrentBackend {
			cwd = r.Cwd
		}
		r.Backends = append(r.Backends, SSHBackendView{Backend: target.Alias, Type: "ssh", Current: target.Alias == r.CurrentBackend, AutoSwitch: e.sshMode.AutoEnabled(key, target.Alias), Cwd: cwd})
	}
	r.Message = e.i18n.Tf(MsgSSHCurrent, r.CurrentBackend, r.Cwd)
	if pending, ok := e.sshPending[key]; ok {
		r.Status = "switch_pending"
		r.PendingBackend = pending.Alias
		r.Message += "\n" + e.i18n.Tf(MsgSSHPending, pending.Alias)
	}
	return r
}

// SSHRequest is deliberately narrower than the human /ssh command. A live
// process cannot migrate hosts: use is deferred until its turn has finished.
func (e *Engine) SSHRequest(ctx context.Context, sessionKey, action, backend, cwd string) (SSHResponse, error) {
	if err := ctx.Err(); err != nil {
		return SSHResponse{Status: "error"}, err
	}
	return e.sshRequest(sessionKey, action, backend, cwd, false)
}

func (e *Engine) sshRequest(key, action, backend, cwd string, human bool) (SSHResponse, error) {
	e.sshMu.Lock()
	defer e.sshMu.Unlock()
	fail := func(err error) (SSHResponse, error) { return SSHResponse{Status: "error", Message: err.Error()}, err }
	if e.sshMode == nil || !sshValidSession(key) {
		return fail(errors.New(e.i18n.T(MsgSSHUnavailable)))
	}
	if !human && action != "list" && action != "status" && action != "test" && action != "use" {
		return fail(errors.New(e.i18n.T(MsgSSHUsage)))
	}
	switch action {
	case "list", "status":
		if backend != "" || cwd != "" {
			return fail(errors.New(e.i18n.T(MsgSSHUsage)))
		}
		return e.sshSnapshotLocked(key), nil
	case "test":
		if cwd != "" {
			return fail(errors.New(e.i18n.T(MsgSSHUsage)))
		}
		if backend == "" {
			backend = e.sshMode.CurrentBackend(key)
		}
		if err := e.sshMode.Validate(backend); err != nil {
			return fail(err)
		}
		if target, ok := e.sshMode.Target(backend); ok {
			if err := target.Validate(); err != nil {
				return fail(err)
			}
		}
		r := e.sshSnapshotLocked(key)
		r.Message = e.i18n.Tf(MsgSSHTest, backend)
		return r, nil
	case "on", "off":
		if !human || cwd != "" {
			return fail(errors.New(e.i18n.T(MsgSSHUsage)))
		}
		if backend == "" {
			backend = "all"
		}
		if err := e.sshMode.SetAuto(key, backend, action == "on"); err != nil {
			return fail(err)
		}
		if action == "off" {
			if pending, ok := e.sshPending[key]; ok && (backend == "all" || backend == pending.Alias) {
				delete(e.sshPending, key)
			}
		}
		r := e.sshSnapshotLocked(key)
		r.Message = e.i18n.Tf(MsgSSHAuto, backend, action) + "\n" + r.Message
		return r, nil
	case "use":
		if err := e.sshMode.Validate(backend); err != nil {
			return fail(err)
		}
		if err := sshValidateCwd(cwd); err != nil {
			return fail(err)
		}
		if backend == "local" && cwd != "" {
			return fail(errors.New(e.i18n.T(MsgSSHUsage)))
		}
		target, _ := e.sshMode.Target(backend)
		if cwd == "" {
			cwd = target.Cwd
		}
		binding := SSHBinding{Alias: backend, Cwd: cwd}
		current, _ := e.sshMode.Binding(key)
		if current.Alias == "" {
			current.Alias = "local"
		}
		if current == binding {
			delete(e.sshPending, key)
			return e.sshSnapshotLocked(key), nil
		}
		if !human && !e.sshMode.CanAutoSwitch(key, backend) {
			r := e.sshSnapshotLocked(key)
			r.Status = "approval_required"
			r.ApprovalRequired = true
			command := "/ssh use " + backend
			if cwd != "" {
				command += " " + sshQuote(cwd)
			}
			r.Message = e.i18n.Tf(MsgSSHApproval, command)
			if route, ok := e.sshRoutes[key]; ok {
				e.reply(route.platform, route.replyCtx, r.Message)
			}
			return r, nil
		}
		sessions := e.sshManagers[key]
		if sessions == nil {
			_, sessions = e.localSessionContextForKey(key)
		}
		session := sessions.GetOrCreateActive(key)
		if !session.TryLock() {
			if human {
				return fail(errors.New(e.i18n.T(MsgSSHBusy)))
			}
			e.sshPending[key] = binding
			return e.sshSnapshotLocked(key), nil
		}
		defer session.UnlockWithoutUpdate()
		if err := e.sshSwitchLocked(key, binding, session, sessions); err != nil {
			return fail(err)
		}
		return e.sshSnapshotLocked(key), nil
	default:
		return fail(errors.New(e.i18n.T(MsgSSHUsage)))
	}
}

// The conversation lane is locked before this function. Validate/create before
// persistence and tear-down, so failure never changes the selected backend.
func (e *Engine) sshSwitchLocked(key string, binding SSHBinding, session *Session, sessions *SessionManager) error {
	if binding.Alias != "local" {
		if _, err := e.sshAgentLocked(key, binding); err != nil {
			return err
		}
	}
	oldKey := e.interactiveKeyForSessionKey(key)
	if err := e.sshMode.Use(key, binding.Alias, binding.Cwd); err != nil {
		return err
	}
	e.cleanupInteractiveState(oldKey)
	e.sshManagers[key] = sessions
	session.SelectAgentScope(sshNativeScope(binding))
	sessions.Save()
	delete(e.sshPending, key)
	return nil
}

func (e *Engine) sshHasPending(key string) bool {
	if e.sshMode == nil {
		return false
	}
	e.sshMu.Lock()
	defer e.sshMu.Unlock()
	_, ok := e.sshPending[key]
	return ok
}

// Called only after EventResult/Send completion, with the conversation lane
// still locked. Queued user messages are replayed through full routing rather
// than sent to the old native process. Nothing is silently dropped.
func (e *Engine) finishSSHPending(state *interactiveState, session *Session, sessions *SessionManager, key string) bool {
	if !e.sshHasPending(key) {
		return false
	}
	e.sshMu.Lock()
	binding, ok := e.sshPending[key]
	if !ok {
		e.sshMu.Unlock()
		return false
	}
	state.mu.Lock()
	if state.eventsNeedResync || state.stopped {
		state.mu.Unlock()
		delete(e.sshPending, key)
		e.sshMu.Unlock()
		e.reply(state.platform, state.replyCtx, e.i18n.T(MsgSSHUnavailable))
		return false
	}
	queue := state.pendingMessages
	state.pendingMessages = nil
	state.mu.Unlock()
	err := e.sshSwitchLocked(key, binding, session, sessions)
	if err != nil {
		delete(e.sshPending, key)
		state.mu.Lock()
		state.pendingMessages = append(queue, state.pendingMessages...)
		state.mu.Unlock()
		e.sshMu.Unlock()
		e.reply(state.platform, state.replyCtx, e.i18n.T(MsgSSHUnavailable))
		return false
	}
	e.sshMu.Unlock()
	if len(queue) == 0 {
		session.Unlock()
		return true
	}
	first := queue[0]
	next := e.interactiveKeyForSessionKey(key)
	e.ensureInteractiveStateForQueueing(next, first.platform, first.replyCtx)
	e.interactiveMu.Lock()
	newState := e.interactiveStates[next]
	e.interactiveMu.Unlock()
	newState.mu.Lock()
	newState.pendingMessages = append(newState.pendingMessages, queue[1:]...)
	newState.mu.Unlock()
	msg := &Message{SessionKey: key, Platform: first.msgPlatform, ReplyCtx: first.replyCtx, UserID: first.userID, UserName: first.userName, Content: first.content, Images: first.images, Files: first.files, MessageID: first.messageID, FromVoice: first.fromVoice, UserMessageTimeMs: first.userMessageTimeMs, ChannelKey: first.channelKey}
	e.processInteractiveMessageWith(first.platform, msg, session, e.agent, sessions, next, "", key)
	return true
}

func (e *Engine) cmdSSH(p Platform, msg *Message, args []string) {
	action, backend, cwd := "status", "", ""
	if len(args) > 0 {
		action = args[0]
	}
	if len(args) > 1 {
		backend = args[1]
	}
	switch len(args) {
	case 0, 1, 2:
	case 3:
		if strings.HasPrefix(args[2], "-") {
			e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUsage))
			return
		}
		cwd = args[2] // retain the initial positional form
	case 4:
		if action != "use" || args[2] != "--cwd" {
			e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUsage))
			return
		}
		cwd = args[3]
	default:
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUsage))
		return
	}
	if (action == "on" || action == "off" || action == "use") && !e.isAdmin(msg.UserID) {
		e.reply(p, msg.ReplyCtx, e.i18n.Tf(MsgAdminRequired, "/ssh "+action))
		return
	}
	r, err := e.sshRequest(msg.SessionKey, action, backend, cwd, true)
	if err != nil {
		e.reply(p, msg.ReplyCtx, e.i18n.Tf(MsgError, err))
		return
	}
	text := r.Message
	if action == "list" {
		for _, b := range r.Backends {
			text += fmt.Sprintf("\n%s  current=%t  auto_switch=%t  %s", b.Backend, b.Current, b.AutoSwitch, b.Cwd)
		}
	}
	e.reply(p, msg.ReplyCtx, text)
}

// Conservative allowlist: commands that inspect gateway-owned configuration,
// skills, history paths, credentials or native file affordances fail closed.
func sshCommandAllowed(cmd string) bool {
	switch cmd {
	case "ssh", "stop", "interrupt", "cancel", "new", "history", "search", "name", "list", "switch", "current", "status", "dir", "shell", "diff", "show", "help", "lang", "whoami", "version", "thread", "steer", "ps":
		return true
	}
	return false
}

func sshQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func sshShellPath(s string) string {
	if s == "~" {
		return `"$HOME"`
	}
	if strings.HasPrefix(s, "~/") {
		return `"$HOME"/` + sshQuote(s[2:])
	}
	return sshQuote(s)
}

func (e *Engine) sshRun(p Platform, msg *Message, command string, timeout time.Duration) {
	agent, _, _, err := e.sshContext(msg.SessionKey)
	if err != nil {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUnavailable))
		return
	}
	runner, ok := agent.(SSHCommandRunner)
	if !ok {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUnsupported))
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, timeout)
	defer cancel()
	output, exit, err := runner.RunCommand(ctx, command)
	if err != nil {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUnavailable))
		return
	}
	if output == "" {
		output = e.i18n.T(MsgSSHEmptyOutput)
	}
	e.reply(p, msg.ReplyCtx, e.i18n.Tf(MsgSSHCommandOutput, exit, truncateStr(output, 12000)))
}

func (e *Engine) cmdSSHDir(p Platform, msg *Message, args []string) {
	if len(args) == 0 {
		r, _ := e.SSHRequest(e.ctx, msg.SessionKey, "status", "", "")
		e.reply(p, msg.ReplyCtx, r.Message)
		return
	}
	if len(args) != 1 || sshHasControl(args[0]) {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUsage))
		return
	}
	e.sshMu.Lock()
	defer e.sshMu.Unlock()
	sessions := e.sshManagers[msg.SessionKey]
	if sessions == nil {
		_, sessions = e.localSessionContextForKey(msg.SessionKey)
		e.sshManagers[msg.SessionKey] = sessions
	}
	session := sessions.GetOrCreateActive(msg.SessionKey)
	if !session.TryLock() {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHBusy))
		return
	}
	defer session.UnlockWithoutUpdate()
	binding, _ := e.sshMode.Binding(msg.SessionKey)
	agent, err := e.sshAgentLocked(msg.SessionKey, binding)
	if err != nil {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUnavailable))
		return
	}
	runner, ok := agent.(SSHCommandRunner)
	if !ok {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUnsupported))
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	output, exit, err := runner.RunCommand(ctx, "cd -- "+sshShellPath(args[0])+" && pwd -P")
	cwd := strings.TrimSpace(output)
	if err != nil || exit != 0 || !strings.HasPrefix(cwd, "/") || sshValidateCwd(cwd) != nil {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUnavailable))
		return
	}
	binding.Cwd = cwd
	if err := e.sshSwitchLocked(msg.SessionKey, binding, session, sessions); err != nil {
		e.reply(p, msg.ReplyCtx, e.i18n.T(MsgSSHUnavailable))
		return
	}
	e.reply(p, msg.ReplyCtx, e.i18n.Tf(MsgDirChanged, cwd))
}

// Used by legacy read-only helpers whose signature cannot return an error.
// No capability interfaces are implemented, preventing any local fallback.
type failedSSHAgent struct{}

func (failedSSHAgent) Name() string { return "ssh" }
func (failedSSHAgent) StartSession(context.Context, string) (AgentSession, error) {
	return nil, errors.New("SSH unavailable")
}
func (failedSSHAgent) ListSessions(context.Context) ([]AgentSessionInfo, error) {
	return nil, errors.New("SSH unavailable")
}
func (failedSSHAgent) Stop() error { return nil }
