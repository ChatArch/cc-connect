package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type sshTestAgent struct {
	stubAgent
	mu            sync.Mutex
	label, cwd    string
	starts        []string
	sessions      []*sshTestSession
	commands      []string
	commandOutput string
	commandExit   int
	listed        []AgentSessionInfo
	control       func(context.Context, string, string, string) (SSHResponse, error)
	prompt        string
	env           []string
	beforeSend    func(*sshTestSession, string) error
}

func (a *sshTestAgent) ListSessions(context.Context) ([]AgentSessionInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AgentSessionInfo(nil), a.listed...), nil
}
func (a *sshTestAgent) SetSSHControl(fn func(context.Context, string, string, string) (SSHResponse, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.control = fn
}
func (a *sshTestAgent) SetPlatformPrompt(prompt string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prompt = prompt
}
func (a *sshTestAgent) SetSessionEnv(env []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.env = append([]string(nil), env...)
}

type sshTestSession struct {
	*cujAgentSession
	id         string
	beforeSend func(*sshTestSession, string) error
}

func (s *sshTestSession) Send(prompt string, images []ImageAttachment, files []FileAttachment) error {
	if s.beforeSend != nil {
		if err := s.beforeSend(s, prompt); err != nil {
			return err
		}
	}
	return s.cujAgentSession.Send(prompt, images, files)
}
func (s *sshTestSession) CurrentSessionID() string { return s.id }
func (a *sshTestAgent) GetWorkDir() string         { return a.cwd }
func (a *sshTestAgent) SetWorkDir(w string)        { a.cwd = w }
func (a *sshTestAgent) StartSession(_ context.Context, id string) (AgentSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.starts = append(a.starts, id)
	s := &sshTestSession{cujAgentSession: newCUJAgentSession(), id: a.label + "-sid", beforeSend: a.beforeSend}
	if id != "" {
		s.id = id
	}
	s.reply = a.label + " reply"
	a.sessions = append(a.sessions, s)
	return s, nil
}
func (a *sshTestAgent) RunCommand(_ context.Context, command string) (string, int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.commands = append(a.commands, command)
	if a.commandOutput != "" {
		return a.commandOutput, a.commandExit, nil
	}
	return "remote-output", a.commandExit, nil
}

type sshTestEnv struct {
	e       *Engine
	p       *stubPlatformEngine
	mode    *SSHMode
	local   *sshTestAgent
	remotes []*sshTestAgent
	mu      sync.Mutex
}

func newSSHTestEnv(t *testing.T) *sshTestEnv {
	t.Helper()
	p := &stubPlatformEngine{n: "test"}
	local := &sshTestAgent{label: "local", cwd: t.TempDir()}
	e := NewEngine("ssh-test", local, []Platform{p}, "", LangEnglish)
	e.SetAdminFrom("*")
	mode, err := NewSSHMode("", []SSHTarget{{Alias: "remote", Host: "remote.example", User: "worker", Cwd: "/remote/work", IdentityFile: "/private/identity"}, {Alias: "other", Host: "other.example", User: "worker", Cwd: "~/other"}})
	if err != nil {
		t.Fatal(err)
	}
	env := &sshTestEnv{e: e, p: p, mode: mode, local: local}
	setter, ok := any(e).(interface {
		SetSSHMode(*SSHMode, func(SSHTarget, string) (Agent, error))
	})
	if !ok {
		t.Fatal("Engine lacks SSH backend routing (SetSSHMode)")
	}
	setter.SetSSHMode(mode, func(target SSHTarget, cwd string) (Agent, error) {
		a := &sshTestAgent{label: target.Alias, cwd: cwd}
		env.mu.Lock()
		env.remotes = append(env.remotes, a)
		env.mu.Unlock()
		return a, nil
	})
	t.Cleanup(func() {
		e.cancel()
		e.interactiveMu.Lock()
		keys := []string{}
		for k := range e.interactiveStates {
			keys = append(keys, k)
		}
		e.interactiveMu.Unlock()
		for _, k := range keys {
			e.cleanupInteractiveState(k)
		}
	})
	return env
}
func (x *sshTestEnv) send(t *testing.T, key, content string) string {
	t.Helper()
	n := len(x.p.getSent())
	x.e.ReceiveMessage(x.p, &Message{Platform: "test", SessionKey: key, UserID: "u", ReplyCtx: key, Content: content})
	waitForCondition(t, 3*time.Second, func() bool { return len(x.p.getSent()) > n }, "no reply for "+content)
	waitForCondition(t, 3*time.Second, func() bool { _, sm := x.e.sessionContextForKey(key); return !sm.GetOrCreateActive(key).Busy() }, "turn still busy")
	return strings.Join(x.p.getSent()[n:], "\n")
}
func requireSSHText(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("reply %q lacks %q", got, want)
	}
}

func TestCUJ_SSH1_ListUseChatStatusLocal(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:thread:a"
	text := x.send(t, key, "/ssh list")
	requireSSHText(t, text, "remote")
	if strings.Contains(text, "/private/") {
		t.Fatal("identity path leaked")
	}
	requireSSHText(t, x.send(t, key, "hello local"), "local reply")
	requireSSHText(t, x.send(t, key, "/ssh use remote"), "remote")
	requireSSHText(t, x.send(t, key, "hello remote"), "remote reply")
	requireSSHText(t, x.send(t, key, "/ssh status"), "remote")
	requireSSHText(t, x.send(t, key, "/ssh use local"), "local")
	requireSSHText(t, x.send(t, key, "back home"), "local reply")
	requireSSHText(t, x.send(t, key, "/history"), "hello remote")
	x.local.mu.Lock()
	defer x.local.mu.Unlock()
	if len(x.local.starts) != 2 || x.local.starts[1] != "local-sid" {
		t.Fatalf("local resume IDs %v", x.local.starts)
	}
	x.mu.Lock()
	r := x.remotes[0]
	x.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.starts[0] != "" {
		t.Fatalf("remote received local resume ID %q", r.starts[0])
	}
	if !strings.Contains(strings.Join(r.sessions[0].getSentPrompts(), "\n"), "hello local") {
		t.Fatal("new backend missing history handoff")
	}
}
func TestCUJ_SSH2_ThreadIsolationUnknownAndPolicy(t *testing.T) {
	x := newSSHTestEnv(t)
	a, b := "test:chat:thread:a", "test:chat:thread:b"
	x.send(t, a, "/ssh use remote")
	requireSSHText(t, x.send(t, b, "/ssh status"), "local")
	requireSSHText(t, x.send(t, b, "second thread"), "local reply")
	x.send(t, a, "/ssh use nonexistent")
	requireSSHText(t, x.send(t, a, "/ssh status"), "remote")
	x.send(t, a, "/ssh off all")
	requireSSHText(t, x.send(t, a, "continue disabled current"), "remote reply")
	if x.mode.CurrentBackend(a) != "remote" || x.mode.AutoEnabled(a, "remote") {
		t.Fatal("off changed binding or granted auto")
	}
	x.send(t, a, "/ssh on all")
	if !x.mode.AutoEnabled(a, "other") || x.mode.AutoEnabled(b, "other") {
		t.Fatal("grant not scoped")
	}
	x.send(t, a, "/ssh use local extra extra")
	if x.mode.CurrentBackend(a) != "remote" {
		t.Fatal("wrong args changed binding")
	}
}
func TestCUJ_SSH3_BusySwitchRejected(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:thread:a"
	x.send(t, key, "/ssh use remote")
	x.send(t, key, "hello")
	s := x.e.sessions.GetOrCreateActive(key)
	if !s.TryLock() {
		t.Fatal("busy before test")
	}
	n := len(x.p.getSent())
	x.e.ReceiveMessage(x.p, &Message{Platform: "test", SessionKey: key, UserID: "u", Content: "/ssh use local"})
	requireSSHText(t, strings.Join(x.p.getSent()[n:], "\n"), "/stop")
	if x.mode.CurrentBackend(key) != "remote" {
		t.Fatal("busy switch mutated binding")
	}
	s.Unlock()
	requireSSHText(t, x.send(t, key, "/ssh status"), "remote")
}
func TestSSHRemoteCommandsNeverTouchGateway(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:thread:a"
	x.send(t, key, "/ssh use remote")
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	requireSSHText(t, x.send(t, key, "/shell touch "+marker), "remote-output")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("shell ran on gateway")
	}
	x.mu.Lock()
	r := x.remotes[0]
	x.mu.Unlock()
	r.mu.Lock()
	r.commandOutput = "/remote/never-local\n"
	r.mu.Unlock()
	requireSSHText(t, x.send(t, key, "/dir /remote/never-local"), "/remote/never-local")
	binding, _ := x.mode.Binding(key)
	if binding.Cwd != "/remote/never-local" {
		t.Fatalf("remote cwd not bound: %+v", binding)
	}
	for _, cmd := range []string{"/memory show", "/skills", "/workspace list", "/cron list", "/doctor"} {
		requireSSHText(t, x.send(t, key, cmd), "SSH")
	}
	if x.local.cwd == binding.Cwd {
		t.Fatal("global local workdir mutated")
	}
}
func TestSSHUseWriteFailurePreservesAgentAndBinding(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:u"
	x.send(t, key, "hello")
	bad := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(bad, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	x.mode.path = filepath.Join(bad, "state.json")
	text := x.send(t, key, "/ssh use remote")
	if x.mode.CurrentBackend(key) != "local" {
		t.Fatal("failed persistence changed backend")
	}
	requireSSHText(t, x.send(t, key, "still local"), "local reply")
	if strings.Contains(text, "/private/") {
		t.Fatal(fmt.Sprint("error leaked identity: ", text))
	}
}
