package sshagent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

func TestHomePathsExpandOnCorrectSideAndNeverInterpretShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	worker := "~/bin/cc ' ; $(printf CANARY)"
	raw, err := New(Options{Host: "host", AgentType: "fixture", WorkerCommand: worker, IdentityFile: "~/.ssh/key", KnownHosts: "~/.ssh/known hosts", WorkDir: "~/project"})
	if err != nil {
		t.Fatal(err)
	}
	a := raw.(*Agent)
	if a.opts.IdentityFile != filepath.Join(home, ".ssh/key") || a.opts.KnownHosts != filepath.Join(home, ".ssh/known hosts") {
		t.Fatal("local SSH home paths not expanded")
	}
	if a.GetWorkDir() != "~/project" {
		t.Fatal("remote cwd expanded on gateway")
	}
	cmd := a.command(context.Background())
	remote := cmd.Args[len(cmd.Args)-1]
	parsed, err := exec.Command("sh", "-c", "set -- "+strings.TrimPrefix(remote, "exec ")+"; printf '%s\\n' \"$@\"").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed) != filepath.Join(home, worker[2:])+"\nssh\nworker\n" {
		t.Fatalf("unsafe/literal home worker: %q", parsed)
	}
}

func TestSSHProcessDoesNotInheritGatewayCredentialsOrConfigForwarding(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "CANARY")
	t.Setenv("CC_SESSION_KEY", "CANARY")
	raw, err := New(Options{Host: "host", AgentType: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := raw.(*Agent).command(context.Background())
	if cmd.Env == nil {
		t.Fatal("nil Env inherits entire gateway environment")
	}
	for _, s := range cmd.Env {
		if strings.Contains(s, "CANARY") {
			t.Fatal("gateway credential/session environment copied")
		}
	}
	args := strings.Join(cmd.Args, " ")
	for _, arg := range []string{"-F /dev/null", "ForwardX11=no", "ForwardX11Trusted=no", "PermitLocalCommand=no", "ControlMaster=no", "ControlPath=none", "RequestTTY=no"} {
		if !strings.Contains(args, arg) {
			t.Errorf("missing isolation %s", arg)
		}
	}
}

func TestUnsafeConstructorOptionsNeverReachWorker(t *testing.T) {
	a := fixtureTransport(t, Options{AgentOptions: map[string]any{"model": "safe", "env": map[string]any{"KEY": "CANARY"}, "api_key": "CANARY", "providers": []string{"CANARY"}, "cli_path": "/gateway/CANARY"}})
	original := a.launch
	a.launch = func(ctx context.Context) *exec.Cmd {
		cmd := original(ctx)
		cmd.Env = append(cmd.Env, "CC_SSH_ASSERT_SAFE_OPTIONS=1")
		return cmd
	}
	if _, err := a.ListSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A hostile direct protocol peer cannot bypass the allowlist either.
	p, _ := requestPacket(1, "initialize", requestArgs{AgentType: "ssh-test-fixture", Options: map[string]any{"env": map[string]any{"KEY": "CANARY"}}})
	var input, out bytes.Buffer
	wr := packetWriter{out: &input}
	if err := wr.write(p); err != nil {
		t.Fatal(err)
	}
	if err := ServeWorker(context.Background(), &input, &out); err == nil {
		t.Fatal("worker accepted unsafe initialization")
	}
	if strings.Contains(out.String(), "CANARY") {
		t.Fatal("error echoed credential")
	}
}

func TestWorkerExpandsOwnHomeWorkDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	a := fixtureTransport(t, Options{WorkDir: "~/native project"})
	got, err := a.ListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Summary != filepath.Join(home, "native project") {
		t.Fatalf("remote home not expanded: %#v", got)
	}
}

func TestWorkerCancellationUnblocksOwnedOutput(t *testing.T) {
	r, w := io.Pipe()
	defer func() { _ = r.Close() }()
	inputR, inputW := io.Pipe()
	defer func() { _ = inputW.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	core.RegisterAgent("ssh-blocked-output", func(map[string]any) (core.Agent, error) { return &fixtureAgent{}, nil })
	go func() { done <- ServeWorker(ctx, inputR, w) }()
	p, _ := requestPacket(1, "initialize", requestArgs{AgentType: "ssh-blocked-output"})
	pw := packetWriter{out: inputW}
	if err := pw.write(p); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked output prevented worker cleanup")
	}
}

func TestSerializedNativeErrorFieldIsDecodedExplicitly(t *testing.T) {
	// core.Event.Error is an interface; ordinary Unmarshal cannot decode a
	// non-null string/object into it. The wire decoder must handle it explicitly.
	var input bytes.Buffer
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "event", "params": map[string]any{"event": map[string]any{"Type": core.EventError, "Error": "CANARY"}, "alive": true}})
	input.Write(raw)
	input.WriteByte('\n')
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &connection{ctx: ctx, cancel: cancel, stdout: io.NopCloser(&input), events: make(chan core.Event, 1), readDone: make(chan struct{})}
	c.readLoop()
	e, ok := <-c.events
	if !ok || e.Error == nil || strings.Contains(e.Error.Error(), "CANARY") {
		t.Fatalf("serialized Error lost or leaked: %#v", e)
	}
}

func TestProcessGroupCleanupIncludesBackgroundChild(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("Linux /proc ownership assertion")
	}
	dir := t.TempDir()
	a := fixtureTransport(t, Options{WorkDir: dir})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, err := a.RunCommand(ctx, "sleep 60 & echo $! > child.pid; wait"); done <- err }()
	var pid string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(filepath.Join(dir, "child.pid"))
		pid = strings.TrimSpace(string(b))
		if pid != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == "" {
		cancel()
		t.Fatal("child did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("exec cancellation hung")
	}
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + pid); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned descendant remains (including unreaped zombie)")
}
