package sshagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

// A short, owned test root: long project TMPDIR and testing.T names exceed
// Unix socket limits. Never skip control tests or use /tmp as a fallback.
func controlTestRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(home, ".chatarch")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("CHATARCH_HOME", dir)
	return dir
}

func TestControlStatusesAndRedactedErrors(t *testing.T) {
	controlTestRoot(t)
	a := fixtureTransport(t, Options{})
	a.SetSSHControl(func(ctx context.Context, action, backend, cwd string) (core.SSHResponse, error) {
		if backend == "failure" {
			return core.SSHResponse{}, errors.New("CANARY /private/key")
		}
		return core.SSHResponse{Status: backend, CurrentBackend: "remote", PendingBackend: "local", ApprovalRequired: backend == "approval_required", Cwd: cwd}, nil
	})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"ok", "approval_required", "switch_pending"} {
		body := `{"project":"ssh-worker","session_key":"remote","action":"use","backend":"` + status + `","cwd":"~/next"}`
		if err := s.Send("control:"+body, nil, nil); err != nil {
			t.Fatal(err)
		}
		e := nextEvent(t, s)
		var r core.SSHResponse
		if json.Unmarshal([]byte(e.Content), &r) != nil || r.Status != status || r.Cwd != "~/next" || r.ApprovalRequired != (status == "approval_required") {
			t.Fatalf("lost response: %s", e.Content)
		}
	}
	if err := s.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"use","backend":"failure"}`, nil, nil); err != nil {
		t.Fatal(err)
	}
	if e := nextEvent(t, s); e.Content != "HTTP 502" {
		t.Fatalf("failure not bounded/redacted: %q", e.Content)
	}
}

func TestControlCancellationReleasesCallbackAndDoesNotBlockReadLoop(t *testing.T) {
	controlTestRoot(t)
	a := fixtureTransport(t, Options{})
	entered := make(chan struct{})
	exited := make(chan struct{})
	a.SetSSHControl(func(ctx context.Context, _, _, _ string) (core.SSHResponse, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return core.SSHResponse{}, ctx.Err()
	})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- s.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"status"}`, nil, nil)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("callback not invoked")
	}
	// Another request must still cross both read loops while callback blocks.
	permissionDone := make(chan error, 1)
	go func() { permissionDone <- s.RespondPermission("parallel", core.PermissionResult{Behavior: "deny"}) }()
	select {
	case err := <-permissionDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback blocked read loop")
	}
	closed := make(chan struct{})
	go func() { _ = s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(4 * time.Second):
		t.Fatal("close blocked on callback")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("callback was not canceled")
	}
	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("pending send leaked")
	}
}

func TestControlCallbackCanStopItsOwnAgent(t *testing.T) {
	controlTestRoot(t)
	a := fixtureTransport(t, Options{})
	callbackDone := make(chan struct{})
	a.SetSSHControl(func(context.Context, string, string, string) (core.SSHResponse, error) {
		defer close(callbackDone)
		_ = a.Stop()
		return core.SSHResponse{Status: "ok"}, nil
	})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- s.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"status"}`, nil, nil)
	}()
	select {
	case <-callbackDone:
	case <-time.After(5 * time.Second):
		t.Fatal("callback self-stop deadlock")
	}
	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("send leaked")
	}
}

func TestControlHTTPDisconnectCancelsRPC(t *testing.T) {
	controlTestRoot(t)
	a := fixtureTransport(t, Options{})
	entered := make(chan struct{})
	exited := make(chan struct{})
	a.SetSSHControl(func(ctx context.Context, action, _, _ string) (core.SSHResponse, error) {
		if action == "test" {
			close(entered)
			<-ctx.Done()
			close(exited)
			return core.SSHResponse{}, ctx.Err()
		}
		return core.SSHResponse{Status: "ok"}, nil
	})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"status"}`, nil, nil); err != nil {
		t.Fatal(err)
	}
	dir := nextEvent(t, s).Metadata["control_dir"].(string)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "run/api.sock"))
	}}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://worker/ssh", strings.NewReader(`{"project":"ssh-worker","session_key":"remote","action":"test","backend":"local"}`))
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, _ := (&http.Client{Transport: tr}).Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("callback not entered")
	}
	cancel()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP cancellation did not reach gateway")
	}
	<-done
	if err := s.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"status"}`, nil, nil); err != nil {
		t.Fatal("late canceled response poisoned stream:", err)
	}
	nextEvent(t, s)
}

func TestControlWorkerRejectsLongRuntimeRootWithoutArtifacts(t *testing.T) {
	root := controlTestRoot(t)
	long := filepath.Join(root, strings.Repeat("x", 110))
	t.Setenv("CHATARCH_HOME", long)
	core.RegisterAgent("ssh-long-control", func(map[string]any) (core.Agent, error) { return &fixtureAgent{}, nil })
	var input, output bytes.Buffer
	p, _ := requestPacket(1, "initialize", requestArgs{AgentType: "ssh-long-control", ControlEnabled: true})
	pw := packetWriter{out: &input}
	_ = pw.write(p)
	if err := ServeWorker(context.Background(), &input, &output); err == nil {
		t.Fatal("long socket root accepted")
	}
	if _, err := os.Stat(long); !os.IsNotExist(err) {
		t.Fatal("failed path preflight left artifacts")
	}
	if strings.Contains(output.String(), long) {
		t.Fatal("runtime path leaked to peer")
	}
}

func TestWorkerRejectsUnsafeOptionsBeforeFactory(t *testing.T) {
	called := false
	core.RegisterAgent("ssh-unsafe-control", func(map[string]any) (core.Agent, error) { called = true; return &fixtureAgent{}, nil })
	p, _ := requestPacket(1, "initialize", requestArgs{AgentType: "ssh-unsafe-control", Options: map[string]any{"env": map[string]any{"KEY": "CANARY"}}})
	var input, output bytes.Buffer
	pw := packetWriter{out: &input}
	_ = pw.write(p)
	if err := ServeWorker(context.Background(), &input, &output); err == nil || called {
		t.Fatalf("unsafe options passed factory, called=%v err=%v", called, err)
	}
}

func TestControlProxyRejectsOversizedAndTrailingBodies(t *testing.T) {
	controlTestRoot(t)
	a := fixtureTransport(t, Options{})
	a.SetSSHControl(func(context.Context, string, string, string) (core.SSHResponse, error) {
		return core.SSHResponse{Status: "ok"}, nil
	})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"status"}`, nil, nil); err != nil {
		t.Fatal(err)
	}
	dir := nextEvent(t, s).Metadata["control_dir"].(string)
	body := `{"project":"ssh-worker","session_key":"remote","action":"status"}`
	for _, invalid := range []string{body + ` {}`, `{"project":"ssh-worker","session_key":"remote","action":"use","backend":"x","cwd":"` + strings.Repeat("x", 64<<10) + `"}`, `{"project":"ssh-worker","session_key":"remote","action":"use","backend":"x","cwd":"bad\u0000path"}`} {
		got, err := fixtureControl([]string{"CC_DATA_DIR=" + dir}, "/ssh", invalid)
		if err != nil || !strings.HasPrefix(got, "HTTP 4") {
			t.Fatalf("invalid request accepted: %s %v", got, err)
		}
	}

}
