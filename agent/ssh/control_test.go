package sshagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

func (a *fixtureAgent) SetSessionEnv(env []string) { a.env = append([]string(nil), env...) }

func fixtureControl(env []string, path string, body string) (string, error) {
	dir := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "CC_DATA_DIR=") {
			dir = strings.TrimPrefix(kv, "CC_DATA_DIR=")
		}
	}
	if dir == "" {
		return "", fmt.Errorf("control env unavailable")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "run/api.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	resp, err := client.Post("http://worker"+path, "application/json", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("HTTP %d", resp.StatusCode), nil
	}
	return string(b), nil
}

func TestControlRoundTripIsScopedToConnectionAndCleansSocket(t *testing.T) {
	controlTestRoot(t)
	a := fixtureTransport(t, Options{})
	b := fixtureTransport(t, Options{})
	var mu sync.Mutex
	var calls []string
	a.SetSSHControl(func(ctx context.Context, action, backend, cwd string) (core.SSHResponse, error) {
		mu.Lock()
		calls = append(calls, action+":"+backend+":"+cwd)
		mu.Unlock()
		return core.SSHResponse{Status: "ok", CurrentBackend: "scope-a", PendingBackend: backend, Cwd: cwd}, nil
	})
	b.SetSSHControl(func(ctx context.Context, action, backend, cwd string) (core.SSHResponse, error) {
		return core.SSHResponse{Status: "ok", CurrentBackend: "scope-b"}, nil
	})
	first, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var firstDir string
	for _, action := range []string{"list", "status", "test", "use"} {
		backend, cwd := "", ""
		if action == "test" || action == "use" {
			backend = "local"
		}
		if action == "use" {
			cwd = "~/next"
		}
		body := fmt.Sprintf(`{"project":"ssh-worker","session_key":"remote","action":%q,"backend":%q,"cwd":%q}`, action, backend, cwd)
		if err := first.Send("control:"+body, nil, nil); err != nil {
			t.Fatal(err)
		}
		e := nextEvent(t, first)
		var r core.SSHResponse
		if json.Unmarshal([]byte(e.Content), &r) != nil || r.CurrentBackend != "scope-a" || r.PendingBackend != backend || r.Cwd != cwd {
			t.Fatalf("control response %q", e.Content)
		}
		firstDir = e.Metadata["control_dir"].(string)
	}
	if firstDir == "" {
		t.Fatal("missing worker private directory")
	}
	info, err := os.Stat(filepath.Join(firstDir, "run/api.sock"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permission %v %v", info, err)
	}
	info, err = os.Stat(firstDir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("private dir permission %v %v", info, err)
	}
	if err := second.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"status"}`, nil, nil); err != nil {
		t.Fatal(err)
	}
	e := nextEvent(t, second)
	if !strings.Contains(e.Content, "scope-b") {
		t.Fatalf("cross-session callback %q", e.Content)
	}
	secondDir := e.Metadata["control_dir"].(string)
	if secondDir == firstDir {
		t.Fatal("workers shared control socket")
	}
	for _, body := range []string{
		`{"project":"other","session_key":"remote","action":"status"}`,
		`{"project":"ssh-worker","session_key":"other","action":"status"}`,
		`{"project":"ssh-worker","session_key":"remote","action":"on","backend":"all"}`,
		`{"project":"ssh-worker","session_key":"remote","action":"off"}`,
		`{"project":"ssh-worker","session_key":"remote","action":"status","admin":true}`,
	} {
		text, err := fixtureControl([]string{"CC_DATA_DIR=" + firstDir}, "/ssh", body)
		if err != nil || !strings.HasPrefix(text, "HTTP 4") {
			t.Fatalf("proxy allowed %s: %q %v", body, text, err)
		}
	}
	for _, path := range []string{"/send", "/cron/add", "/ssh?other=true", "//ssh", "/ssh/"} {
		text, err := fixtureControl([]string{"CC_DATA_DIR=" + firstDir}, path, `{}`)
		if err != nil || !strings.HasPrefix(text, "HTTP 4") {
			t.Fatalf("foreign route %s: %q %v", path, text, err)
		}
	}
	mu.Lock()
	n := len(calls)
	mu.Unlock()
	if n != 4 {
		t.Fatalf("proxy forwarded invalid calls: %d", n)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(firstDir); !os.IsNotExist(err) {
		t.Fatalf("proxy artifacts linger: %v", err)
	}
	if _, err := os.Stat(filepath.Join(secondDir, "run/api.sock")); err != nil {
		t.Fatal("closing first removed unrelated proxy")
	}
	if err := second.Send(`control:{"project":"ssh-worker","session_key":"remote","action":"status"}`, nil, nil); err != nil {
		t.Fatal(err)
	}
	nextEvent(t, second)
}

func TestControlUnavailableForNativeWithoutSessionEnvInjector(t *testing.T) {
	core.RegisterAgent("ssh-no-injector", func(map[string]any) (core.Agent, error) { return noInjectorAgent{}, nil })
	p, _ := requestPacket(1, "initialize", requestArgs{AgentType: "ssh-no-injector", ControlEnabled: true})
	var in, out bytes.Buffer
	pw := packetWriter{out: &in}
	if err := pw.write(p); err != nil {
		t.Fatal(err)
	}
	if err := ServeWorker(context.Background(), &in, &out); err == nil || !strings.Contains(err.Error(), "control unavailable") {
		t.Fatalf("missing explicit capability failure: %v", err)
	}
	var response packet
	if json.Unmarshal(bytes.TrimSpace(out.Bytes()), &response) != nil || response.Error == nil || response.Error.Code != -32001 {
		t.Fatalf("missing wire capability failure: %s", out.String())
	}
}

type noInjectorAgent struct{}

func (noInjectorAgent) Name() string { return "ssh-no-injector" }
func (noInjectorAgent) Stop() error  { return nil }
func (noInjectorAgent) StartSession(context.Context, string) (core.AgentSession, error) {
	return nil, fmt.Errorf("not used")
}
func (noInjectorAgent) ListSessions(context.Context) ([]core.AgentSessionInfo, error) {
	return nil, nil
}
