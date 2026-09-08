package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHStatePathProjectIsolation(t *testing.T) {
	dir := t.TempDir()
	first := sshModeStatePath(dir, "a/b")
	second := sshModeStatePath(dir, "a_b")
	if first == second || first == sshModeStatePath(dir, "other") {
		t.Fatal("project SSH states collide")
	}
	if strings.Contains(first, "a/b") || !strings.HasPrefix(first, dir+string(os.PathSeparator)) {
		t.Fatal("unsafe state path")
	}
}

func TestSSHCLIOfflineResolvesConfigEnvironment(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	t.Setenv("SSH_TEST_TARGET_HOST", "dev.example.invalid")
	if err := os.WriteFile(cfg, []byte("[[ssh.targets]]\nalias='dev'\nuser='agent'\nhost='${SSH_TEST_TARGET_HOST}'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := executeSSH([]string{"list", "--offline", "--config", cfg}, &out, &errOut); code != 0 {
		t.Fatalf("%d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "dev.example.invalid") {
		t.Fatalf("unresolved host: %s", out.String())
	}
}

func TestSSHCLIRegisteredSurface(t *testing.T) {
	cmd, ok := lookupTopLevelCommand("ssh")
	if !ok || cmd.Run == nil {
		t.Fatal("ssh not registered")
	}
	got := map[string]bool{}
	for _, c := range cmd.Children {
		got[c.Name] = true
	}
	for _, name := range []string{"list", "status", "test", "use", "worker"} {
		if !got[name] {
			t.Fatalf("missing ssh %s", name)
		}
	}
	if got["on"] || got["off"] {
		t.Fatal("model CLI must not self-grant auto permissions")
	}
}

func TestSSHCLIParseValidationAndScope(t *testing.T) {
	t.Setenv("CC_PROJECT", "project")
	t.Setenv("CC_SESSION_KEY", "thread-a")
	req, err := parseSSHArgs([]string{"use", "remote", "--cwd", "/remote dir"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Action != "use" || req.Backend != "remote" || req.Cwd != "/remote dir" || req.Project != "project" || req.SessionKey != "thread-a" {
		t.Fatalf("bad parse: %+v", req)
	}
	for _, args := range [][]string{{"on", "remote"}, {"off", "all"}, {"use"}, {"test"}, {"list", "extra"}, {"status", "--cwd", "/x"}, {"use", "remote", "--cwd"}, {"use", "remote", "--offline"}, {"test", "remote", "extra"}, {"list", "--unknown"}, {"use", "remote", "--project", "other"}, {"use", "remote", "--session", "other"}} {
		if _, err := parseSSHArgs(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestSSHCLIOfflineListUsesOwnRegistryAndRedactsPaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	text := "data_dir = " + fmtJSON(dir) + "\n[ssh]\n[[ssh.targets]]\nalias = \"remote\"\nhost = \"host.example\"\nuser = \"agent\"\nidentity_file = \"/private/CANARY\"\nknown_hosts = \"/private/KNOWN\"\n"
	if err := os.WriteFile(configPath, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := executeSSH([]string{"list", "--offline", "--config", configPath}, &out, &errOut)
	if code != 0 {
		t.Fatalf("%d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "remote") || !strings.Contains(out.String(), "local") || !strings.Contains(out.String(), "REDACTED") {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String()+errOut.String(), "CANARY") || strings.Contains(out.String(), "KNOWN") {
		t.Fatal("private paths leaked")
	}
	out.Reset()
	errOut.Reset()
	if code := executeSSH([]string{"test", "missing", "--offline", "--config", configPath}, &out, &errOut); code == 0 {
		t.Fatal("invalid target returned success")
	}
}
func fmtJSON(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestSSHCLIUnixAPIAndNonSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Unix socket integration")
	}
	dir, err := os.MkdirTemp(os.TempDir(), "api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "run", "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("unix socket unavailable: %v", err)
	}
	var got map[string]any
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ssh" || r.Method != "POST" {
			t.Errorf("wrong route %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"approval_required","current_backend":"local","message":"user approval required"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	t.Setenv("CC_DATA_DIR", dir)
	t.Setenv("CC_PROJECT", "p")
	t.Setenv("CC_SESSION_KEY", "thread")
	var out, errOut bytes.Buffer
	code := executeSSH([]string{"use", "remote"}, &out, &errOut)
	if code == 0 {
		t.Fatal("approval-required falsely reported successful switch")
	}
	if got["session_key"] != "thread" || got["project"] != "p" || got["action"] != "use" {
		t.Fatalf("wrong scope: %#v", got)
	}
	if !strings.Contains(out.String(), "approval_required") {
		t.Fatal("structured approval result lost")
	}
}

func TestSSHCLIMissingScopeAndMalformedArgsExitNonzero(t *testing.T) {
	t.Setenv("CC_SESSION_KEY", "")
	t.Setenv("CC_PROJECT", "")
	var out, errOut bytes.Buffer
	for _, args := range [][]string{{"use", "remote"}, {"status"}, {"worker", "unexpected"}, {"unknown"}} {
		out.Reset()
		errOut.Reset()
		if code := executeSSH(args, &out, &errOut); code == 0 {
			t.Fatalf("accepted %v", args)
		}
	}
}
