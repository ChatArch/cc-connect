package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHStateRejectsFieldCaseAliasesAndMissingFields(t *testing.T) {
	target := SSHTarget{Alias: "remote", Host: "dev.example", User: "worker", Cwd: "/srv/project"}
	cases := []string{
		`{"version":99,"Version":1,"bindings":{},"auto_switch":{}}`,
		`{"Version":1,"bindings":{},"auto_switch":{}}`,
		`{"version":1,"bindings":{},"Bindings":{},"auto_switch":{}}`,
		`{"version":1,"bindings":{},"auto_switch":{},"Auto_Switch":{}}`,
		`{"version":1,"bindings":{"s":{"alias":"unknown","Alias":"remote","cwd":"/srv/project"}},"auto_switch":{}}`,
		`{"version":1,"bindings":{"s":{"alias":"remote","Cwd":"/srv/project"}},"auto_switch":{}}`,
		`{"version":1,"bindings":{"s":{"alias":"remote"}},"auto_switch":{}}`,
		`{"version":1,"bindings":{"s":{"cwd":"/srv/project"}},"auto_switch":{}}`,
	}
	for i, body := range cases {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewSSHMode(path, []SSHTarget{target}); err == nil {
			t.Errorf("ambiguous/incomplete state accepted at %d", i)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != body {
			t.Fatal("failed load changed state file")
		}
	}
}

func TestSSHStatePreservesCaseSensitiveMapKeysAndExplicitEmptyCwd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	body := `{"version":1,"bindings":{"Room":{"alias":"remote","cwd":""},"room":{"alias":"remote","cwd":"/srv/other"}},"auto_switch":{"Room":{"remote":true},"room":{"remote":false}}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewSSHMode(path, []SSHTarget{{Alias: "remote", Host: "dev.example", User: "worker"}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.AutoEnabled("Room", "remote") || m.AutoEnabled("room", "remote") {
		t.Fatal("case-sensitive session permissions collapsed")
	}
	a, okA := m.Binding("Room")
	b, okB := m.Binding("room")
	if !okA || !okB || a.Cwd != "" || b.Cwd != "/srv/other" {
		t.Fatal("explicit empty cwd or session identity lost")
	}
}

func TestSSHRegisteredAPIRejectsAmbiguousJSONBeforeMutation(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:json"
	x.send(t, key, "hello")
	x.send(t, key, "/ssh on remote")
	dir, err := os.MkdirTemp(os.TempDir(), "api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	api, err := NewAPIServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = api.listener.Close() }()
	defer api.Stop()
	api.RegisterEngine("ssh-test", x.e)
	for _, fields := range []string{
		`"action":"status","action":"use","backend":"remote"`,
		`"action":"status","Action":"use","backend":"remote"`,
		`"Action":"use","backend":"remote"`,
		`"action":"status","\u0061ction":"use","backend":"remote"`,
		`"action":"use","backend":"other","backend":"remote"`,
		`"action":"use","backend":"remote","Backend":"other"`,
		`"action":"use","backend":"remote","cwd":null`,
	} {
		body := `{"project":"ssh-test","session_key":"` + key + `",` + fields + `}`
		w := httptest.NewRecorder()
		api.mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/ssh", strings.NewReader(body)))
		if w.Code != 400 {
			t.Errorf("ambiguous JSON got %d: %s", w.Code, fields)
		}
		if x.mode.CurrentBackend(key) != "local" {
			t.Errorf("invalid JSON changed active backend: %s", fields)
			_, _ = x.e.SSHRequest(t.Context(), key, "use", "local", "")
		}
		if !x.mode.AutoEnabled(key, "remote") {
			t.Fatal("invalid JSON changed user grant")
		}
	}
	body := `{"project":"ssh-test","session_key":"` + key + `","action":"use","backend":"remote"}`
	w := httptest.NewRecorder()
	api.mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/ssh", strings.NewReader(body)))
	var result SSHResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || result.Status != "ok" || result.CurrentBackend != "remote" || x.mode.CurrentBackend(key) != "remote" {
		t.Fatalf("authorized use did not really switch: %d %+v", w.Code, result)
	}
	if x.mode.CurrentBackend("test:chat:other") != "local" {
		t.Fatal("other conversation changed")
	}
}
