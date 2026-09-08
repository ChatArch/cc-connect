package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSSHAPIRegisteredRoute(t *testing.T) {
	x := newSSHTestEnv(t)
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
	r := httptest.NewRequest(http.MethodPost, "/ssh", strings.NewReader(`{"project":"ssh-test","session_key":"a","action":"status"}`))
	w := httptest.NewRecorder()
	api.mux.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"current_backend":"local"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestSSHAPIValidationAndNoSelfGrant(t *testing.T) {
	x := newSSHTestEnv(t)
	api := &APIServer{engines: map[string]*Engine{"ssh-test": x.e}}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"project":"ssh-test","session_key":"thread","action":"status"}`, 200},
		{`{"project":"ssh-test","session_key":"thread","action":"on","backend":"all"}`, 400},
		{`{"project":"ssh-test","session_key":"thread","action":"off","backend":"all"}`, 400},
		{`{"project":"missing","session_key":"thread","action":"status"}`, 404},
		{`{"project":"ssh-test","action":"status"}`, 400},
		{`{"project":"ssh-test","session_key":"thread","action":"status","admin":true}`, 400},
		{`{"project":"ssh-test","session_key":"thread","action":"status"} {}`, 400},
		{`null`, 400},
		{`[]`, 400},
		{`{"project":"ssh-test","session_key":"thread","action":"list","backend":"remote"}`, 400},
	} {
		r := httptest.NewRequest(http.MethodPost, "/ssh", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		api.handleSSH(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.body, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "/private/") {
			t.Fatal("private diagnostics exposed")
		}
	}
	if x.mode.AutoEnabled("thread", "remote") {
		t.Fatal("API granted itself permissions")
	}
	r := httptest.NewRequest(http.MethodGet, "/ssh", nil)
	w := httptest.NewRecorder()
	api.handleSSH(w, r)
	if w.Code != 405 {
		t.Fatal("GET accepted")
	}
	r = httptest.NewRequest(http.MethodPost, "/ssh", strings.NewReader(strings.Repeat("x", (64<<10)+1)))
	w = httptest.NewRecorder()
	api.handleSSH(w, r)
	if w.Code != 400 {
		t.Fatal("oversized body accepted")
	}
}

func TestSSHAPIGrantRequiredAndIndependentConversation(t *testing.T) {
	x := newSSHTestEnv(t)
	x.send(t, "test:chat:a", "hello")
	api := &APIServer{engines: map[string]*Engine{"ssh-test": x.e}}
	body := `{"project":"ssh-test","session_key":"test:chat:a","action":"use","backend":"remote"}`
	r := httptest.NewRequest(http.MethodPost, "/ssh", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.handleSSH(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "approval_required") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if x.mode.CurrentBackend("test:chat:a") != "local" {
		t.Fatal("ungranted switch")
	}
	x.send(t, "test:chat:a", "/ssh on remote")
	r = httptest.NewRequest(http.MethodPost, "/ssh", strings.NewReader(body))
	w = httptest.NewRecorder()
	api.handleSSH(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if x.mode.CurrentBackend("test:chat:b") != "local" {
		t.Fatal("other conversation changed")
	}
}
