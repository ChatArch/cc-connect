package core

import (
	"path/filepath"
	"testing"
)

func TestCUJ_SSHMultiWorkspaceColdRestartPreservesOwner(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:room:user"
	local, sm, workspace := sshMultiWorkspace(t, x, key)
	path := filepath.Join(t.TempDir(), "workspace-sessions.json")
	sm.storePath = path
	x.mode.path = filepath.Join(filepath.Dir(path), "ssh-mode.json")
	x.send(t, key, "local persisted history")
	x.send(t, key, "/ssh use remote")
	x.send(t, key, "remote persisted history")
	x.e.cleanupInteractiveState(x.e.interactiveKeyForSessionKey(key))
	sm.Save()
	y := newSSHTestEnv(t)
	y.e.SetMultiWorkspace(workspace, filepath.Join(workspace, "bindings.json"))
	ws := y.e.workspacePool.GetOrCreate(workspace)
	ws.mu.Lock()
	ws.agent = &sshTestAgent{label: "workspace", cwd: workspace}
	ws.sessions = NewSessionManager(path)
	loaded := ws.sessions
	restoredLocal := ws.agent.(*sshTestAgent)
	ws.mu.Unlock()
	mode, err := NewSSHMode(x.mode.path, x.mode.Targets())
	if err != nil {
		t.Fatal(err)
	}
	y.mode = mode
	y.e.sshMode = mode
	if len(y.e.sshManagers) != 0 {
		t.Fatal("not a cold engine")
	}
	_, selected, _, err := y.e.sshContext(key)
	if err != nil {
		t.Fatal(err)
	}
	if selected != loaded {
		t.Fatal("cold remote binding fell back to global SessionManager")
	}
	requireSSHText(t, y.send(t, key, "/history"), "remote persisted history")
	y.send(t, key, "resume remote")
	y.mu.Lock()
	r := y.remotes[0]
	y.mu.Unlock()
	r.mu.Lock()
	sid := r.starts[0]
	r.mu.Unlock()
	if sid != "remote-sid" {
		t.Fatalf("remote resume id %q", sid)
	}
	y.send(t, key, "/ssh use local")
	y.send(t, key, "resume local")
	restoredLocal.mu.Lock()
	defer restoredLocal.mu.Unlock()
	if len(restoredLocal.starts) != 1 || restoredLocal.starts[0] != "workspace-sid" {
		t.Fatalf("local identity lost: %v (old=%v)", restoredLocal.starts, local.starts)
	}
	if y.e.sessions != nil && y.e.sessions.GetOrCreateActive(key).HistoryLen() != 0 {
		t.Fatal("global store polluted")
	}
}
