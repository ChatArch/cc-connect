package core

import (
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestSSHSessionSnapshotPreservesScopes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	sm := NewSessionManager(path)
	s := sm.GetOrCreateActive("test:chat:u")
	s.SetAgentInfo("local-old", "local", "history")
	s.SetAgentSessionID("local-new", "local")
	s.SetActiveProvider("local-provider")
	s.SelectAgentScope("ssh:remote")
	s.SetAgentInfo("remote-old", "remote", "history")
	s.SetAgentSessionID("remote-new", "remote")
	s.SetActiveProvider("remote-provider")
	s.TouchUserActivity()
	activity := s.GetLastUserActivity()
	s.AddHistory("user", "shared conversation")
	sm.Save()
	loaded := NewSessionManager(path).GetOrCreateActive("test:chat:u")
	if loaded.AgentScope != "ssh:remote" {
		t.Fatalf("saved scope %q, want ssh:remote", loaded.AgentScope)
	}
	for _, tc := range []struct{ scope, id, typ, provider, past string }{{"ssh:remote", "remote-new", "remote", "remote-provider", "remote-old"}, {"", "local-new", "local", "local-provider", "local-old"}, {"ssh:remote", "remote-new", "remote", "remote-provider", "remote-old"}} {
		loaded.SelectAgentScope(tc.scope)
		if loaded.GetAgentSessionID() != tc.id || loaded.AgentType != tc.typ || loaded.GetActiveProvider() != tc.provider || !reflect.DeepEqual(loaded.PastAgentSessionIDs, []string{tc.past}) {
			t.Fatalf("scope %q lost state: %+v", tc.scope, loaded)
		}
	}
	if !loaded.GetLastUserActivity().Equal(activity) || loaded.HistoryLen() != 1 {
		t.Fatal("snapshot lost history or user activity")
	}
	// Race coverage: snapshot maps and nested PastIDs must not alias live state.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.mu.Lock()
			v := s.AgentScopes[""]
			v.PastIDs[0] = "mutated"
			s.AgentScopes[""] = v
			s.mu.Unlock()
		}
	}()
	for i := 0; i < 20; i++ {
		sm.Save()
	}
	wg.Wait()
}

func TestCUJ_SSHRestartResumesBothBackends(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:thread:restart"
	path := filepath.Join(t.TempDir(), "sessions.json")
	x.e.sessions = NewSessionManager(path)
	x.send(t, key, "local before restart")
	x.send(t, key, "/ssh use remote")
	x.send(t, key, "remote before restart")
	x.e.cleanupInteractiveState(x.e.interactiveKeyForSessionKey(key))
	x.e.sessions.Save()
	y := newSSHTestEnv(t)
	y.e.sessions = NewSessionManager(path)
	if err := y.mode.Use(key, "remote", "/remote/work"); err != nil {
		t.Fatal(err)
	}
	y.send(t, key, "remote after restart")
	y.mu.Lock()
	r := y.remotes[0]
	y.mu.Unlock()
	r.mu.Lock()
	remoteID := r.starts[0]
	r.mu.Unlock()
	if remoteID != "remote-sid" {
		t.Fatalf("remote restart resume %q, want remote-sid", remoteID)
	}
	y.send(t, key, "/ssh use local")
	y.send(t, key, "local after restart")
	y.local.mu.Lock()
	localID := y.local.starts[0]
	y.local.mu.Unlock()
	if localID != "local-sid" {
		t.Fatalf("local restart resume %q, want local-sid", localID)
	}
	y.send(t, key, "/ssh use remote")
	requireSSHText(t, y.send(t, key, "remote again"), "remote reply")
}
