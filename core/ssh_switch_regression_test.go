package core

import "testing"

func TestCUJ_SSHSwitchExternalSessionAndBackendCollision(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:thread:switch"
	x.local.listed = []AgentSessionInfo{{ID: "same-sid", Summary: "local external"}}
	x.send(t, key, "/switch 1")
	x.send(t, key, "local history only")
	localSession := x.e.sessions.GetOrCreateActive(key)
	x.send(t, key, "/ssh use remote")
	x.mu.Lock()
	remote := x.remotes[0]
	x.mu.Unlock()
	remote.mu.Lock()
	remote.listed = []AgentSessionInfo{{ID: "same-sid", Summary: "remote external"}, {ID: "remote-only", Summary: "another"}}
	remote.mu.Unlock()
	x.send(t, key, "/switch 1")
	remoteSession := x.e.sessions.GetOrCreateActive(key)
	if remoteSession == localSession {
		t.Fatal("same native SID on different backends collided")
	}
	requireSSHText(t, x.send(t, key, "remote history only"), "remote reply")
	remote.mu.Lock()
	id := remote.starts[0]
	remote.mu.Unlock()
	if id != "same-sid" {
		t.Fatalf("/switch next StartSession got %q, want same-sid", id)
	}
	x.send(t, key, "/switch 2")
	x.send(t, key, "second remote")
	x.send(t, key, "/switch 1")
	if x.e.sessions.GetOrCreateActive(key) != remoteSession {
		t.Fatal("remote /switch lost existing history session")
	}
	requireSSHText(t, x.send(t, key, "/history"), "remote history only")
	x.send(t, key, "/ssh use local")
	x.send(t, key, "/switch 1")
	if x.e.sessions.GetOrCreateActive(key) != localSession {
		t.Fatal("local API no longer finds inactive local scope")
	}
	requireSSHText(t, x.send(t, key, "/history"), "local history only")
	x.send(t, key, "resume local")
	x.local.mu.Lock()
	defer x.local.mu.Unlock()
	if got := x.local.starts[len(x.local.starts)-1]; got != "same-sid" {
		t.Fatalf("local resume %q", got)
	}
}

func TestCUJ_SSHSwitchRemoteOnlyNextStartID(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:thread:external"
	x.send(t, key, "/ssh use remote")
	x.mu.Lock()
	r := x.remotes[0]
	x.mu.Unlock()
	r.mu.Lock()
	r.listed = []AgentSessionInfo{{ID: "external-remote", Summary: "external"}}
	r.mu.Unlock()
	x.send(t, key, "/switch 1")
	x.send(t, key, "continue selected")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.starts[0] != "external-remote" {
		t.Fatalf("remote /switch got StartSession(%q)", r.starts[0])
	}
}
