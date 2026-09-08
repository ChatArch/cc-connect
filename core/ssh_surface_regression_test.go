package core

import (
	"strings"
	"testing"
)

func TestCUJ_SSHExplicitCwdAndModelEntryHint(t *testing.T) {
	x := newSSHTestEnv(t)
	key := "test:chat:thread:cwd"
	x.send(t, key, "/ssh use remote --cwd '/remote path'")
	b, ok := x.mode.Binding(key)
	if !ok || b.Alias != "remote" || b.Cwd != "/remote path" {
		t.Fatalf("explicit cwd not bound: %+v %v", b, ok)
	}
	x.send(t, key, "work here")
	x.mu.Lock()
	r := x.remotes[0]
	x.mu.Unlock()
	prompts := sshPrompts(r)
	joined := strings.Join(prompts, "\n")
	for _, want := range []string{"cc-connect ssh list", "cc-connect ssh use local", "switch_pending", "approval_required", "remote"} {
		if !strings.Contains(joined, want) {
			t.Errorf("native prompt missing %q", want)
		}
	}
	x.send(t, key, "/ssh use local")
	x.send(t, key, "local task")
	if !strings.Contains(strings.Join(sshPrompts(x.local), "\n"), "cc-connect ssh status") {
		t.Fatal("local model has no SSH control entry")
	}
	for _, bad := range []string{"/ssh use remote --cwd", "/ssh use remote --bad /path", "/ssh status --cwd /path"} {
		x.send(t, key, bad)
		if x.mode.CurrentBackend(key) != "local" {
			t.Fatalf("malformed command changed backend: %s", bad)
		}
	}
}
