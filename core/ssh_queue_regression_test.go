package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func sshMultiWorkspace(t *testing.T, x *sshTestEnv, key string) (*sshTestAgent, *SessionManager, string) {
	t.Helper()
	root := t.TempDir()
	x.e.SetMultiWorkspace(root, filepath.Join(root, "bindings.json"))
	workspace := normalizeWorkspacePath(root)
	x.e.workspaceBindings.Bind("project:"+x.e.name, extractWorkspaceChannelKey(key), "room", workspace)
	local := &sshTestAgent{label: "workspace", cwd: workspace}
	ws := x.e.workspacePool.GetOrCreate(workspace)
	ws.mu.Lock()
	ws.agent = local
	ws.sessions = NewSessionManager("")
	sm := ws.sessions
	ws.mu.Unlock()
	return local, sm, workspace
}

func sshReceive(x *sshTestEnv, key, content string) {
	x.e.ReceiveMessage(x.p, &Message{Platform: "test", SessionKey: key, UserID: "u", ReplyCtx: key, Content: content})
}
func sshWaitIdle(t *testing.T, sm *SessionManager, key string) {
	t.Helper()
	waitForCondition(t, 3*time.Second, func() bool { return !sm.GetOrCreateActive(key).Busy() }, "conversation did not finish")
}
func sshPrompts(a *sshTestAgent) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, s := range a.sessions {
		out = append(out, s.getSentPrompts()...)
	}
	return out
}

func TestCUJ_SSHMultiWorkspacePendingFIFO(t *testing.T) {
	for _, scenario := range []string{"local-to-remote", "remote-to-local", "rollback", "off-cancels", "turn-error", "send-error", "queued-turn-switch"} {
		t.Run(scenario, func(t *testing.T) {
			x := newSSHTestEnv(t)
			key := "test:room:user"
			local, sm, workspace := sshMultiWorkspace(t, x, key)
			x.send(t, key, "prime workspace")
			source, target := "local", "remote"
			if scenario == "remote-to-local" {
				source, target = "remote", "local"
				x.send(t, key, "/ssh use remote")
				x.send(t, key, "prime remote")
			}
			x.send(t, key, "/ssh on "+target)
			current, _ := x.e.sessionContextForKey(key)
			a := current.(*sshTestAgent)
			requested := make(chan SSHResponse, 1)
			release := make(chan struct{})
			var once sync.Once
			t.Cleanup(func() { once.Do(func() { close(release) }); sshWaitIdle(t, sm, key) })
			a.mu.Lock()
			s := a.sessions[len(a.sessions)-1]
			control := a.control
			a.mu.Unlock()
			s.beforeSend = func(s *sshTestSession, prompt string) error {
				if !strings.Contains(prompt, "request-switch") {
					return nil
				}
				var r SSHResponse
				var err error
				if control != nil {
					r, err = control(context.Background(), "use", target, "")
				} else {
					r, err = x.e.SSHRequest(context.Background(), key, "use", target, "")
				}
				if err != nil {
					requested <- SSHResponse{Status: "error", Message: err.Error()}
				} else {
					requested <- r
				}
				<-release
				if scenario == "send-error" {
					return errors.New("fixture send failed")
				}
				if scenario == "turn-error" {
					s.mu.Lock()
					s.nextEventOverride = &Event{Type: EventError, Error: errors.New("fixture turn failed")}
					s.mu.Unlock()
				}
				return nil
			}
			sshReceive(x, key, "request-switch")
			select {
			case r := <-requested:
				if r.Status != "switch_pending" || r.CurrentBackend != source {
					t.Fatalf("model use = %+v", r)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("model control request missing")
			}
			oldKey := x.e.interactiveKeyForSessionKey(key)
			if source == "local" && oldKey != workspace+":"+key {
				t.Fatalf("not a namespaced local state: %q", oldKey)
			}
			if scenario == "queued-turn-switch" {
				// The second turn requests another switch while drained inside the event loop.
				x.e.sshMu.Lock()
				remote, err := x.e.sshAgentLocked(key, SSHBinding{Alias: "remote", Cwd: "/remote/work"})
				x.e.sshMu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				ra := remote.(*sshTestAgent)
				ra.mu.Lock()
				ra.beforeSend = func(_ *sshTestSession, prompt string) error {
					if strings.HasSuffix(prompt, "queued-2") {
						r, err := x.e.SSHRequest(context.Background(), key, "use", "local", "")
						if err != nil || r.Status != "switch_pending" {
							return fmt.Errorf("second switch: %+v %v", r, err)
						}
					}
					return nil
				}
				ra.mu.Unlock()
				if err := x.mode.SetAuto(key, "local", true); err != nil {
					t.Fatal(err)
				}
			}
			for i := 1; i <= 3; i++ {
				sshReceive(x, key, fmt.Sprintf("queued-%d", i))
			}
			if n := x.e.pendingQueueDepth(oldKey); n != 3 {
				t.Fatalf("queue depth %d, want 3", n)
			}
			wantBackend := target
			switch scenario {
			case "rollback":
				bad := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(bad, []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
				x.mode.path = filepath.Join(bad, "state.json")
				wantBackend = source
			case "off-cancels":
				sshReceive(x, key, "/ssh off "+target)
				wantBackend = source
			case "turn-error", "send-error":
				wantBackend = source
			case "queued-turn-switch":
				wantBackend = "local"
			}
			once.Do(func() { close(release) })
			sshWaitIdle(t, sm, key)
			if x.mode.CurrentBackend(key) != wantBackend {
				t.Fatalf("final backend %s, want %s", x.mode.CurrentBackend(key), wantBackend)
			}
			if x.e.sshHasPending(key) {
				t.Fatal("pending switch not resolved")
			}
			if scenario == "send-error" {
				requireSSHText(t, strings.Join(x.p.getSent(), "\n"), "fixture send failed")
				requireSSHText(t, x.send(t, key, "recover after failure"), "workspace reply")
				return // Existing Send-error contract explicitly notifies/drops its queue.
			}
			var all []string
			localPrompts := sshPrompts(local)
			x.mu.Lock()
			remotes := append([]*sshTestAgent(nil), x.remotes...)
			x.mu.Unlock()
			all = append(all, localPrompts...)
			for _, r := range remotes {
				all = append(all, sshPrompts(r)...)
			}
			// Check actual sends, not history handoff snippets; FIFO and exactly once.
			var queued []string
			for _, prompt := range all {
				for i := 1; i <= 3; i++ {
					q := fmt.Sprintf("queued-%d", i)
					if strings.HasSuffix(prompt, q) {
						queued = append(queued, q)
					}
				}
			}
			if scenario != "queued-turn-switch" && !reflect.DeepEqual(queued, []string{"queued-1", "queued-2", "queued-3"}) {
				t.Fatalf("queue delivery %v", queued)
			}
			expectedLocal := wantBackend == "local"
			for i := 1; i <= 3; i++ {
				q := fmt.Sprintf("queued-%d", i)
				foundLocal := false
				for _, p := range localPrompts {
					if strings.HasSuffix(p, q) {
						foundLocal = true
					}
				}
				wantLocal := expectedLocal
				if scenario == "queued-turn-switch" {
					wantLocal = i == 3
				}
				if foundLocal != wantLocal {
					t.Fatalf("%s sent local=%v want %v (backend %s)", q, foundLocal, wantLocal, wantBackend)
				}
			}
			if got := len(sshPrompts(x.local)); got != 0 {
				t.Fatalf("global fallback received %d prompts", got)
			}
			if scenario == "remote-to-local" || scenario == "queued-turn-switch" {
				nextKey := x.e.interactiveKeyForSessionKey(key)
				if nextKey != workspace+":"+key {
					t.Fatalf("return-local lost workspace key: %q", nextKey)
				}
				requireSSHText(t, x.send(t, key, "follow up local"), "workspace reply")
			}
		})
	}
}
