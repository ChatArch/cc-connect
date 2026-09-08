package sshagent

import (
	"context"
	"testing"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

func TestNativeEOFClosesEventStreamAndReapsWorker(t *testing.T) {
	for _, withResult := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-result", true: "buffered-result"}[withResult], func(t *testing.T) {
			a := fixtureTransport(t, Options{})
			s, err := a.StartSession(context.Background(), "")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Send("native-eof", nil, nil); err != nil {
				t.Fatal(err)
			}
			id := "native-eof"
			if withResult {
				id = "eof-with-result"
			}
			_ = s.RespondPermission(id, core.PermissionResult{Behavior: "allow"})
			results := 0
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			for {
				select {
				case e, ok := <-s.Events():
					if !ok {
						if withResult && results != 1 {
							t.Fatal("buffered authoritative result lost")
						}
						select {
						case <-s.(*session).conn.finished:
							return
						case <-timer.C:
							t.Fatal("worker not reaped")
						}
					}
					if e.Type == core.EventResult {
						results++
					}
				case <-timer.C:
					t.Fatal("native EOF left event stream open")
				}
			}
		})
	}
}

func TestNativeEOFPreservesSuccessfulSendAcknowledgement(t *testing.T) {
	a := fixtureTransport(t, Options{})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send("result-and-eof", nil, nil); err != nil {
		t.Fatalf("successful send masked by native EOF: %v", err)
	}
	e := nextEvent(t, s)
	if e.Type != core.EventResult || e.Content != "definitive-result" {
		t.Fatalf("result lost: %+v", e)
	}
	assertClosed(t, s)
}

func TestWorkerExpandsNativeCommandOnTarget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CC_SSH_ASSERT_REMOTE_CMD", "1")
	a := fixtureTransport(t, Options{AgentOptions: map[string]any{"cmd": "~/.local/bin/native"}})
	if _, err := a.ListSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
}
