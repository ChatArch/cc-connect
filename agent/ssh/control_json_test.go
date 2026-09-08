package sshagent

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/chenhg5/cc-connect/core"
)

func TestRemoteControlRejectsAmbiguousJSONBeforeCallback(t *testing.T) {
	controlTestRoot(t)
	a := fixtureTransport(t, Options{})
	var calls atomic.Int32
	a.SetSSHControl(func(context.Context, string, string, string) (core.SSHResponse, error) {
		calls.Add(1)
		return core.SSHResponse{Status: "ok"}, nil
	})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, fields := range []string{
		`"action":"status","action":"use","backend":"local"`,
		`"action":"status","Action":"use","backend":"local"`,
		`"Action":"status"`,
		`"action":"status","\u0061ction":"use","backend":"local"`,
		`"action":"use","backend":"local","Backend":"other"`,
		`"action":"use","backend":"local","cwd":null`,
	} {
		body := `{"project":"ssh-worker","session_key":"remote",` + fields + `}`
		if err := s.Send("control:"+body, nil, nil); err != nil {
			t.Fatal(err)
		}
		if e := nextEvent(t, s); e.Content != "HTTP 400" {
			t.Errorf("ambiguous body reached control callback: %s (%s)", fields, e.Content)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid requests invoked callback %d times", calls.Load())
	}
}
