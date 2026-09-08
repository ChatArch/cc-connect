package sshagent

import (
	"context"
	"testing"
)

func TestIPv6ConfiguredTargetsReachSSHAsLiteralHosts(t *testing.T) {
	for _, host := range []string{"::1", "[::1]", "2001:db8::1"} {
		t.Run(host, func(t *testing.T) {
			raw, err := New(Options{Host: host, User: "agent", AgentType: "cursor"})
			if err != nil {
				t.Fatal(err)
			}
			a := raw.(*Agent)
			cmd := a.command(context.Background())
			want := host
			if host == "[::1]" {
				want = "::1"
			}
			if cmd.Args[len(cmd.Args)-2] != "agent@"+want {
				t.Fatalf("invalid SSH address: %v", cmd.Args)
			}
		})
	}
	for _, host := range []string{"abc:def", "[::1]oops", "-evil", "host%extra"} {
		if _, err := New(Options{Host: host, AgentType: "cursor"}); err == nil {
			t.Fatalf("unsafe host accepted: %s", host)
		}
	}
}
