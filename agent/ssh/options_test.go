package sshagent

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestOptionsSafeSSHCommand(t *testing.T) {
	a, err := New(Options{Host: "example.test", User: "worker", AgentType: "fixture", WorkDir: "/remote/not-local", WorkerCommand: "/remote/bin/cc'connect", KnownHosts: "/private/known hosts", IdentityFile: "/private/key name"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "fixture" {
		t.Fatalf("Name = %q", a.Name())
	}
	cmd := a.(*Agent).command(context.Background())
	want := []string{"ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "SendEnv=-*", "-p", "22", "-i", "/private/key name", "-o", "UserKnownHostsFile=\"/private/known hosts\"", "-F", "/dev/null", "-o", "ForwardX11=no", "-o", "ForwardX11Trusted=no", "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "RequestTTY=no", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "--", "worker@example.test", "exec '/remote/bin/cc'\"'\"'connect' 'ssh' 'worker'"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("args = %#v, want %#v", cmd.Args, want)
	}
	if cmd.Dir != "" {
		t.Fatalf("remote cwd incorrectly set locally: %q", cmd.Dir)
	}
	for _, kv := range cmd.Env {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case "HOME", "PATH", "USER", "LOGNAME", "LANG", "LC_CTYPE":
		default:
			t.Fatalf("unexpected forwarded variable %s", key)
		}
	}
}

func TestOptionsRejectInjectionWithoutEchoingInputs(t *testing.T) {
	tests := []Options{
		{Host: "-oProxyCommand=bad"}, {Host: "host\nBAD"}, {Host: "host;bad"}, {Host: "host name"}, {Host: "u@host"},
		{Host: "host", User: "-root"}, {Host: "host", User: "root\nBAD"}, {Host: "host", User: "root;bad"},
		{Host: "host", Port: -1}, {Host: "host", Port: 65536}, {Host: "host", HostKeyPolicy: "no"},
		{Host: "host", IdentityFile: "/private/CANARY\nkey"}, {Host: "host", KnownHosts: "/private/CANARY\nknown"},
		{Host: "host", WorkerCommand: "-evil"}, {Host: "host", WorkerCommand: "cc-connect\nBAD"},
		{Host: "host", WorkDir: "/remote\x00BAD"}, {Host: "host", AgentType: "-evil"},
	}
	for _, opts := range tests {
		if opts.AgentType == "" {
			opts.AgentType = "fixture"
		}
		_, err := New(opts)
		if err == nil {
			t.Errorf("accepted unsafe options: %#v", opts)
			continue
		}
		for _, secret := range []string{"CANARY", "BAD", "ProxyCommand", "/private"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaked input: %v", err)
			}
		}
	}
	for _, opts := range []Options{{Host: "host"}, {AgentType: "fixture"}} {
		if _, err := New(opts); err == nil {
			t.Error("accepted missing required field")
		}
	}
}

func TestOptionsSnapshotAndDefaults(t *testing.T) {
	opts := Options{Host: "2001:db8::1", AgentType: "fixture", AgentOptions: map[string]any{"model": "safe", "nested": map[string]any{"mode": "safe"}}}
	raw, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	a := raw.(*Agent)
	opts.AgentOptions["model"] = "changed"
	opts.AgentOptions["nested"].(map[string]any)["mode"] = "changed"
	if a.opts.AgentOptions["model"] != "safe" || a.opts.AgentOptions["nested"].(map[string]any)["mode"] != "safe" {
		t.Fatal("options were not deeply snapshotted")
	}
	if a.opts.Port != 22 || a.opts.WorkerCommand != "cc-connect" || a.opts.HostKeyPolicy != "strict" || !a.opts.IdentitiesOnly {
		t.Fatalf("bad defaults: %#v", a.opts)
	}
}

func TestWorkerCommandIsOneShellQuotedExecutable(t *testing.T) {
	value := "/remote/cc ' ; $(printf compromised)"
	raw, err := New(Options{Host: "host", AgentType: "fixture", WorkerCommand: value})
	if err != nil {
		t.Fatal(err)
	}
	cmd := raw.(*Agent).command(context.Background())
	remote := cmd.Args[len(cmd.Args)-1]
	// Execute only shell parsing against a printf fixture, never SSH or a model.
	parsed, err := exec.Command("sh", "-c", "set -- "+strings.TrimPrefix(remote, "exec ")+"; printf '%s\\n' \"$@\"").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed) != value+"\nssh\nworker\n" {
		t.Fatalf("shell quoting changed args: %q", parsed)
	}
}
