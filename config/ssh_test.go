package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/chenhg5/cc-connect/core"
)

func sshRegistryFixture(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSSHConfigTOMLFields(t *testing.T) {
	var cfg Config
	_, err := toml.Decode(`[ssh]
registry = "/custom/targets.yaml"
[[ssh.targets]]
alias = "remote"
host = "host.example"
user = "agent"
port = 2222
identity_file = "~/.ssh/private"
identities_only = true
known_hosts = "~/.ssh/known_hosts"
host_key_policy = "accept-new"
cwd = "~/project"
worker_command = "~/.local/bin/cc-connect"
[ssh.targets.agent_options]
model = "test-model"
`, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSH.Registry != "/custom/targets.yaml" || len(cfg.SSH.Targets) != 1 {
		t.Fatal("SSH config not decoded")
	}
	target := cfg.SSH.Targets[0]
	if target.Alias != "remote" || target.Host != "host.example" || target.User != "agent" || target.Port != 2222 || target.IdentityFile != "~/.ssh/private" || !target.IdentitiesOnly || target.KnownHosts != "~/.ssh/known_hosts" || target.HostKeyPolicy != "accept-new" || target.Cwd != "~/project" || target.WorkerCommand != "~/.local/bin/cc-connect" || target.AgentOptions["model"] != "test-model" {
		t.Fatal("SSH target fields not decoded")
	}
}

func TestLoadSSHTargetsFormats(t *testing.T) {
	fields := "    host: host.example\n    user: agent\n    port: 2222\n    identity_file: ~/.ssh/private\n    identities_only: true\n    known_hosts: ~/.ssh/known_hosts\n    host_key_policy: accept-new\n    cwd: ~/project\n    worker_command: /remote/bin/cc-connect\n    agent_options:\n      model: test-model\n"
	mapping := "targets:\n  remote:\n" + fields
	list := "targets:\n  - alias: remote\n" + fields
	for name, text := range map[string]string{"mapping": mapping, "list": list, "nested mapping": "ssh:\n" + indentSSHFixture(mapping), "nested list": "ssh:\n" + indentSSHFixture(list)} {
		t.Run(name, func(t *testing.T) {
			targets, err := LoadSSHTargets(t.TempDir(), SSHConfig{Registry: sshRegistryFixture(t, text)})
			if err != nil {
				t.Fatal(err)
			}
			if len(targets) != 1 {
				t.Fatalf("count %d", len(targets))
			}
			v := targets[0]
			if v.Alias != "remote" || v.Host != "host.example" || v.User != "agent" || v.Port != 2222 || v.IdentityFile != "~/.ssh/private" || !v.IdentitiesOnly || v.KnownHosts != "~/.ssh/known_hosts" || v.HostKeyPolicy != "accept-new" || v.Cwd != "~/project" || v.WorkerCommand != "/remote/bin/cc-connect" || v.AgentOptions["model"] != "test-model" {
				t.Fatal("registry fields lost")
			}
		})
	}
}

func indentSSHFixture(s string) string {
	return "  " + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n  ") + "\n"
}

func TestLoadSSHTargetsDefaultAndExplicitMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, relative := range []string{".ssh/config", ".hermes/ssh/targets.yaml", ".hermes/ssh_targets.yaml"} {
		p := filepath.Join(home, relative)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("must not be read"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dataDir := t.TempDir()
	got, err := LoadSSHTargets(dataDir, SSHConfig{})
	if err != nil || len(got) != 0 {
		t.Fatalf("missing default should be empty: %v", err)
	}
	if _, err := LoadSSHTargets(dataDir, SSHConfig{Registry: filepath.Join(dataDir, "missing.yaml")}); err == nil {
		t.Fatal("explicit missing registry accepted")
	}
	path := filepath.Join(dataDir, "ssh", "targets.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("targets:\n  default:\n    host: host.example\n    user: agent\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = LoadSSHTargets(dataDir, SSHConfig{})
	if err != nil || len(got) != 1 || got[0].Alias != "default" || got[0].HostKeyPolicy != "strict" {
		t.Fatalf("default registry not loaded: %v", err)
	}
	explicit := sshRegistryFixture(t, "targets:\n  chosen:\n    host: chosen.example\n    user: agent\n")
	got, err = LoadSSHTargets(dataDir, SSHConfig{Registry: explicit})
	if err != nil || len(got) != 1 || got[0].Alias != "chosen" {
		t.Fatalf("explicit registry ignored: %v", err)
	}
}

func TestLoadSSHTargetsHomeRelativeRegistryAndReadErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, "targets.yaml")
	if err := os.WriteFile(path, []byte("targets: {remote: {host: host.example, user: agent}}"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSSHTargets(t.TempDir(), SSHConfig{Registry: "~/targets.yaml"})
	if err != nil || len(got) != 1 || got[0].Alias != "remote" {
		t.Fatalf("home-relative registry failed: %v", err)
	}
	for _, registry := range []string{"~", home, filepath.Join(home, "private-missing")} {
		_, err := LoadSSHTargets(t.TempDir(), SSHConfig{Registry: registry})
		if err == nil {
			t.Fatal("unreadable explicit registry accepted")
		}
		if strings.Contains(err.Error(), home) || strings.Contains(err.Error(), "private-missing") {
			t.Fatal("private path leaked")
		}
	}
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "ssh", "targets.yaml"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSSHTargets(dataDir, SSHConfig{}); err == nil {
		t.Fatal("unreadable default registry treated as missing")
	}
}

func TestLoadSSHTargetsMergeSortedClonedAndDuplicates(t *testing.T) {
	path := sshRegistryFixture(t, "targets:\n  zeta:\n    host: host.example\n    user: agent\n")
	inline := []core.SSHTarget{{Alias: "alpha", Host: "other.example", User: "agent", AgentOptions: map[string]any{"model": "test"}}}
	got, err := LoadSSHTargets(t.TempDir(), SSHConfig{Registry: path, Targets: inline})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Alias != "alpha" || got[1].Alias != "zeta" {
		t.Fatal("merge/sort incorrect")
	}
	got[0].AgentOptions["model"] = "changed"
	if inline[0].AgentOptions["model"] != "test" {
		t.Fatal("inline map not cloned")
	}
	inline[0].Alias = "zeta"
	if _, err := LoadSSHTargets(t.TempDir(), SSHConfig{Registry: path, Targets: inline}); err == nil {
		t.Fatal("registry/inline duplicate accepted")
	}
	if _, err := LoadSSHTargets(t.TempDir(), SSHConfig{Targets: append(inline, inline[0])}); err == nil {
		t.Fatal("inline duplicate accepted")
	}
	inline[0].Alias = "local"
	if _, err := LoadSSHTargets(t.TempDir(), SSHConfig{Targets: inline}); err == nil {
		t.Fatal("invalid inline target accepted")
	}
}

func TestLoadSSHTargetsInvalidRegistryFailsWithoutLeakingPaths(t *testing.T) {
	invalid := []string{
		`targets: {"": {alias: remote, host: host.example, user: agent}}`,
		`targets: !custom []`,
		`targets: {remote: {host: host.example}}`,
		`targets: {remote: {host: host.example, user: ""}}`,
		`targets: {remote: {host: host.example, user: agent, port: "22"}}`,
		`targets: {remote: {host: host.example, user: agent, port: null}}`,
		`targets: {remote: {host: host.example, user: agent, identities_only: "true"}}`,
		`targets: {remote: {host: host.example, user: agent, host: other.example}}`,
		`targets: {remote: {host: host.example, user: agent, agent_options: {model: one, model: two}}}`,
		`targets: {remote: {host: host.example, user: agent, agent_options: {model: 42}}}`,
		"targets: {}\ntargets: {}\n",
		"targets: [", "wrong_root: {}", "targets: text", "targets: 42", "targets: null", "targets:\n  remote: null", "targets:\n  - host: host.example\n    user: agent\n",
		"targets:\n  local:\n    host: host.example\n    user: agent\n", "targets:\n  all:\n    host: host.example\n    user: agent\n",
		"targets:\n  remote:\n    alias: another\n    host: host.example\n    user: agent\n",
		"targets:\n  remote:\n    host: host.example\n    user: agent\n    host_key_policy: no\n",
		"targets:\n  remote:\n    host: host.example\n    user: agent\n    host_key_policy: ignore\n",
		"targets:\n  remote:\n    host: host.example\n    user: agent\n    private_key: private-key-sentinel\n",
		"targets:\n  remote:\n    host: host.example\n    user: agent\n    identity_file: [private-key-sentinel]\n",
		"targets:\n  remote:\n    host: host.example\n    user: agent\n    agent_options:\n      token: private-key-sentinel\n",
		"targets:\n  remote:\n    host: host.example\n    user: agent\n  remote:\n    host: other.example\n    user: agent\n",
		"targets:\n  - alias: remote\n    host: host.example\n    user: agent\n  - alias: remote\n    host: other.example\n    user: agent\n",
		"targets: {}\n---\ntargets: {}\n", "targets: {}\nssh:\n  targets: {}\n",
	}
	for i, data := range invalid {
		t.Run(strings.ReplaceAll(data[:min(len(data), 24)], "\n", " "), func(t *testing.T) {
			path := sshRegistryFixture(t, data)
			_, err := LoadSSHTargets(t.TempDir(), SSHConfig{Registry: path})
			if err == nil {
				t.Fatalf("invalid registry %d accepted", i)
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "private-key-sentinel") {
				t.Fatal("private path or input leaked")
			}
			after, _ := os.ReadFile(path)
			if string(after) != data {
				t.Fatal("loader modified registry")
			}
		})
	}
	for _, data := range []string{"targets: {}\n", "targets: []\n"} {
		got, err := LoadSSHTargets(t.TempDir(), SSHConfig{Registry: sshRegistryFixture(t, data)})
		if err != nil || len(got) != 0 {
			t.Fatalf("explicit empty invalid: %v", err)
		}
	}
}
