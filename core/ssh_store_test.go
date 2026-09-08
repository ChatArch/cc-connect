package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func sshTestTargets() []SSHTarget {
	return []SSHTarget{
		{Alias: "zeta", Host: "192.0.2.10", User: "worker", Cwd: "~/project", AgentOptions: map[string]any{"model": "test-model"}},
		{Alias: "alpha", Host: "host.example", User: "worker", Cwd: "/srv/project"},
	}
}

func TestSSHTargetValidation(t *testing.T) {
	good := SSHTarget{Alias: "test.remote", Host: "host.example", User: "agent", IdentityFile: "~/.ssh/private", KnownHosts: "~/.ssh/known_hosts", WorkerCommand: "cc-connect", Cwd: "~/project"}
	for _, change := range []func(*SSHTarget){
		func(v *SSHTarget) {}, func(v *SSHTarget) { v.Port = 1 }, func(v *SSHTarget) { v.Port = 65535 },
		func(v *SSHTarget) { v.Host = "2001:db8::1" }, func(v *SSHTarget) { v.Host = "[2001:db8::1]" },
		func(v *SSHTarget) { v.HostKeyPolicy = "accept-new" }, func(v *SSHTarget) { v.HostKeyPolicy = "strict" },
		func(v *SSHTarget) { v.WorkerCommand = "/opt/bin/cc-connect" }, func(v *SSHTarget) { v.WorkerCommand = "~/.local/bin/cc-connect" },
		func(v *SSHTarget) { v.Cwd = "/not-present-locally/with space" }, func(v *SSHTarget) { v.Cwd = "~" },
		func(v *SSHTarget) {
			v.AgentOptions = map[string]any{"model": "test", "mode": "suggest", "reasoning_effort": "high", "backend": "exec", "cmd": "/remote/bin/agent"}
		},
	} {
		v := good
		change(&v)
		if err := v.Validate(); err != nil {
			t.Fatalf("valid target rejected: %v", err)
		}
	}
	tests := map[string]func(*SSHTarget){
		"empty alias": func(v *SSHTarget) { v.Alias = "" }, "local alias": func(v *SSHTarget) { v.Alias = "local" }, "all alias": func(v *SSHTarget) { v.Alias = "all" },
		"flag alias": func(v *SSHTarget) { v.Alias = "-oProxyCommand=x" }, "shell alias": func(v *SSHTarget) { v.Alias = "x;id" }, "control alias": func(v *SSHTarget) { v.Alias = "x\ny" },
		"empty host": func(v *SSHTarget) { v.Host = "" }, "flag host": func(v *SSHTarget) { v.Host = "-oProxyCommand=x" }, "shell host": func(v *SSHTarget) { v.Host = "$(id)" }, "space host": func(v *SSHTarget) { v.Host = "host other" }, "user in host": func(v *SSHTarget) { v.Host = "user@host" }, "control host": func(v *SSHTarget) { v.Host = "host\x00" },
		"empty user": func(v *SSHTarget) { v.User = "" }, "flag user": func(v *SSHTarget) { v.User = "-root" }, "shell user": func(v *SSHTarget) { v.User = "a;id" }, "control user": func(v *SSHTarget) { v.User = "a\r" },
		"negative port": func(v *SSHTarget) { v.Port = -1 }, "large port": func(v *SSHTarget) { v.Port = 65536 },
		"ignore policy": func(v *SSHTarget) { v.HostKeyPolicy = "ignore" }, "no policy": func(v *SSHTarget) { v.HostKeyPolicy = "no" },
		"relative cwd": func(v *SSHTarget) { v.Cwd = "project" }, "control cwd": func(v *SSHTarget) { v.Cwd = "/private\npath" },
		"shell worker": func(v *SSHTarget) { v.WorkerCommand = "sh -c id" }, "worker substitution": func(v *SSHTarget) { v.WorkerCommand = "/bin/$(id)" }, "worker flag": func(v *SSHTarget) { v.WorkerCommand = "--help" }, "relative worker": func(v *SSHTarget) { v.WorkerCommand = "bin/worker" },
		"identity newline": func(v *SSHTarget) { v.IdentityFile = "/private\nidentity" }, "knownhosts newline": func(v *SSHTarget) { v.KnownHosts = "/private\nhosts" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			v := good
			change(&v)
			if v.Validate() == nil {
				t.Fatal("invalid target accepted")
			}
		})
	}
	for _, key := range []string{"key", "token", "secret", "password", "env", "run_as_user", "api_key", "api_base", "codex_home", "work_dir", "unknown", "Model"} {
		t.Run("option "+key, func(t *testing.T) {
			v := good
			v.AgentOptions = map[string]any{key: "private-option-value"}
			err := v.Validate()
			if err == nil {
				t.Fatal("unsafe option accepted")
			}
			if strings.Contains(err.Error(), "private-option-value") {
				t.Fatal("option leaked")
			}
		})
	}
	for _, value := range []any{42, true, []string{"x"}, map[string]any{"token": "s"}, "model\x1b[31m"} {
		v := good
		v.AgentOptions = map[string]any{"model": value}
		if v.Validate() == nil {
			t.Fatal("invalid option value accepted")
		}
	}
	for _, cmd := range []string{"sh -c id", "-bad", "relative/path", "/bin/$(id)"} {
		v := good
		v.AgentOptions = map[string]any{"cmd": cmd}
		if v.Validate() == nil {
			t.Fatal("unsafe remote cmd accepted")
		}
	}
	good.IdentityFile = "/private-identity-sentinel\n"
	good.KnownHosts = "/private-hosts-sentinel"
	good.Cwd = "relative-private-cwd-sentinel"
	err := good.Validate()
	if err == nil {
		t.Fatal("expected validation failure")
	}
	for _, secret := range []string{"private-identity-sentinel", "private-hosts-sentinel", "private-cwd-sentinel"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("private path leaked")
		}
	}
}

func TestSSHTargetTags(t *testing.T) {
	fields := map[string]string{"Alias": "alias", "Host": "host", "User": "user", "Port": "port", "IdentityFile": "identity_file", "KnownHosts": "known_hosts", "HostKeyPolicy": "host_key_policy", "IdentitiesOnly": "identities_only", "Cwd": "cwd", "WorkerCommand": "worker_command", "AgentOptions": "agent_options"}
	typ := reflect.TypeOf(SSHTarget{})
	for field, want := range fields {
		f, _ := typ.FieldByName(field)
		for _, tag := range []string{"json", "yaml", "toml"} {
			if strings.Split(f.Tag.Get(tag), ",")[0] != want {
				t.Errorf("%s %s tag mismatch", field, tag)
			}
		}
	}
}

func TestSSHModeTargetsCloneSortedAndDefaults(t *testing.T) {
	targets := sshTestTargets()
	m, err := NewSSHMode("", targets)
	if err != nil {
		t.Fatal(err)
	}
	targets[0].AgentOptions["model"] = "changed"
	targets[0].Host = "changed"
	got := m.Targets()
	if len(got) != 2 || got[0].Alias != "alpha" || got[1].Alias != "zeta" {
		t.Fatalf("not sorted: %v", got)
	}
	if got[1].HostKeyPolicy != "strict" {
		t.Fatal("strict must be default")
	}
	got[1].AgentOptions["model"] = "mutated"
	got[0].Host = "mutated"
	target, ok := m.Target("zeta")
	if !ok || target.Host != "192.0.2.10" || target.AgentOptions["model"] != "test-model" {
		t.Fatal("target aliased caller state")
	}
	target.AgentOptions["model"] = "mutated again"
	next, _ := m.Target("zeta")
	if next.AgentOptions["model"] != "test-model" {
		t.Fatal("Target did not clone")
	}
	if _, ok := m.Target("unknown"); ok {
		t.Fatal("unknown target exists")
	}
	duplicate := append(sshTestTargets(), sshTestTargets()[0])
	if _, err := NewSSHMode("", duplicate); err == nil {
		t.Fatal("duplicate alias accepted")
	}
	invalid := sshTestTargets()
	invalid[0].Host = "-bad"
	if _, err := NewSSHMode("", invalid); err == nil {
		t.Fatal("invalid target accepted")
	}
}

func TestSSHModeSessionBindingAndAutoPermissions(t *testing.T) {
	m, err := NewSSHMode("", sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	if m.CurrentBackend("s1") != "local" || !m.AutoEnabled("s1", "local") || !m.CanAutoSwitch("s1", "local") {
		t.Fatal("local defaults incorrect")
	}
	if m.AutoEnabled("s1", "alpha") || m.CanAutoSwitch("s1", "alpha") {
		t.Fatal("remote auto must default off")
	}
	for _, v := range []string{"local", "alpha", "zeta"} {
		if err := m.Validate(v); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"", "all", "unknown", "-bad"} {
		if m.Validate(v) == nil || m.CanAutoSwitch("s1", v) || m.AutoEnabled("s1", v) {
			t.Fatal("unknown backend accepted")
		}
	}
	if err := m.Use("s1", "alpha", ""); err != nil {
		t.Fatal(err)
	}
	if got, ok := m.Binding("s1"); !ok || got != (SSHBinding{Alias: "alpha", Cwd: "/srv/project"}) {
		t.Fatalf("default cwd missing: %+v", got)
	}
	if m.AutoEnabled("s1", "alpha") || !m.CanAutoSwitch("s1", "alpha") {
		t.Fatal("current off backend must remain usable without granting auto")
	}
	if m.CurrentBackend("s2") != "local" {
		t.Fatal("session binding leaked")
	}
	if err := m.SetAuto("s1", "alpha", true); err != nil {
		t.Fatal(err)
	}
	if m.AutoEnabled("s2", "alpha") {
		t.Fatal("grant leaked across sessions")
	}
	if err := m.SetAuto("s1", "alpha", false); err != nil {
		t.Fatal(err)
	}
	if m.CurrentBackend("s1") != "alpha" || !m.CanAutoSwitch("s1", "alpha") {
		t.Fatal("off returned to local")
	}
	if err := m.Use("s1", "zeta", "/remote/other project"); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Binding("s1"); got.Cwd != "/remote/other project" {
		t.Fatal("explicit cwd ignored")
	}
	if err := m.SetAuto("s1", "all", true); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"local", "alpha", "zeta"} {
		if !m.AutoEnabled("s1", b) {
			t.Fatalf("all missed %s", b)
		}
	}
	if err := m.SetAuto("s1", "all", false); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"local", "alpha", "zeta"} {
		if m.AutoEnabled("s1", b) {
			t.Fatalf("all missed %s", b)
		}
	}
	if !m.CanAutoSwitch("s1", "zeta") || m.CanAutoSwitch("s1", "local") {
		t.Fatal("off/current semantics incorrect")
	}
	if err := m.Use("s1", "local", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Binding("s1"); ok {
		t.Fatal("local must clear binding")
	}
	if m.CurrentBackend("s1") != "local" || m.AutoEnabled("s1", "local") {
		t.Fatal("Use must not grant auto")
	}
}

func TestSSHModePersistenceAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ssh")
	path := filepath.Join(dir, "mode.json")
	m, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("constructor wrote missing file")
	}
	if err := m.Use("s1", "alpha", "~/remote"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAuto("s1", "all", true); err != nil {
		t.Fatal(err)
	}
	if err := m.Use("s2", "zeta", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAuto("s2", "local", false); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := reopened.Binding("s1"); !ok || b.Cwd != "~/remote" || b.Alias != "alpha" {
		t.Fatal("binding not persisted")
	}
	if reopened.CurrentBackend("s2") != "zeta" || !reopened.AutoEnabled("s1", "zeta") || reopened.AutoEnabled("s2", "local") || reopened.AutoEnabled("s2", "alpha") {
		t.Fatal("grants not persisted or isolated")
	}
	if runtime.GOOS != "windows" {
		for p, mode := range map[string]os.FileMode{dir: 0700, path: 0600} {
			st, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != mode {
				t.Errorf("permissions %o want %o", st.Mode().Perm(), mode)
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("invalid JSON")
	}
	if bytes.Contains(data, []byte("host.example")) || bytes.Contains(data, []byte("agent_options")) {
		t.Fatal("state persisted target config")
	}
	if err := reopened.Use("s1", "local", ""); err != nil {
		t.Fatal(err)
	}
	again, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Binding("s1"); ok || !again.AutoEnabled("s1", "alpha") {
		t.Fatal("local clear altered grants")
	}
}

func TestSSHModeInvalidMutationsLeaveMemoryAndDiskUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Use("s", "alpha", ""); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	operations := []func() error{
		func() error { return m.Use("s", "unknown", "") }, func() error { return m.Use("s", "zeta", "relative") },
		func() error { return m.Use("s", "local", "relative") }, func() error { return m.Use("s", "zeta", "/private\npath") },
		func() error { return m.SetAuto("s", "unknown", true) }, func() error { return m.SetAuto("", "all", true) }, func() error { return m.Use("", "alpha", "") },
	}
	for _, op := range operations {
		if err := op(); err == nil {
			t.Fatal("invalid mutation succeeded")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) || m.CurrentBackend("s") != "alpha" || m.AutoEnabled("s", "zeta") {
			t.Fatal("failed mutation changed state")
		}
	}
}

func TestSSHModeWriteFailureIsAtomic(t *testing.T) {
	for _, operation := range []string{"use", "local", "auto", "all"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			m, err := NewSSHMode(path, sshTestTargets())
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Use("s", "alpha", ""); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			backup := filepath.Join(dir, "backup.json")
			if err := os.Rename(path, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			var failure error
			switch operation {
			case "use":
				failure = m.Use("s", "zeta", "")
			case "local":
				failure = m.Use("s", "local", "")
			case "auto":
				failure = m.SetAuto("s", "zeta", true)
			case "all":
				failure = m.SetAuto("s", "all", true)
			}
			if failure == nil {
				t.Fatal("write failure ignored")
			}
			if strings.Contains(failure.Error(), dir) {
				t.Fatal("private state path leaked")
			}
			after, _ := os.ReadFile(backup)
			if !bytes.Equal(before, after) || m.CurrentBackend("s") != "alpha" || m.AutoEnabled("s", "zeta") {
				t.Fatal("failed write changed memory or old disk state")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 2 {
				t.Fatal("orphan temporary file left")
			}
		})
	}
}

func TestSSHModeCorruptStoreFailsClosed(t *testing.T) {
	for _, data := range []string{"", "null", "[]", "{broken", "{}", `{"version":99,"bindings":{},"auto_switch":{}}`, `{"version":1,"bindings":{"s":{"alias":"missing","cwd":"/srv"}},"auto_switch":{}}`, `{"version":1,"bindings":{"s":{"alias":"alpha","cwd":"relative"}},"auto_switch":{}}`, `{"version":1,"bindings":{},"auto_switch":{"s":{"unknown":true}}}`, `{"version":1,"bindings":{},"auto_switch":{}} trailing`} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if m, err := NewSSHMode(path, sshTestTargets()); err == nil || m != nil {
			t.Fatal("corrupt store silently restored local")
		}
		after, _ := os.ReadFile(path)
		if string(after) != data {
			t.Fatal("corrupt store overwritten")
		}
	}
}

func TestSSHModeAmbiguousJSONFailsClosed(t *testing.T) {
	cases := map[string]string{
		"duplicate version":        `{"version":99,"version":1,"bindings":{},"auto_switch":{}}`,
		"duplicate bindings":       `{"version":1,"bindings":{"s":{"alias":"missing","cwd":"/srv"}},"bindings":{},"auto_switch":{}}`,
		"duplicate alias":          `{"version":1,"bindings":{"s":{"alias":"missing","alias":"alpha","cwd":"/srv"}},"auto_switch":{}}`,
		"duplicate session":        `{"version":1,"bindings":{},"auto_switch":{"s":{"alpha":false},"s":{"alpha":true}}}`,
		"duplicate grant":          `{"version":1,"bindings":{},"auto_switch":{"s":{"alpha":false,"alpha":true}}}`,
		"escaped duplicate grant":  `{"version":1,"bindings":{},"auto_switch":{"s":{"alpha":false,"\u0061lpha":true}}}`,
		"null grant":               `{"version":1,"bindings":{},"auto_switch":{"s":{"local":null}}}`,
		"null cwd":                 `{"version":1,"bindings":{"s":{"alias":"alpha","cwd":null}},"auto_switch":{}}`,
		"unknown field":            `{"version":1,"bindings":{},"auto_switch":{},"private-sentinel":1}`,
		"empty session":            `{"version":1,"bindings":{"":{"alias":"alpha","cwd":"/srv"}},"auto_switch":{}}`,
		"null session grants":      `{"version":1,"bindings":{},"auto_switch":{"s":null}}`,
		"unknown disabled backend": `{"version":1,"bindings":{},"auto_switch":{"s":{"missing":false}}}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-sentinel.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			m, err := NewSSHMode(path, sshTestTargets())
			if err == nil || m != nil {
				t.Fatal("ambiguous/corrupt state accepted")
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("state error leaked input")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != data {
				t.Fatal("corrupt state mutated")
			}
		})
	}
}

func TestSSHModeFullSessionKeysKeepGrantsIsolatedAfterReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		"project-one:feishu:chat:user:thread-one",
		"project-one:feishu:chat:user:thread-two",
		"project-two:feishu:chat:user:thread-one",
		"project-one:feishu:chat:other-user:thread-one",
	}
	if err := m.SetAuto(keys[0], "alpha", true); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAuto(keys[0], "zeta", true); err != nil {
		t.Fatal(err)
	}
	if err := m.Use(keys[0], "alpha", "~/isolated"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAuto(keys[0], "alpha", false); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.AutoEnabled(keys[0], "alpha") || !reopened.AutoEnabled(keys[0], "zeta") || reopened.CurrentBackend(keys[0]) != "alpha" || !reopened.CanAutoSwitch(keys[0], "alpha") {
		t.Fatal("off changed binding or sibling grant")
	}
	for _, key := range keys[1:] {
		if _, ok := reopened.Binding(key); ok {
			t.Fatal("binding leaked across full keys")
		}
		if reopened.CanAutoSwitch(key, "alpha") || reopened.AutoEnabled(key, "zeta") || !reopened.AutoEnabled(key, "local") {
			t.Fatal("grants leaked across full keys")
		}
	}
}

func TestSSHModeStateDirectoryFailurePreservesMemory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state-dir")
	path := filepath.Join(dir, "state.json")
	m, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Use("s", "alpha", "~/old"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "backup-dir")
	if err := os.Rename(dir, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("block directory creation"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, op := range []func() error{
		func() error { return m.Use("s", "local", "") },
		func() error { return m.SetAuto("s", "all", true) },
	} {
		err := op()
		if err == nil {
			t.Fatal("directory failure ignored")
		}
		if strings.Contains(err.Error(), root) {
			t.Fatal("private path leaked")
		}
		if m.CurrentBackend("s") != "alpha" || m.AutoEnabled("s", "zeta") {
			t.Fatal("failed write changed memory")
		}
		after, err := os.ReadFile(filepath.Join(backup, "state.json"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("failed write changed old state file")
		}
	}
}

func TestSSHModeStateReadFailureIsRedacted(t *testing.T) {
	path := t.TempDir()
	m, err := NewSSHMode(path, sshTestTargets())
	if err == nil || m != nil {
		t.Fatal("unreadable state accepted")
	}
	if strings.Contains(err.Error(), path) {
		t.Fatal("private path leaked")
	}
}

func TestSSHModeExistingDirectoryPermissionsUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	m, err := NewSSHMode(path, sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"alpha", "zeta", "local"} {
		if err := m.Use("s", backend, ""); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(dir)
		if err != nil || st.Mode().Perm() != 0755 {
			t.Fatal("shared directory permissions changed")
		}
		st, err = os.Stat(path)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("state file is not private")
		}
	}
}

func TestSSHModeConcurrentSessionIsolation(t *testing.T) {
	m, err := NewSSHMode(filepath.Join(t.TempDir(), "state.json"), sshTestTargets())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := fmt.Sprintf("session-%d", i)
			for j := 0; j < 8; j++ {
				if err := m.Use(s, "alpha", fmt.Sprintf("/remote/%d", i)); err != nil {
					t.Error(err)
				}
				if err := m.SetAuto(s, "zeta", i%2 == 0); err != nil {
					t.Error(err)
				}
				m.Targets()
				m.Target("alpha")
				m.Binding(s)
				m.CurrentBackend(s)
				m.CanAutoSwitch(s, "zeta")
				m.AutoEnabled(s, "zeta")
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < 12; i++ {
		s := fmt.Sprintf("session-%d", i)
		b, ok := m.Binding(s)
		if !ok || b.Cwd != fmt.Sprintf("/remote/%d", i) || m.AutoEnabled(s, "zeta") != (i%2 == 0) {
			t.Fatal("concurrent state lost or mixed")
		}
	}
}
