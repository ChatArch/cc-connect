package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chenhg5/cc-connect/config"
	"github.com/chenhg5/cc-connect/core"
)

type stubMainAgent struct {
	workDir string
}

func (a *stubMainAgent) Name() string { return "stub-main" }

func (a *stubMainAgent) StartSession(_ context.Context, _ string) (core.AgentSession, error) {
	return &stubMainAgentSession{}, nil
}

func (a *stubMainAgent) ListSessions(_ context.Context) ([]core.AgentSessionInfo, error) {
	return nil, nil
}

func (a *stubMainAgent) Stop() error { return nil }

func (a *stubMainAgent) SetWorkDir(dir string) {
	a.workDir = dir
}

func (a *stubMainAgent) GetWorkDir() string {
	return a.workDir
}

type stubMainAgentSession struct{}

func (s *stubMainAgentSession) Send(string, []core.ImageAttachment, []core.FileAttachment) error {
	return nil
}
func (s *stubMainAgentSession) RespondPermission(string, core.PermissionResult) error { return nil }
func (s *stubMainAgentSession) Events() <-chan core.Event                             { return nil }
func (s *stubMainAgentSession) Close() error                                          { return nil }
func (s *stubMainAgentSession) CurrentSessionID() string                              { return "" }
func (s *stubMainAgentSession) Alive() bool                                           { return true }

func TestProjectStatePath(t *testing.T) {
	dataDir := t.TempDir()
	got := projectStatePath(dataDir, "my/project:one")
	want := filepath.Join(dataDir, "projects", "my_project_one.state.json")
	if got != want {
		t.Fatalf("projectStatePath() = %q, want %q", got, want)
	}
}

func TestResolveResetOnIdle(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	cases := []struct {
		name          string
		configured    *int
		wantDuration  time.Duration
		wantDefaulted bool
	}{
		{
			name:          "unset applies default and reports defaulted",
			configured:    nil,
			wantDuration:  time.Duration(defaultResetOnIdleMins) * time.Minute,
			wantDefaulted: true,
		},
		{
			name:          "explicit zero opts out and is not defaulted",
			configured:    intPtr(0),
			wantDuration:  0,
			wantDefaulted: false,
		},
		{
			name:          "explicit positive value is honored",
			configured:    intPtr(45),
			wantDuration:  45 * time.Minute,
			wantDefaulted: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDuration, gotDefaulted := resolveResetOnIdle(tc.configured)
			if gotDuration != tc.wantDuration {
				t.Errorf("duration = %v, want %v", gotDuration, tc.wantDuration)
			}
			if gotDefaulted != tc.wantDefaulted {
				t.Errorf("defaulted = %v, want %v", gotDefaulted, tc.wantDefaulted)
			}
		})
	}
}

func TestApplyProjectStateOverride(t *testing.T) {
	baseDir := t.TempDir()
	overrideDir := filepath.Join(t.TempDir(), "override")
	if err := os.Mkdir(overrideDir, 0o755); err != nil {
		t.Fatalf("mkdir override dir: %v", err)
	}

	store := core.NewProjectStateStore(filepath.Join(t.TempDir(), "projects", "demo.state.json"))
	store.SetWorkDirOverride(overrideDir)

	agent := &stubMainAgent{workDir: baseDir}
	got := applyProjectStateOverride("demo", agent, baseDir, store)

	if got != overrideDir {
		t.Fatalf("applyProjectStateOverride() = %q, want %q", got, overrideDir)
	}
	if agent.workDir != overrideDir {
		t.Fatalf("agent workDir = %q, want %q", agent.workDir, overrideDir)
	}
}

func TestResolveConfigPathSkipsCodexConfigInCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	cwd := filepath.Join(dir, "cwd")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	t.Setenv("HOME", home)
	t.Chdir(cwd)

	codexConfig := `model_provider = "crs"
preferred_auth_method = "token"

[model_providers.crs]
name = "crs"

[projects."/home/zhihong"]
trust_level = "trusted"
`
	if err := os.WriteFile(filepath.Join(cwd, "config.toml"), []byte(codexConfig), 0o644); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	want := filepath.Join(home, ".chatarch", "cc-connect", "config.toml")
	if got := resolveConfigPath(""); got != want {
		t.Fatalf("resolveConfigPath() = %q, want %q", got, want)
	}
}

func TestResolveConfigPathKeepsCCConnectConfigInCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Chdir(dir)

	ccConnectConfig := `[[projects]]
name = "demo"

[projects.agent]
type = "codex"
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(ccConnectConfig), 0o644); err != nil {
		t.Fatalf("write cc-connect config: %v", err)
	}

	if got := resolveConfigPath(""); got != "config.toml" {
		t.Fatalf("resolveConfigPath() = %q, want config.toml", got)
	}
}

type stubProviderRefreshAgent struct {
	stubMainAgent
	providers  []core.ProviderConfig
	activeName string
	calls      []string
	activateOK bool
}

func (a *stubProviderRefreshAgent) SetProviders(providers []core.ProviderConfig) {
	a.providers = append([]core.ProviderConfig(nil), providers...)
	a.calls = append(a.calls, "set_providers")
}

func (a *stubProviderRefreshAgent) SetActiveProvider(name string) bool {
	if !a.activateOK {
		a.calls = append(a.calls, "set_active_provider_failed")
		return false
	}
	a.activeName = name
	a.calls = append(a.calls, "set_active_provider")
	return true
}

func (a *stubProviderRefreshAgent) GetActiveProvider() *core.ProviderConfig {
	for i := range a.providers {
		if a.providers[i].Name == a.activeName {
			return &a.providers[i]
		}
	}
	return nil
}

func (a *stubProviderRefreshAgent) ListProviders() []core.ProviderConfig {
	providers := make([]core.ProviderConfig, len(a.providers))
	copy(providers, a.providers)
	return providers
}

func (a *stubProviderRefreshAgent) StartInitialModelRefresh() {
	a.calls = append(a.calls, "start_initial_model_refresh")
}

func TestBuildAgentOptionsInjectsProjectScope(t *testing.T) {
	proj := config.ProjectConfig{
		Name: "demo-project",
		Agent: config.AgentConfig{
			Options: map[string]any{
				"work_dir": "/tmp/work",
				"model":    "gpt-test",
			},
		},
	}

	got := buildAgentOptions("/tmp/data", proj)

	if got["cc_data_dir"] != "/tmp/data" {
		t.Fatalf("cc_data_dir = %v, want %q", got["cc_data_dir"], "/tmp/data")
	}
	if got["cc_project"] != "demo-project" {
		t.Fatalf("cc_project = %v, want %q", got["cc_project"], "demo-project")
	}
	if got["work_dir"] != "/tmp/work" || got["model"] != "gpt-test" {
		t.Fatalf("buildAgentOptions() lost existing options: %v", got)
	}
	if _, exists := proj.Agent.Options["cc_data_dir"]; exists {
		t.Fatalf("project agent options mutated: %v", proj.Agent.Options)
	}
}

func TestWireAgentProvidersStartsRefreshAfterProviderWiring(t *testing.T) {
	agent := &stubProviderRefreshAgent{activateOK: true}
	proj := config.ProjectConfig{
		Agent: config.AgentConfig{
			Options: map[string]any{"provider": "provider-b"},
			Providers: []config.ProviderConfig{
				{Name: "provider-a", APIKey: "key-a"},
				{Name: "provider-b", APIKey: "key-b", Model: "model-b"},
			},
		},
	}

	result := wireAgentProviders(agent, proj.Agent)
	startInitialRefreshIfReady(agent, result)

	wantCalls := []string{"set_providers", "set_active_provider", "start_initial_model_refresh"}
	if !reflect.DeepEqual(agent.calls, wantCalls) {
		t.Fatalf("call order = %v, want %v", agent.calls, wantCalls)
	}
	if len(agent.providers) != 2 {
		t.Fatalf("provider count = %d, want 2", len(agent.providers))
	}
	if agent.activeName != "provider-b" {
		t.Fatalf("active provider = %q, want %q", agent.activeName, "provider-b")
	}
}

func TestWireAgentProviders_SkipsRefreshWhenExplicitProviderActivationFails(t *testing.T) {
	agent := &stubProviderRefreshAgent{}
	agent.activateOK = false
	agent.workDir = "/tmp/original"
	proj := config.ProjectConfig{
		Agent: config.AgentConfig{
			Options:   map[string]any{"provider": "missing-provider"},
			Providers: []config.ProviderConfig{{Name: "provider-a", APIKey: "key-a"}},
		},
	}

	result := wireAgentProviders(agent, proj.Agent)

	if result.canStartInitialRefresh {
		t.Fatal("canStartInitialRefresh = true, want false")
	}
	if !result.explicitProviderRequested {
		t.Fatal("explicitProviderRequested = false, want true")
	}
	if result.activeProviderApplied {
		t.Fatal("activeProviderApplied = true, want false")
	}
	wantCalls := []string{"set_providers", "set_active_provider_failed"}
	if !reflect.DeepEqual(agent.calls, wantCalls) {
		t.Fatalf("call order = %v, want %v", agent.calls, wantCalls)
	}
}

func TestWireAgentProviders_AllowsRefreshWithoutProviders(t *testing.T) {
	agent := &stubProviderRefreshAgent{stubMainAgent: stubMainAgent{workDir: "/tmp/original"}}
	proj := config.ProjectConfig{Agent: config.AgentConfig{Options: map[string]any{}}}

	result := wireAgentProviders(agent, proj.Agent)

	if !result.canStartInitialRefresh {
		t.Fatal("canStartInitialRefresh = false, want true")
	}
	if result.explicitProviderRequested {
		t.Fatal("explicitProviderRequested = true, want false")
	}
	if result.activeProviderApplied {
		t.Fatal("activeProviderApplied = true, want false")
	}
	if len(agent.calls) != 0 {
		t.Fatalf("calls = %v, want no provider wiring calls", agent.calls)
	}
}

func TestStartInitialRefresh_AfterProjectStateOverride(t *testing.T) {
	agent := &stubProviderRefreshAgent{activateOK: true, stubMainAgent: stubMainAgent{workDir: "/tmp/original"}}
	overrideDir := filepath.Join(t.TempDir(), "override")
	if err := os.Mkdir(overrideDir, 0o755); err != nil {
		t.Fatalf("mkdir override dir: %v", err)
	}
	store := core.NewProjectStateStore(filepath.Join(t.TempDir(), "projects", "demo.state.json"))
	store.SetWorkDirOverride(overrideDir)
	proj := config.ProjectConfig{
		Name: "demo",
		Agent: config.AgentConfig{
			Options:   map[string]any{"provider": "provider-b", "work_dir": "/tmp/original"},
			Providers: []config.ProviderConfig{{Name: "provider-a"}, {Name: "provider-b"}},
		},
	}

	result := wireAgentProviders(agent, proj.Agent)
	applyProjectStateOverride(proj.Name, agent, "/tmp/original", store)
	startInitialRefreshIfReady(agent, result)

	wantCalls := []string{"set_providers", "set_active_provider", "start_initial_model_refresh"}
	if !reflect.DeepEqual(agent.calls, wantCalls) {
		t.Fatalf("call order = %v, want %v", agent.calls, wantCalls)
	}
	if agent.workDir != overrideDir {
		t.Fatalf("agent workDir at refresh = %q, want %q", agent.workDir, overrideDir)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = old
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy stderr: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	return buf.String()
}

func TestPrintUsage_ListsCronExecCommand(t *testing.T) {
	out := captureStderr(t, printUsage)

	if !strings.Contains(out, "Manage scheduled tasks") {
		t.Fatalf("printUsage() output missing cron section:\n%s", out)
	}
	if !strings.Contains(out, "exec             Trigger a scheduled task immediately") {
		t.Fatalf("printUsage() output missing cron exec command:\n%s", out)
	}
}

func TestCanonicalCronSubcommand_ManualTriggerAliases(t *testing.T) {
	for _, sub := range []string{"exec", "run", "trigger"} {
		if got := canonicalCronSubcommand(sub); got != "exec" {
			t.Fatalf("canonicalCronSubcommand(%q) = %q, want exec", sub, got)
		}
	}
}
