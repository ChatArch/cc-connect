package sshagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chenhg5/cc-connect/core"
)

// This is a deterministic local subprocess fixture, NOT a real SSH/model smoke.
func TestSSHWorkerHelper(t *testing.T) {
	if os.Getenv("CC_SSH_TEST_WORKER") != "1" {
		return
	}
	core.RegisterAgent("ssh-test-fixture", func(opts map[string]any) (core.Agent, error) {
		if os.Getenv("CC_SSH_ASSERT_SAFE_OPTIONS") == "1" {
			for _, key := range []string{"env", "api_key", "providers", "cli_path"} {
				if _, ok := opts[key]; ok {
					return nil, errors.New("unsafe options reached worker")
				}
			}
		}
		if os.Getenv("CC_SSH_ASSERT_REMOTE_CMD") == "1" && opts["cmd"] != filepath.Join(os.Getenv("HOME"), ".local/bin/native") {
			return nil, errors.New("remote cmd not expanded")
		}
		if opts["model"] == "fail" {
			return nil, errors.New("secret CANARY /private/identity")
		}
		// Test-only lifecycle markers stay out of production constructor options.
		for _, key := range []string{"stop_marker", "close_marker"} {
			if v := os.Getenv("CC_SSH_TEST_" + key); v != "" {
				opts[key] = v
			}
		}
		return &fixtureAgent{opts: opts}, nil
	})
	if err := ServeWorker(context.Background(), os.Stdin, os.Stdout); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

type fixtureAgent struct {
	opts map[string]any
	env  []string
}

func (a *fixtureAgent) Name() string { return "ssh-test-fixture" }
func (a *fixtureAgent) Stop() error {
	if p, _ := a.opts["stop_marker"].(string); p != "" {
		return os.WriteFile(p, []byte("stopped"), 0600)
	}
	return nil
}
func (a *fixtureAgent) StartSession(ctx context.Context, id string) (core.AgentSession, error) {
	if id == "fail" {
		return nil, errors.New("CANARY /private/session")
	}
	if id == "" {
		id = "initial"
	}
	s := &fixtureSession{ctx: ctx, id: id, events: make(chan core.Event, 256), alive: true, opts: a.opts, env: a.env}
	return s, nil
}
func (a *fixtureAgent) ListSessions(ctx context.Context) ([]core.AgentSessionInfo, error) {
	if a.opts["model"] == "list-fail" {
		return nil, errors.New("CANARY /private/history")
	}
	return []core.AgentSessionInfo{{ID: "remote-history", Summary: fmt.Sprint(a.opts["work_dir"]), MessageCount: 7}}, nil
}
func (a *fixtureAgent) SetModel(v string) { a.opts["model"] = v }
func (a *fixtureAgent) GetModel() string  { v, _ := a.opts["model"].(string); return v }
func (a *fixtureAgent) AvailableModels(context.Context) []core.ModelOption {
	return []core.ModelOption{{Name: "fixture-model", Desc: "not a real model"}}
}
func (a *fixtureAgent) SetMode(v string) { a.opts["mode"] = v }
func (a *fixtureAgent) GetMode() string  { v, _ := a.opts["mode"].(string); return v }
func (a *fixtureAgent) PermissionModes() []core.PermissionModeInfo {
	return []core.PermissionModeInfo{{Key: "ask"}}
}

type fixtureSession struct {
	mu     sync.Mutex
	ctx    context.Context
	id     string
	events chan core.Event
	alive  bool
	opts   map[string]any
	env    []string
}

func (s *fixtureSession) Send(prompt string, images []core.ImageAttachment, files []core.FileAttachment) error {
	if strings.HasPrefix(prompt, "control:") {
		text, err := fixtureControl(s.env, "/ssh", strings.TrimPrefix(prompt, "control:"))
		if err != nil {
			return err
		}
		dir := ""
		for _, kv := range s.env {
			if strings.HasPrefix(kv, "CC_DATA_DIR=") {
				dir = strings.TrimPrefix(kv, "CC_DATA_DIR=")
			}
		}
		if len(s.env) != 3 {
			return errors.New("unexpected environment injection")
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.alive {
			return errors.New("closed")
		}
		s.events <- core.Event{Type: core.EventText, Content: text, Metadata: map[string]any{"control_dir": dir}}
		return nil
	}
	if prompt == "native-eof" {
		return nil
	}
	if prompt == "block" {
		<-s.ctx.Done()
		return s.ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.alive {
		return errors.New("closed")
	}
	if prompt == "error" {
		return errors.New("CANARY /private/credential")
	}
	if prompt == "result-and-eof" {
		s.events <- core.Event{Type: core.EventResult, Content: "definitive-result", Done: true}
		s.alive = false
		close(s.events)
		s.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		s.mu.Lock()
		return nil
	}
	if prompt == "event-error" {
		s.events <- core.Event{Type: core.EventError, Error: errors.New("CANARY /private/file"), Content: "CANARY /private/file"}
		return nil
	}
	s.id = "remote-current"
	s.events <- core.Event{Type: core.EventText, Content: prompt, SessionID: s.id, Metadata: map[string]any{"work_dir": s.opts["work_dir"], "images": images, "files": files, "model": s.opts["model"], "mode": s.opts["mode"]}}
	s.events <- core.Event{Type: core.EventPermissionRequest, RequestID: "permission-1", ToolName: "Bash", ToolInputRaw: map[string]any{"command": "pwd"}, Questions: []core.UserQuestion{{Question: "Proceed?"}}}
	return nil
}
func (s *fixtureSession) RespondPermission(id string, r core.PermissionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.alive {
		return errors.New("closed")
	}
	if id == "native-eof" {
		s.alive = false
		close(s.events)
		return nil
	}
	s.events <- core.Event{Type: core.EventResult, RequestID: id, Content: r.Behavior, Done: true, SessionID: s.id, InputTokens: 11, Metadata: r.UpdatedInput}
	if id == "eof-with-result" {
		s.alive = false
		close(s.events)
	}
	return nil
}
func (s *fixtureSession) Events() <-chan core.Event { return s.events }
func (s *fixtureSession) CurrentSessionID() string  { s.mu.Lock(); defer s.mu.Unlock(); return s.id }
func (s *fixtureSession) Alive() bool               { s.mu.Lock(); defer s.mu.Unlock(); return s.alive }
func (s *fixtureSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alive {
		s.alive = false
		close(s.events)
	}
	if p, _ := s.opts["close_marker"].(string); p != "" {
		return os.WriteFile(p, []byte("closed"), 0600)
	}
	return nil
}

func fixtureTransport(t *testing.T, opts Options) *Agent {
	t.Helper()
	opts.Host = "never-contact-this-fixture.invalid"
	opts.AgentType = "ssh-test-fixture"
	raw, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	a := raw.(*Agent)
	a.launch = func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHWorkerHelper$")
		cmd.Env = append(os.Environ(), "CC_SSH_TEST_WORKER=1")
		for _, key := range []string{"stop_marker", "close_marker"} {
			if v, ok := opts.AgentOptions[key].(string); ok {
				cmd.Env = append(cmd.Env, "CC_SSH_TEST_"+key+"="+v)
			}
		}
		return cmd
	}
	t.Cleanup(func() {
		if err := a.Stop(); err != nil {
			t.Error(err)
		}
	})
	return a
}
func nextEvent(t *testing.T, s core.AgentSession) core.Event {
	t.Helper()
	select {
	case e, ok := <-s.Events():
		if !ok {
			t.Fatal("events closed early")
		}
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("event timeout")
		return core.Event{}
	}
}
func assertClosed(t *testing.T, s core.AgentSession) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case _, ok := <-s.Events():
			if !ok {
				return
			}
		case <-timer.C:
			t.Fatal("session events did not close")
		}
	}
}

func TestTransportRoundTripAttachmentsPermissionsAndResume(t *testing.T) {
	a := fixtureTransport(t, Options{WorkDir: "/remote only/not-local", AgentOptions: map[string]any{"model": "m1", "mode": "ask"}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := a.StartSession(ctx, "resume-42")
	if err != nil {
		t.Fatal(err)
	}
	if s.CurrentSessionID() != "resume-42" || !s.Alive() {
		t.Fatal("session did not resume alive")
	}
	images := []core.ImageAttachment{{MimeType: "image/png", FileName: "photo.png", Data: []byte{0, 1, 2, 255}}}
	files := []core.FileAttachment{{MimeType: "text/plain", FileName: "readme.txt", Data: []byte("actual bytes, not a local path")}}
	if err := s.Send("hello", images, files); err != nil {
		t.Fatal(err)
	}
	e := nextEvent(t, s)
	if e.Type != core.EventText || e.Content != "hello" || e.SessionID != "remote-current" || e.Metadata["work_dir"] != "/remote only/not-local" {
		t.Fatalf("bad text event %#v", e)
	}
	for key, want := range map[string]any{"images": images, "files": files} {
		got, _ := json.Marshal(e.Metadata[key])
		wantJSON, _ := json.Marshal(want)
		var gotValue, wantValue any
		_ = json.Unmarshal(got, &gotValue)
		_ = json.Unmarshal(wantJSON, &wantValue)
		if !reflect.DeepEqual(gotValue, wantValue) {
			t.Fatalf("%s not serialized: %s != %s", key, got, wantJSON)
		}
	}
	e = nextEvent(t, s)
	if e.Type != core.EventPermissionRequest || e.ToolInputRaw["command"] != "pwd" || len(e.Questions) != 1 {
		t.Fatalf("bad permission event %#v", e)
	}
	if err := s.RespondPermission(e.RequestID, core.PermissionResult{Behavior: "allow", UpdatedInput: map[string]any{"command": "pwd"}}); err != nil {
		t.Fatal(err)
	}
	e = nextEvent(t, s)
	if e.Type != core.EventResult || e.Content != "allow" || !e.Done || e.InputTokens != 11 || e.Metadata["command"] != "pwd" {
		t.Fatalf("bad result %#v", e)
	}
	if s.CurrentSessionID() != "remote-current" {
		t.Fatal("session ID not updated")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, s)
	if s.Alive() {
		t.Fatal("closed session alive")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("after close", nil, nil); err == nil {
		t.Fatal("send after close succeeded")
	}
}

func TestListMetadataAndMutableInstanceOptions(t *testing.T) {
	a := fixtureTransport(t, Options{WorkDir: "/remote/one", AgentOptions: map[string]any{"model": "one", "mode": "ask"}})
	a.SetWorkDir("/remote/two")
	a.SetModel("two")
	a.SetMode("review")
	if a.GetWorkDir() != "/remote/two" || a.GetModel() != "two" || a.GetMode() != "review" {
		t.Fatal("option updates lost")
	}
	got, err := a.ListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "remote-history" || got[0].Summary != "/remote/two" {
		t.Fatalf("list: %#v", got)
	}
	if m := a.AvailableModels(context.Background()); len(m) != 1 || m[0].Name != "fixture-model" {
		t.Fatalf("metadata models: %#v", m)
	}
	if m := a.PermissionModes(); len(m) != 1 || m[0].Key != "ask" {
		t.Fatalf("metadata modes: %#v", m)
	}
}

func TestTransportErrorsDoNotLeakPrivateDiagnostics(t *testing.T) {
	for _, model := range []string{"fail", "list-fail"} {
		a := fixtureTransport(t, Options{AgentOptions: map[string]any{"model": model}})
		_, err := a.ListSessions(context.Background())
		if err == nil || strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "/private") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
	a := fixtureTransport(t, Options{})
	if _, err := a.StartSession(context.Background(), "fail"); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("unsafe start error: %v", err)
	}
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send("error", nil, nil); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("unsafe send error: %v", err)
	}
	if err := s.Send("event-error", nil, nil); err != nil {
		t.Fatal(err)
	}
	e := nextEvent(t, s)
	if e.Error == nil || strings.Contains(e.Error.Error()+e.Content, "CANARY") {
		t.Fatalf("unsafe event error: %#v", e)
	}
}

func TestCancellationIsolatesConnectionsAndReapsWorker(t *testing.T) {
	dir := t.TempDir()
	a := fixtureTransport(t, Options{AgentOptions: map[string]any{"stop_marker": filepath.Join(dir, "stop"), "close_marker": filepath.Join(dir, "close")}})
	ctx, cancel := context.WithCancel(context.Background())
	s, err := a.StartSession(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.StartSession(context.Background(), "second")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Send("block", nil, nil) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled send succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation hung")
	}
	assertClosed(t, s)
	if s.Alive() {
		t.Fatal("canceled connection alive")
	}
	if !second.Alive() {
		t.Fatal("cancellation killed unrelated connection")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"close", "stop"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("worker did not clean %s: %v", n, err)
		}
	}
}

func TestWorkerEOFInvalidProtocolAndBoundedRequest(t *testing.T) {
	for _, input := range []string{"", "not-json\n", strings.Repeat("x", maxFrameBytes+1) + "\n"} {
		var out bytes.Buffer
		err := ServeWorker(context.Background(), strings.NewReader(input), &out)
		if input != "" && err == nil {
			t.Fatal("bad protocol accepted")
		}
		if strings.Contains(out.String(), "not-json") {
			t.Fatal("echoed malformed request")
		}
	}
	a := fixtureTransport(t, Options{})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(strings.Repeat("x", maxFrameBytes), nil, nil); err == nil {
		t.Fatal("oversized send accepted")
	}
	if !s.Alive() {
		t.Fatal("preflight validation killed valid session")
	}
}

func TestConcurrentSessionRequestsDoNotMixResponses(t *testing.T) {
	a := fixtureTransport(t, Options{})
	s, err := a.StartSession(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.RespondPermission(fmt.Sprint(i), core.PermissionResult{Behavior: "deny"}); err != nil {
				t.Error(err)
			}
			_ = s.CurrentSessionID()
			_ = s.Alive()
		}(i)
	}
	wg.Wait()
	ids := map[string]bool{}
	for i := 0; i < 20; i++ {
		ids[nextEvent(t, s).RequestID] = true
	}
	if len(ids) != 20 {
		t.Fatalf("lost/mixed events: %#v", ids)
	}
}

func TestRunCommandUsesRemoteDirectoryAndCapturesExit(t *testing.T) {
	dir := t.TempDir()
	a := fixtureTransport(t, Options{WorkDir: dir})
	output, code, err := a.RunCommand(context.Background(), "pwd; printf out; printf err >&2; exit 7")
	if err != nil || code != 7 || !strings.Contains(output, dir) || !strings.Contains(output, "out") || !strings.Contains(output, "err") {
		t.Fatalf("exec = %q, %d, %v", output, code, err)
	}
	output, code, err = a.RunCommand(context.Background(), "printf remote > proof; cat proof")
	if err != nil || code != 0 || output != "remote" {
		t.Fatalf("exec side effect = %q %d %v", output, code, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "proof"))
	if err != nil || string(b) != "remote" {
		t.Fatal("command did not write in configured directory")
	}
}

func TestRunCommandCancellationAndBoundedOutput(t *testing.T) {
	a := fixtureTransport(t, Options{WorkDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := a.RunCommand(ctx, "sleep 30 & wait")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("cancel: %v in %v", err, time.Since(start))
	}
	output, code, err := a.RunCommand(context.Background(), "yes x | head -c 2000000")
	if err != nil || code != 0 || len(output) > maxCommandOutput+100 || len(output) < maxCommandOutput {
		t.Fatalf("output cap: len=%d code=%d err=%v", len(output), code, err)
	}
}

func TestWorkerContextCancellationUnblocksOwnedInput(t *testing.T) {
	r, w := io.Pipe()
	defer func() { _ = w.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeWorker(ctx, r, io.Discard) }()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker blocked on input after context cancellation")
	}
}

func TestTransportDoesNotExposeLocalEnvironmentInjection(t *testing.T) {
	a := fixtureTransport(t, Options{})
	typ := reflect.TypeOf(a)
	for _, method := range []string{"SetSessionEnv", "SetProviders", "GlobalMemoryFile", "ProjectMemoryFile", "SkillDirs", "CommandDirs"} {
		if _, ok := typ.MethodByName(method); ok {
			t.Fatalf("unsafe local capability exposed: %s", method)
		}
	}
}
