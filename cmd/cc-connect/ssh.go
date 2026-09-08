package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	sshagent "github.com/chenhg5/cc-connect/agent/ssh"
	"github.com/chenhg5/cc-connect/config"
	"github.com/chenhg5/cc-connect/core"
)

const sshUsage = `Usage: cc-connect ssh <list|status|test|use|worker> [backend] [options]

  list                   List configured execution backends.
  status                 Show the current conversation's backend and permissions.
  test <backend>         Validate configuration only; does not connect or switch.
  use <backend>          Request a switch, subject to user auto-switch grants.
  worker                 Serve one SSH stdio connection (internal, no config load).

Options:
  --cwd <path>           Remote absolute or ~/ directory (use only).
  --project <name>       Project (defaults to CC_PROJECT).
  --session <key>        Conversation key (defaults to CC_SESSION_KEY).
  --data-dir <path>      Control socket directory (defaults to CC_DATA_DIR).
  --offline             Read own registry without a daemon (list/test only).
  --config <path>        Config file for offline inspection only.

All output is JSON. Exit 0: request completed; 2: approval_required or
switch_pending (finish this turn; the next user turn uses the new backend).
Human-only auto permission controls: /ssh on|off <backend|all> in chat.
/ssh off does not return local. Use /ssh use local for an explicit return.
`

type sshCLIRequest struct {
	Project    string `json:"project"`
	SessionKey string `json:"session_key"`
	Action     string `json:"action"`
	Backend    string `json:"backend,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	DataDir    string `json:"-"`
	Config     string `json:"-"`
	Offline    bool   `json:"-"`
}

func runSSH(args []string) { os.Exit(executeSSH(args, os.Stdout, os.Stderr)) }

func parseSSHArgs(args []string) (sshCLIRequest, error) {
	r := sshCLIRequest{Project: strings.TrimSpace(os.Getenv("CC_PROJECT")), SessionKey: strings.TrimSpace(os.Getenv("CC_SESSION_KEY"))}
	if len(args) == 0 {
		return r, errors.New("SSH action required")
	}
	r.Action = args[0]
	switch r.Action {
	case "list", "status", "test", "use":
	default:
		return r, errors.New("unsupported SSH action")
	}
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if seen[arg] {
				return r, errors.New("duplicate SSH option")
			}
			seen[arg] = true
			if arg == "--offline" {
				r.Offline = true
				continue
			}
			switch arg {
			case "--cwd", "--project", "--session", "--data-dir", "--config":
			default:
				return r, errors.New("unknown SSH option")
			}
			i++
			if i >= len(args) || args[i] == "" {
				return r, errors.New("SSH option requires a value")
			}
			v := args[i]
			switch arg {
			case "--cwd":
				r.Cwd = v
			case "--project":
				if r.Project != "" && r.Project != v {
					return r, errors.New("cannot override active project")
				}
				r.Project = v
			case "--session":
				if r.SessionKey != "" && r.SessionKey != v {
					return r, errors.New("cannot override active conversation")
				}
				r.SessionKey = v
			case "--data-dir":
				r.DataDir = v
			case "--config":
				r.Config = v
			}
		} else {
			if r.Backend != "" {
				return r, errors.New("unexpected SSH argument")
			}
			r.Backend = arg
		}
	}
	if (r.Action == "test" || r.Action == "use") != (r.Backend != "") {
		return r, errors.New("test/use require exactly one backend; list/status take none")
	}
	if r.Cwd != "" && r.Action != "use" {
		return r, errors.New("cwd is only valid with use")
	}
	if r.Offline && r.Action != "list" && r.Action != "test" {
		return r, errors.New("offline supports list and test only")
	}
	if r.Config != "" && !r.Offline {
		return r, errors.New("config is only valid for offline inspection")
	}
	if !r.Offline && (r.Project == "" || r.SessionKey == "") {
		return r, errors.New("project and conversation are required (CC_PROJECT/CC_SESSION_KEY)")
	}
	return r, nil
}

func executeSSH(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, _ = io.WriteString(out, sshUsage)
		return 0
	}
	if args[0] == "worker" {
		if len(args) != 1 {
			_, _ = fmt.Fprintln(errOut, "ssh worker takes no arguments")
			return 1
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := sshagent.ServeWorker(ctx, os.Stdin, out); err != nil {
			_, _ = fmt.Fprintln(errOut, "ssh worker: connection failed")
			return 1
		}
		return 0
	}
	req, err := parseSSHArgs(args)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	var response any
	if req.Offline {
		response, err = sshOffline(req)
	} else {
		response, err = sshOnline(req)
	}
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	if err := json.NewEncoder(out).Encode(response); err != nil {
		_, _ = fmt.Fprintln(errOut, "cannot write SSH result")
		return 1
	}
	if r, ok := response.(map[string]any); ok {
		switch r["status"] {
		case "approval_required", "switch_pending":
			return 2
		}
	}
	return 0
}

func sshOffline(req sshCLIRequest) (any, error) {
	path := req.Config
	if path == "" {
		path = filepath.Join(defaultAppHomeDir(), "config.toml")
	}
	dataDir, settings, err := config.LoadSSHSettings(path)
	if err != nil {
		return nil, err
	}
	if req.DataDir != "" {
		dataDir = req.DataDir
	}
	targets, err := config.LoadSSHTargets(dataDir, settings)
	if err != nil {
		return nil, err
	}
	mode, err := core.NewSSHMode("", targets)
	if err != nil {
		return nil, err
	}
	if req.Action == "test" {
		if err := mode.Validate(req.Backend); err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "backend": req.Backend, "validation": "configuration only; no network connection"}, nil
	}
	backends := []map[string]any{{"backend": "local", "type": "local"}}
	for _, t := range mode.Targets() {
		view := map[string]any{"backend": t.Alias, "type": "ssh", "host": t.Host, "user": t.User, "port": t.Port, "cwd": t.Cwd, "host_key_policy": t.HostKeyPolicy}
		if t.IdentityFile != "" {
			view["identity_file"] = "[REDACTED_PATH]"
		}
		if t.KnownHosts != "" {
			view["known_hosts"] = "[REDACTED_PATH]"
		}
		backends = append(backends, view)
	}
	return map[string]any{"status": "ok", "offline": true, "backends": backends}, nil
}

func sshOnline(req sshCLIRequest) (map[string]any, error) {
	socket := resolveSocketPath(req.DataDir)
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, errors.New("ssh: cannot encode request")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	resp, err := client.Post("http://unix/ssh", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("ssh: control API unavailable; start cc-connect or use list/test --offline")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ssh: control request rejected (HTTP %d)", resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	var result map[string]any
	if err := dec.Decode(&result); err != nil || result == nil {
		return nil, errors.New("ssh: invalid control response")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("ssh: invalid control response")
	}
	switch result["status"] {
	case "ok", "approval_required", "switch_pending":
		return result, nil
	default:
		return nil, errors.New("ssh: unsuccessful control response")
	}
}

// Factory copies only explicitly configured REMOTE options. Never forward local
// provider credentials, CLI paths, run_as_env, or the gateway process environment.
func makeSSHAgentFactory(agentType string) func(core.SSHTarget, string) (core.Agent, error) {
	return func(t core.SSHTarget, cwd string) (core.Agent, error) {
		if err := t.Validate(); err != nil {
			return nil, err
		}
		return sshagent.New(sshagent.Options{Host: t.Host, User: t.User, Port: t.Port, IdentityFile: t.IdentityFile, KnownHosts: t.KnownHosts, HostKeyPolicy: t.HostKeyPolicy, IdentitiesOnly: true, WorkDir: cwd, WorkerCommand: t.WorkerCommand, AgentType: agentType, AgentOptions: t.AgentOptions})
	}
}

func sshModeStatePath(dataDir, project string) string {
	// Hash the exact project name: sanitized names can collide (a/b vs a_b).
	digest := sha256.Sum256([]byte(project))
	return filepath.Join(dataDir, "ssh", "state", fmt.Sprintf("%x.json", digest))
}
