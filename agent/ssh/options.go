// Package sshagent runs native agents on an explicitly configured SSH target.
// It deliberately does not register an agent factory or expose local file/env
// capabilities: callers retain the native agent name and choose the transport.
package sshagent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Options separates SSH credentials from the explicitly configured remote
// agent options. AgentOptions must contain remote-safe constructor options,
// not a copied local environment, provider configuration, or local CLI path.
// WorkerCommand is ONE executable name/path, never a shell command string.
// Host-key checking is strict; accept-new is an explicit TOFU opt-in.
// IdentitiesOnly defaults to true (false does not opt out).
type Options struct {
	Host, User                              string
	Port                                    int
	IdentityFile, KnownHosts, HostKeyPolicy string
	IdentitiesOnly                          bool
	WorkDir, WorkerCommand, AgentType       string
	AgentOptions                            map[string]any
}

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
var userPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*[$]?$`)
var agentPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

func hasControl(v string) bool { return strings.IndexFunc(v, unicode.IsControl) >= 0 }

func normalizeOptions(o Options) (Options, error) {
	if strings.Contains(o.Host, ":") {
		host := o.Host
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if net.ParseIP(host) == nil {
			return o, errors.New("ssh: invalid host")
		}
		o.Host = host
	} else if !hostPattern.MatchString(o.Host) {
		return o, errors.New("ssh: invalid host")
	}
	if o.User != "" && !userPattern.MatchString(o.User) {
		return o, errors.New("ssh: invalid user")
	}
	if !agentPattern.MatchString(o.AgentType) {
		return o, errors.New("ssh: invalid agent type")
	}
	if o.Port == 0 {
		o.Port = 22
	}
	if o.Port < 1 || o.Port > 65535 {
		return o, errors.New("ssh: invalid port")
	}
	if o.HostKeyPolicy == "" {
		o.HostKeyPolicy = "strict"
	}
	if o.HostKeyPolicy != "strict" && o.HostKeyPolicy != "accept-new" {
		return o, errors.New("ssh: invalid host key policy")
	}
	if o.WorkerCommand == "" {
		o.WorkerCommand = "cc-connect"
	}
	if strings.HasPrefix(o.WorkerCommand, "-") || hasControl(o.WorkerCommand) {
		return o, errors.New("ssh: invalid worker executable")
	}
	if hasControl(o.WorkDir) {
		return o, errors.New("ssh: invalid work directory")
	}
	if hasControl(o.IdentityFile) || hasControl(o.KnownHosts) {
		return o, errors.New("ssh: invalid authentication path")
	}
	var pathErr error
	o.IdentityFile, pathErr = expandHome(o.IdentityFile)
	if pathErr != nil {
		return o, pathErr
	}
	o.KnownHosts, pathErr = expandHome(o.KnownHosts)
	if pathErr != nil {
		return o, pathErr
	}
	o.IdentitiesOnly = true
	b, err := json.Marshal(o.AgentOptions)
	if err != nil || len(b) > maxFrameBytes/2 {
		return o, errors.New("ssh: invalid agent options")
	}
	var snapshot map[string]any
	if err := json.Unmarshal(b, &snapshot); err != nil {
		return o, errors.New("ssh: invalid agent options")
	}
	if snapshot == nil {
		snapshot = map[string]any{}
	}
	o.AgentOptions = snapshot
	return o, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("ssh: cannot resolve home directory")
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

// Only this fixed vocabulary crosses the wire. Gateway credentials, local
// executable paths, provider/env maps and capability injection never do.
func safeAgentOptions(options map[string]any) (map[string]any, error) {
	safe := make(map[string]any)
	for k, v := range options {
		switch k {
		case "model", "mode", "reasoning_effort", "backend", "cmd":
		default:
			continue
		}
		text, ok := v.(string)
		if !ok || hasControl(text) {
			return nil, errors.New("ssh: invalid remote agent option")
		}
		if k == "cmd" && (text == "" || strings.HasPrefix(text, "-")) {
			return nil, errors.New("ssh: invalid remote agent executable")
		}
		safe[k] = text
	}
	return safe, nil
}

func remoteExecutable(path string) string {
	if path == "~" {
		return `"$HOME"`
	}
	if strings.HasPrefix(path, "~/") {
		return `"$HOME"/` + shellQuote(path[2:])
	}
	return shellQuote(path)
}

// command never assigns the remote work directory to the local SSH process.
func (a *Agent) command(ctx context.Context) *exec.Cmd {
	a.mu.Lock()
	o := a.opts
	a.mu.Unlock()
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "SendEnv=-*", "-p", strconv.Itoa(o.Port)}
	if o.HostKeyPolicy == "accept-new" {
		args[4] = "StrictHostKeyChecking=accept-new"
	}
	if o.IdentityFile != "" {
		args = append(args, "-i", o.IdentityFile)
	}
	// OpenSSH parses -o values again; quote spaces, quotes and backslashes.
	if o.KnownHosts != "" {
		quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(o.KnownHosts)
		args = append(args, "-o", `UserKnownHostsFile="`+quoted+`"`)
	}
	// Ignore both user and system ssh_config: SendEnv/SetEnv, ProxyCommand,
	// LocalCommand and connection multiplexing must not reintroduce capabilities.
	args = append(args, "-F", os.DevNull, "-o", "ForwardX11=no", "-o", "ForwardX11Trusted=no", "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "RequestTTY=no", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2")
	target := o.Host
	if o.User != "" {
		target = o.User + "@" + target
	}
	args = append(args, "--", target, "exec "+remoteExecutable(o.WorkerCommand)+" "+shellQuote("ssh")+" "+shellQuote("worker"))
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = []string{}
	for _, key := range []string{"HOME", "PATH", "USER", "LOGNAME", "LANG", "LC_CTYPE"} {
		if v, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	return cmd
}
