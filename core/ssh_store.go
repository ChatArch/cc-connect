package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// SSHTarget is an explicitly configured remote execution target. Paths belong
// to the target (except the SSH client's identity and known-hosts files); they
// are not probed locally. Never pass target configuration to a status response
// without redacting the identity and known-hosts paths.
type SSHTarget struct {
	Alias          string         `json:"alias" yaml:"alias" toml:"alias"`
	Host           string         `json:"host" yaml:"host" toml:"host"`
	User           string         `json:"user" yaml:"user" toml:"user"`
	Port           int            `json:"port" yaml:"port" toml:"port"`
	IdentityFile   string         `json:"identity_file" yaml:"identity_file" toml:"identity_file"`
	KnownHosts     string         `json:"known_hosts" yaml:"known_hosts" toml:"known_hosts"`
	HostKeyPolicy  string         `json:"host_key_policy" yaml:"host_key_policy" toml:"host_key_policy"`
	IdentitiesOnly bool           `json:"identities_only" yaml:"identities_only" toml:"identities_only"`
	Cwd            string         `json:"cwd" yaml:"cwd" toml:"cwd"`
	WorkerCommand  string         `json:"worker_command" yaml:"worker_command" toml:"worker_command"`
	AgentOptions   map[string]any `json:"agent_options" yaml:"agent_options" toml:"agent_options"`
}

// Validate rejects flag/shell injection and unsafe remote agent overrides.
// Errors deliberately name fields, never private paths or option values.
func (t SSHTarget) Validate() error {
	if !sshSafeName(t.Alias) || t.Alias == "local" || t.Alias == "all" {
		return errors.New("ssh: invalid or reserved target alias")
	}
	if !sshSafeHost(t.Host) {
		return errors.New("ssh: invalid target host")
	}
	if !sshSafeName(t.User) {
		return errors.New("ssh: invalid target user")
	}
	if t.Port < 0 || t.Port > 65535 {
		return errors.New("ssh: port must be 1..65535 or 0 for default")
	}
	if t.HostKeyPolicy != "" && t.HostKeyPolicy != "strict" && t.HostKeyPolicy != "accept-new" {
		return errors.New("ssh: host_key_policy must be strict or accept-new")
	}
	if sshHasControl(t.IdentityFile) {
		return errors.New("ssh: invalid identity_file")
	}
	if sshHasControl(t.KnownHosts) {
		return errors.New("ssh: invalid known_hosts")
	}
	if err := sshValidateCwd(t.Cwd); err != nil {
		return err
	}
	if t.WorkerCommand != "" && !sshSafeCommand(t.WorkerCommand) {
		return errors.New("ssh: worker_command must be a binary name or absolute/home-relative path")
	}
	for key, value := range t.AgentOptions {
		switch key {
		case "model", "mode", "reasoning_effort", "backend", "cmd":
		default:
			return errors.New("ssh: unsupported or unsafe agent option")
		}
		text, ok := value.(string)
		if !ok || sshHasControl(text) {
			return errors.New("ssh: agent options must be strings without control characters")
		}
		if key == "cmd" && !sshSafeCommand(text) {
			return errors.New("ssh: agent cmd must be an explicit remote binary name or absolute/home-relative path")
		}
	}
	return nil
}

func sshSafeName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			continue
		}
		if i > 0 && (c == '.' || c == '-') {
			continue
		}
		return false
	}
	return true
}

func sshSafeHost(s string) bool {
	if strings.Contains(s, ":") {
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			s = s[1 : len(s)-1]
		}
		return net.ParseIP(s) != nil
	}
	return sshSafeName(s)
}

func sshHasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}

func sshValidateCwd(cwd string) error {
	if cwd == "" {
		return nil
	}
	if sshHasControl(cwd) || !strings.HasPrefix(cwd, "/") && cwd != "~" && !strings.HasPrefix(cwd, "~/") {
		return errors.New("ssh: cwd must be absolute or home-relative, without control characters")
	}
	return nil
}

// Commands are executable paths, never shell programs plus arguments. The
// allowlist also prevents expansions when a remote shell invokes the worker.
func sshSafeCommand(s string) bool {
	if s == "" || s == "." || s == ".." || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "/") {
		return false
	}
	if strings.Contains(s, "/") && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "~/") {
		return false
	}
	if s == "~" {
		return false
	}
	for i, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '/' {
			continue
		}
		if i == 0 && c == '~' && strings.HasPrefix(s, "~/") {
			continue
		}
		return false
	}
	return true
}

func cloneSSHTarget(t SSHTarget) SSHTarget {
	if t.AgentOptions != nil {
		options := make(map[string]any, len(t.AgentOptions))
		for k, v := range t.AgentOptions {
			options[k] = v
		} // Validate permits only immutable strings.
		t.AgentOptions = options
	}
	return t
}

// SSHBinding is scoped to a full session key, including project/thread identity.
type SSHBinding struct {
	Alias string `json:"alias"`
	Cwd   string `json:"cwd"`
}

type sshModeState struct {
	Version    int                        `json:"version"`
	Bindings   map[string]SSHBinding      `json:"bindings"`
	AutoSwitch map[string]map[string]bool `json:"auto_switch"`
}

// SSHMode persists session bindings independently of automatic-switch grants.
// One instance owns a store path. Callers must share that instance; the mutex
// serializes both persistence and memory updates, not multiple OS processes.
type SSHMode struct {
	mu      sync.RWMutex
	path    string
	targets map[string]SSHTarget
	state   sshModeState
}

// NewSSHMode loads only its own JSON state. Missing state is normal; corrupt
// or stale/unknown bindings fail closed rather than silently reverting local.
// An empty path opts into in-memory state with the same validation semantics.
func NewSSHMode(path string, targets []SSHTarget) (*SSHMode, error) {
	m := &SSHMode{path: path, targets: make(map[string]SSHTarget), state: sshModeState{Version: 1, Bindings: make(map[string]SSHBinding), AutoSwitch: make(map[string]map[string]bool)}}
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return nil, err
		}
		if _, exists := m.targets[target.Alias]; exists {
			return nil, errors.New("ssh: duplicate target alias")
		}
		if target.HostKeyPolicy == "" {
			target.HostKeyPolicy = "strict"
		}
		m.targets[target.Alias] = cloneSSHTarget(target)
	}
	if path == "" {
		return m, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, errors.New("ssh: cannot read state file")
	}
	if err := sshCheckStateJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, errors.New("ssh: invalid state file")
	}
	if err := sshValidateStateFields(data); err != nil {
		return nil, errors.New("ssh: invalid state fields")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state sshModeState
	if err := dec.Decode(&state); err != nil {
		return nil, errors.New("ssh: invalid state file")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("ssh: invalid state file")
	}
	if state.Version != 1 || state.Bindings == nil || state.AutoSwitch == nil {
		return nil, errors.New("ssh: invalid state schema or version")
	}
	for session, binding := range state.Bindings {
		if !sshValidSession(session) || binding.Alias == "local" || m.Validate(binding.Alias) != nil || sshValidateCwd(binding.Cwd) != nil {
			return nil, errors.New("ssh: invalid or unconfigured stored binding")
		}
	}
	for session, grants := range state.AutoSwitch {
		if !sshValidSession(session) || grants == nil {
			return nil, errors.New("ssh: invalid stored auto-switch permissions")
		}
		for backend := range grants {
			if m.Validate(backend) != nil {
				return nil, errors.New("ssh: unconfigured stored auto-switch backend")
			}
		}
	}
	m.state = state
	return m, nil
}

// sshCheckStateJSON rejects ambiguities encoding/json normally accepts:
// duplicate keys (including escaped duplicates) and null scalar values. State
// contains only objects/scalars, at most root -> section -> session objects.
// The typed decoder below still enforces the field types and known fields.
func sshCheckStateJSON(dec *json.Decoder, depth int) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("ssh: null state value")
	}
	delim, object := token.(json.Delim)
	if !object {
		return nil
	}
	if delim != '{' || depth >= 3 {
		return errors.New("ssh: invalid state structure")
	}
	seen := make(map[string]bool)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return errors.New("ssh: duplicate or invalid state key")
		}
		seen[key] = true
		if err := sshCheckStateJSON(dec, depth+1); err != nil {
			return err
		}
	}
	token, err = dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('}') {
		return errors.New("ssh: invalid state structure")
	}
	return nil
}

// Targets returns sorted independent copies, not the mutable registry map.
func (m *SSHMode) Targets() []SSHTarget {
	result := make([]SSHTarget, 0, len(m.targets))
	for _, target := range m.targets {
		result = append(result, cloneSSHTarget(target))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Alias < result[j].Alias })
	return result
}

func (m *SSHMode) Target(alias string) (SSHTarget, bool) {
	target, ok := m.targets[alias]
	return cloneSSHTarget(target), ok
}

func (m *SSHMode) Binding(sessionKey string) (SSHBinding, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	binding, ok := m.state.Bindings[sessionKey]
	return binding, ok
}

func (m *SSHMode) CurrentBackend(sessionKey string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentLocked(sessionKey)
}

func (m *SSHMode) currentLocked(sessionKey string) string {
	if binding, ok := m.state.Bindings[sessionKey]; ok {
		return binding.Alias
	}
	return "local"
}

// Validate checks an execution backend. "all" is accepted only by SetAuto.
func (m *SSHMode) Validate(backend string) error {
	if backend == "local" {
		return nil
	}
	if _, ok := m.targets[backend]; !ok {
		return errors.New("ssh: unknown backend")
	}
	return nil
}

func sshValidSession(session string) bool {
	return strings.TrimSpace(session) != "" && !sshHasControl(session)
}

// Use is an explicit user-authorized switch; it never changes auto grants.
// Empty cwd uses the target default. Returning local removes the binding.
func (m *SSHMode) Use(sessionKey, backend, cwd string) error {
	if !sshValidSession(sessionKey) {
		return errors.New("ssh: invalid session key")
	}
	if err := m.Validate(backend); err != nil {
		return err
	}
	if err := sshValidateCwd(cwd); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.cloneStateLocked()
	if backend == "local" {
		delete(next.Bindings, sessionKey)
	} else {
		if cwd == "" {
			cwd = m.targets[backend].Cwd
		}
		next.Bindings[sessionKey] = SSHBinding{Alias: backend, Cwd: cwd}
	}
	return m.commitLocked(next)
}

// SetAuto changes only the named session's automatic-switch permission.
// "all" updates local and every configured remote atomically.
func (m *SSHMode) SetAuto(sessionKey, backend string, enabled bool) error {
	if !sshValidSession(sessionKey) {
		return errors.New("ssh: invalid session key")
	}
	if backend != "all" {
		if err := m.Validate(backend); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.cloneStateLocked()
	if next.AutoSwitch[sessionKey] == nil {
		next.AutoSwitch[sessionKey] = make(map[string]bool)
	}
	grants := next.AutoSwitch[sessionKey]
	if backend == "all" {
		grants["local"] = enabled
		for alias := range m.targets {
			grants[alias] = enabled
		}
	} else {
		grants[backend] = enabled
	}
	return m.commitLocked(next)
}

// CanAutoSwitch allows continuing on the current backend even if its grant
// is off. Disabling auto never forces an active session to another backend.
func (m *SSHMode) CanAutoSwitch(sessionKey, backend string) bool {
	if m.Validate(backend) != nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentLocked(sessionKey) == backend || m.autoEnabledLocked(sessionKey, backend)
}

func (m *SSHMode) AutoEnabled(sessionKey, backend string) bool {
	if m.Validate(backend) != nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.autoEnabledLocked(sessionKey, backend)
}

func (m *SSHMode) autoEnabledLocked(sessionKey, backend string) bool {
	if enabled, ok := m.state.AutoSwitch[sessionKey][backend]; ok {
		return enabled
	}
	return backend == "local"
}

func (m *SSHMode) cloneStateLocked() sshModeState {
	next := sshModeState{Version: 1, Bindings: make(map[string]SSHBinding, len(m.state.Bindings)), AutoSwitch: make(map[string]map[string]bool, len(m.state.AutoSwitch))}
	for key, binding := range m.state.Bindings {
		next.Bindings[key] = binding
	}
	for key, grants := range m.state.AutoSwitch {
		next.AutoSwitch[key] = make(map[string]bool, len(grants))
		for backend, enabled := range grants {
			next.AutoSwitch[key][backend] = enabled
		}
	}
	return next
}

// Persist before publishing: any write failure preserves the prior memory and
// file. Newly created store directories are private; shared parents are never
// chmod'ed. AtomicWriteFile cleans up temporary files on every failure path.
func (m *SSHMode) commitLocked(next sshModeState) error {
	if m.path != "" {
		data, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			return errors.New("ssh: cannot encode state")
		}
		if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
			return errors.New("ssh: cannot create state directory")
		}
		if err := AtomicWriteFile(m.path, data, 0600); err != nil {
			return errors.New("ssh: cannot write state file")
		}
	}
	m.state = next
	return nil
}
