package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// handleSSH is a model-request surface on the owner's 0600 Unix socket, not an
// administrative grant endpoint. Remote workers expose a narrower callback
// whose conversation is captured by the gateway, not selected by the caller.
func (s *APIServer) handleSSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Project    string `json:"project"`
		SessionKey string `json:"session_key"`
		Action     string `json:"action"`
		Backend    string `json:"backend,omitempty"`
		Cwd        string `json:"cwd,omitempty"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid SSH request", 400)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid SSH request", 400)
		return
	}
	if strings.TrimSpace(req.Project) == "" || !sshValidSession(req.SessionKey) {
		http.Error(w, "project and conversation required", 400)
		return
	}
	switch req.Action {
	case "list", "status":
		if req.Backend != "" || req.Cwd != "" {
			http.Error(w, "unexpected SSH arguments", 400)
			return
		}
	case "test", "use":
		if req.Backend == "" || (req.Action == "test" && req.Cwd != "") {
			http.Error(w, "backend required; cwd for use only", 400)
			return
		}
	default:
		http.Error(w, "model API supports list/status/test/use only; permissions are user-owned", 400)
		return
	}
	s.mu.RLock()
	engine := s.engines[req.Project]
	s.mu.RUnlock()
	if engine == nil {
		http.Error(w, "project not found", 404)
		return
	}
	result, err := engine.SSHRequest(r.Context(), req.SessionKey, req.Action, req.Backend, req.Cwd)
	if err != nil {
		http.Error(w, "SSH request failed: "+err.Error(), 400)
		return
	}
	apiJSON(w, http.StatusOK, result)
}
