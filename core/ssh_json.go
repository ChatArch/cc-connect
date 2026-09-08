package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// sshExactObject validates only structural field names. Caller-owned map keys
// (session IDs, backend aliases) must never be case-folded.
func sshExactObject(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("ssh: expected JSON object")
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || !allowed[key] {
			return nil, errors.New("ssh: unknown or noncanonical JSON field")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("ssh: duplicate JSON field")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, errors.New("ssh: null JSON field")
		}
		fields[key] = raw
	}
	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("ssh: invalid JSON object")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("ssh: trailing JSON value")
	}
	for _, key := range required {
		if _, exists := fields[key]; !exists {
			return nil, errors.New("ssh: missing JSON field")
		}
	}
	return fields, nil
}

func sshValidateStateFields(data []byte) error {
	fields, err := sshExactObject(data, []string{"version", "bindings", "auto_switch"}, nil)
	if err != nil {
		return err
	}
	var bindings map[string]json.RawMessage
	if err := json.Unmarshal(fields["bindings"], &bindings); err != nil {
		return err
	}
	for _, raw := range bindings {
		if _, err := sshExactObject(raw, []string{"alias", "cwd"}, nil); err != nil {
			return err
		}
	}
	return nil
}

// SSHControlRequest is shared by the owner-local API and the remote worker's
// narrower proxy. Authorization and conversation binding remain in the caller.
type SSHControlRequest struct {
	Project    string `json:"project"`
	SessionKey string `json:"session_key"`
	Action     string `json:"action"`
	Backend    string `json:"backend,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
}

// DecodeSSHControlRequest rejects duplicates, case aliases, missing required
// fields, nulls, unknown fields and trailing JSON before any action is selected.
// Its limit is intrinsic so both API surfaces have the same bounded contract.
func DecodeSSHControlRequest(reader io.Reader) (SSHControlRequest, error) {
	var req SSHControlRequest
	data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return req, errors.New("ssh: invalid or oversized control request")
	}
	if _, err := sshExactObject(data, []string{"project", "session_key", "action"}, []string{"backend", "cwd"}); err != nil {
		return req, errors.New("ssh: invalid control request fields")
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return SSHControlRequest{}, errors.New("ssh: invalid control request values")
	}
	return req, nil
}
