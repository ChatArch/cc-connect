package sshagent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/chenhg5/cc-connect/core"
)

// Bounds apply to encoded NDJSON frames, including base64 attachment data.
const maxFrameBytes = 8 << 20
const maxCommandOutput = 1 << 20

var errDisconnected = errors.New("ssh: worker connection closed")
var errFrameTooLarge = errors.New("ssh: protocol frame exceeds size limit")

// Both sides use JSON-RPC 2.0 with one JSON object per line. IDs correlate
// responses; event notifications never consume a request ID. The first request
// must be initialize. There is one agent and at most one session per worker.
type packet struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type requestArgs struct {
	AgentType      string                 `json:"agent_type,omitempty"`
	ControlEnabled bool                   `json:"control_enabled,omitempty"`
	Options        map[string]any         `json:"options,omitempty"`
	WorkDir        string                 `json:"work_dir,omitempty"`
	SessionID      string                 `json:"session_id,omitempty"`
	Prompt         string                 `json:"prompt,omitempty"`
	Images         []core.ImageAttachment `json:"images,omitempty"`
	Files          []core.FileAttachment  `json:"files,omitempty"`
	RequestID      string                 `json:"request_id,omitempty"`
	Permission     core.PermissionResult  `json:"permission,omitempty"`
	Command        string                 `json:"command,omitempty"`
}
type result struct {
	SessionID string                    `json:"session_id,omitempty"`
	Alive     bool                      `json:"alive"`
	Sessions  []core.AgentSessionInfo   `json:"sessions,omitempty"`
	Models    []core.ModelOption        `json:"models,omitempty"`
	Modes     []core.PermissionModeInfo `json:"modes,omitempty"`
	Output    string                    `json:"output,omitempty"`
	ExitCode  int                       `json:"exit_code"`
}
type eventMessage struct {
	Event     core.Event `json:"event"`
	ErrorText string     `json:"error_text,omitempty"`
	SessionID string     `json:"session_id,omitempty"`
	Alive     bool       `json:"alive"`
}

// Remove the interface-typed Error before decoding core.Event. A peer may
// serialize it as an object/string; neither is safe to expose as diagnostics.
func (m *eventMessage) UnmarshalJSON(b []byte) error {
	var raw struct {
		Event     json.RawMessage `json:"event"`
		ErrorText string          `json:"error_text"`
		SessionID string          `json:"session_id"`
		Alive     bool            `json:"alive"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw.Event, &fields); err != nil {
		return err
	}
	hasError := raw.ErrorText != ""
	for key, v := range fields {
		if strings.EqualFold(key, "error") {
			hasError = hasError || string(v) != "null"
			delete(fields, key)
		}
	}
	event, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(event, &m.Event); err != nil {
		return err
	}
	m.SessionID = raw.SessionID
	m.Alive = raw.Alive
	if hasError || m.Event.Type == core.EventError {
		m.ErrorText = "ssh: native agent reported an error"
		m.Event.Error = errors.New(m.ErrorText)
		m.Event.Content = ""
	}
	return nil
}

func encode(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, errors.New("ssh: invalid protocol value")
	}
	if len(b)+1 > maxFrameBytes {
		return nil, errFrameTooLarge
	}
	return b, nil
}
func scanner(in io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 4096), maxFrameBytes)
	return s
}

type packetWriter struct {
	mu     sync.Mutex
	out    io.Writer
	ctx    context.Context
	cancel context.CancelFunc
}

func (w *packetWriter) write(p packet) error {
	p.JSONRPC = "2.0"
	b, err := encode(p)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	ctx := w.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return errDisconnected
	}
	// A pipe/socket must be closable. Closing the owned stream interrupts a
	// blocked Write without abandoning a writer goroutine or retaining its frame.
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	stopped := make(chan struct{})
	stop := context.AfterFunc(writeCtx, func() {
		defer close(stopped)
		if w.cancel != nil {
			w.cancel()
		}
		if c, ok := w.out.(io.Closer); ok {
			_ = c.Close()
		}
	})
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	b = append(b, '\n')
	for len(b) > 0 {
		n, err := w.out.Write(b)
		if err != nil {
			return errDisconnected
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
