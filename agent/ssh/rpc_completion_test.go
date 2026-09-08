package sshagent

import (
	"context"
	"encoding/json"
	"testing"
)

type rpcReplyWriter func([]byte) (int, error)

func (w rpcReplyWriter) Write(p []byte) (int, error) { return w(p) }

// Pause RPC consumption at the writer boundary. Both cancellation cases and
// the authoritative reply are ready before call enters its select.
func TestRPCBufferedReplyWinsSharedContextCancellation(t *testing.T) {
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		c := &connection{ctx: ctx, cancel: cancel, pending: map[uint64]chan packet{}}
		c.writer = packetWriter{out: rpcReplyWriter(func(b []byte) (int, error) {
			var p packet
			if err := json.Unmarshal(b, &p); err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			ch := c.pending[p.ID]
			c.mu.Unlock()
			ch <- packet{JSONRPC: "2.0", ID: p.ID, Result: json.RawMessage(`{"output":"confirmed"}`)}
			cancel()
			return len(b), nil
		})}
		result, err := c.call(ctx, "send", requestArgs{})
		if err != nil || result.Output != "confirmed" {
			t.Fatalf("buffered authoritative reply lost: %+v %v", result, err)
		}
	}
}
