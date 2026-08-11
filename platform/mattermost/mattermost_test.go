package mattermost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chenhg5/cc-connect/core"
)

func TestNewRequiresURLAndToken(t *testing.T) {
	if _, err := New(map[string]any{"token": "tok"}); err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("New without url error = %v, want url requirement", err)
	}
	if _, err := New(map[string]any{"url": "https://matter.example"}); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("New without token error = %v, want token requirement", err)
	}
}

func TestNormalizeSessionScope(t *testing.T) {
	cases := []struct {
		raw   any
		share bool
		want  string
	}{
		{nil, false, "user"},
		{nil, true, "channel"},
		{"", false, "user"},
		{"user", true, "user"},
		{"channel", false, "channel"},
		{"thread", false, "thread"},
		{" Thread ", false, "thread"},
		{"bogus", false, "user"},
		{"bogus", true, "channel"},
	}
	for _, c := range cases {
		if got := normalizeSessionScope(c.raw, c.share); got != c.want {
			t.Fatalf("normalizeSessionScope(%v, share=%v) = %q, want %q", c.raw, c.share, got, c.want)
		}
	}
}

func TestBuildSessionKey(t *testing.T) {
	const (
		channel = "channel123"
		user    = "user456"
		thread  = "root789"
	)
	cases := []struct {
		scope  string
		rootID string
		want   string
	}{
		{"user", thread, "mattermost:channel123:user456"},
		{"channel", thread, "mattermost:channel123"},
		{"thread", thread, "mattermost:channel123:t:root789"},
		{"thread", "", "mattermost:channel123:user456"},
		{"", thread, "mattermost:channel123:user456"},
	}
	for _, c := range cases {
		p := &Platform{sessionScope: c.scope}
		if got := p.buildSessionKey(channel, user, c.rootID); got != c.want {
			t.Fatalf("scope=%q rootID=%q: buildSessionKey = %q, want %q", c.scope, c.rootID, got, c.want)
		}
	}
}

func TestReconstructReplyCtx(t *testing.T) {
	p := &Platform{}
	cases := []struct {
		key     string
		channel string
		rootID  string
	}{
		{"mattermost:channel123:user456", "channel123", ""},
		{"mattermost:channel123", "channel123", ""},
		{"mattermost:channel123:t:root789", "channel123", "root789"},
	}
	for _, c := range cases {
		got, err := p.ReconstructReplyCtx(c.key)
		if err != nil {
			t.Fatalf("ReconstructReplyCtx(%q) error: %v", c.key, err)
		}
		rc := got.(replyContext)
		if rc.ChannelID != c.channel || rc.RootID != c.rootID {
			t.Fatalf("ReconstructReplyCtx(%q) = {channel:%q root:%q}, want {channel:%q root:%q}", c.key, rc.ChannelID, rc.RootID, c.channel, c.rootID)
		}
	}
	if _, err := p.ReconstructReplyCtx("slack:C123:U456"); err == nil {
		t.Fatal("ReconstructReplyCtx should reject non-mattermost keys")
	}
}

func TestShouldHandlePostDMBypassesMention(t *testing.T) {
	p := &Platform{botUsername: "cc-connect", botUserID: "bot", allowFrom: "user1"}
	post := mattermostPost{ID: "post1", UserID: "user1", ChannelID: "dmchan", Message: "hello without mention"}
	channel := mattermostChannel{ID: "dmchan", Type: "D"}
	content, rootID, ok := p.shouldHandlePost(post, channel)
	if !ok {
		t.Fatal("DM should trigger without @mention")
	}
	if content != "hello without mention" {
		t.Fatalf("content = %q", content)
	}
	if rootID != "post1" {
		t.Fatalf("rootID = %q, want post1 so replies can thread under the DM message", rootID)
	}
}

func TestShouldHandlePostChannelRequiresMention(t *testing.T) {
	p := &Platform{botUsername: "cc-connect", botUserID: "bot", allowFrom: "user1"}
	channel := mattermostChannel{ID: "chan", Type: "O"}
	if _, _, ok := p.shouldHandlePost(mattermostPost{ID: "p1", UserID: "user1", ChannelID: "chan", Message: "hello"}, channel); ok {
		t.Fatal("channel message without bot mention should not trigger")
	}
	content, rootID, ok := p.shouldHandlePost(mattermostPost{ID: "p2", UserID: "user1", ChannelID: "chan", Message: "@cc-connect please help"}, channel)
	if !ok {
		t.Fatal("channel message with @mention should trigger")
	}
	if content != "please help" {
		t.Fatalf("content = %q, want mention stripped", content)
	}
	if rootID != "p2" {
		t.Fatalf("rootID = %q, want p2", rootID)
	}
}

func TestShouldHandlePostSkipsSelfUnauthorizedAndDuplicate(t *testing.T) {
	p := &Platform{botUsername: "cc-connect", botUserID: "bot", allowFrom: "user1"}
	channel := mattermostChannel{ID: "chan", Type: "O"}
	if _, _, ok := p.shouldHandlePost(mattermostPost{ID: "self", UserID: "bot", ChannelID: "chan", Message: "@cc-connect self"}, channel); ok {
		t.Fatal("self message should not trigger by default")
	}
	if _, _, ok := p.shouldHandlePost(mattermostPost{ID: "unauth", UserID: "user2", ChannelID: "chan", Message: "@cc-connect no"}, channel); ok {
		t.Fatal("unauthorized user should not trigger")
	}
	post := mattermostPost{ID: "dup", UserID: "user1", ChannelID: "chan", Message: "@cc-connect once"}
	if _, _, ok := p.shouldHandlePost(post, channel); !ok {
		t.Fatal("first duplicate candidate should trigger")
	}
	if _, _, ok := p.shouldHandlePost(post, channel); ok {
		t.Fatal("second duplicate candidate should not trigger")
	}
}

func TestShouldHandlePostAllowsExplicitSelfMessageSmoke(t *testing.T) {
	p := &Platform{botUsername: "cc-connect", botUserID: "bot", allowFrom: "*", allowSelfMessages: true}
	channel := mattermostChannel{ID: "chan", Type: "O"}
	content, _, ok := p.shouldHandlePost(mattermostPost{ID: "self-smoke", UserID: "bot", ChannelID: "chan", Message: "@cc-connect /help"}, channel)
	if !ok {
		t.Fatal("self message should trigger when allow_self_messages is explicitly enabled")
	}
	if content != "/help" {
		t.Fatalf("content = %q, want /help after mention stripping", content)
	}
}

func TestHandlePostedEventDispatchesCoreMessage(t *testing.T) {
	p := &Platform{
		url:          "https://matter.example",
		botUsername:  "cc-connect",
		botUserID:    "bot",
		allowFrom:    "user1",
		sessionScope: "thread",
		channelLookup: func(context.Context, string) (mattermostChannel, error) {
			return mattermostChannel{ID: "chan", Name: "agent-lab", Type: "O", TeamID: "team1"}, nil
		},
		userLookup: func(context.Context, string) (mattermostUser, error) {
			return mattermostUser{ID: "user1", Username: "alice", FirstName: "Alice"}, nil
		},
	}
	var got *core.Message
	p.handler = func(_ core.Platform, msg *core.Message) { got = msg }

	post := mattermostPost{ID: "post1", CreateAt: 1720000000000, UserID: "user1", ChannelID: "chan", Message: "@cc-connect summarize", RootID: "root0"}
	rawPost, _ := json.Marshal(post)
	event := mattermostWebSocketEvent{Event: "posted", Data: map[string]any{"post": string(rawPost)}}
	if err := p.handleWebSocketEvent(context.Background(), event); err != nil {
		t.Fatalf("handleWebSocketEvent error: %v", err)
	}
	if got == nil {
		t.Fatal("expected core.Message")
	}
	if got.Platform != "mattermost" || got.MessageID != "post1" || got.ChannelID != "chan" || got.ChannelKey != "mattermost:team1:chan" {
		t.Fatalf("unexpected message identity: %#v", got)
	}
	if got.SessionKey != "mattermost:chan:t:root0" {
		t.Fatalf("SessionKey = %q", got.SessionKey)
	}
	if got.Content != "summarize" || got.UserName != "Alice" || got.ChatName != "agent-lab" {
		t.Fatalf("unexpected content/user/chat: content=%q user=%q chat=%q", got.Content, got.UserName, got.ChatName)
	}
	rc := got.ReplyCtx.(replyContext)
	if rc.ChannelID != "chan" || rc.RootID != "root0" || rc.PostID != "post1" {
		t.Fatalf("reply context = %#v", rc)
	}
}

func TestReplyPostsThreadedMessage(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotPayload map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"reply1"}`))
	}))
	defer ts.Close()

	p := &Platform{url: ts.URL, token: "secret-token"}
	err := p.Reply(context.Background(), replyContext{ChannelID: "chan", RootID: "root1"}, "hello **world**")
	if err != nil {
		t.Fatalf("Reply error: %v", err)
	}
	if gotPath != "/api/v4/posts" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotPayload["channel_id"] != "chan" || gotPayload["root_id"] != "root1" || gotPayload["message"] != "hello **world**" {
		t.Fatalf("payload = %#v", gotPayload)
	}
}

var _ core.Platform = (*Platform)(nil)
var _ core.ReplyContextReconstructor = (*Platform)(nil)
