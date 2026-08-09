package mattermost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/chenhg5/cc-connect/core"
	"github.com/gorilla/websocket"
)

func init() {
	core.RegisterPlatform("mattermost", New)
}

type replyContext struct {
	ChannelID string
	RootID    string
	PostID    string
}

type Platform struct {
	url               string
	token             string
	allowFrom         string
	sessionScope      string
	botUserID         string
	botUsername       string
	allowSelfMessages bool

	handler core.MessageHandler
	cancel  context.CancelFunc

	dedup core.MessageDedup

	mu       sync.Mutex
	ws       *websocket.Conn
	channels sync.Map // channelID -> mattermostChannel
	users    sync.Map // userID -> mattermostUser

	channelLookup func(context.Context, string) (mattermostChannel, error)
	userLookup    func(context.Context, string) (mattermostUser, error)
}

type mattermostPost struct {
	ID        string `json:"id"`
	CreateAt  int64  `json:"create_at"`
	UpdateAt  int64  `json:"update_at"`
	EditAt    int64  `json:"edit_at"`
	DeleteAt  int64  `json:"delete_at"`
	UserID    string `json:"user_id"`
	ChannelID string `json:"channel_id"`
	RootID    string `json:"root_id"`
	Message   string `json:"message"`
	Type      string `json:"type"`
}

type mattermostChannel struct {
	ID          string `json:"id"`
	TeamID      string `json:"team_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
}

type mattermostUser struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Nickname  string `json:"nickname"`
}

type mattermostWebSocketEvent struct {
	Seq       int            `json:"seq"`
	Event     string         `json:"event"`
	Action    string         `json:"action"`
	Status    string         `json:"status"`
	Data      map[string]any `json:"data"`
	Broadcast map[string]any `json:"broadcast"`
}

func New(opts map[string]any) (core.Platform, error) {
	rawURL, _ := opts["url"].(string)
	if rawURL == "" {
		rawURL, _ = opts["server_url"].(string)
	}
	token, _ := opts["token"].(string)
	if token == "" {
		token, _ = opts["bot_token"].(string)
	}
	if rawURL == "" {
		return nil, fmt.Errorf("mattermost: url is required")
	}
	if token == "" {
		return nil, fmt.Errorf("mattermost: token is required")
	}
	allowFrom, _ := opts["allow_from"].(string)
	core.CheckAllowFrom("mattermost", allowFrom)
	shareSessionInChannel, _ := opts["share_session_in_channel"].(bool)
	scope := normalizeSessionScope(opts["session_scope"], shareSessionInChannel)
	botUsername, _ := opts["bot_username"].(string)
	allowSelfMessages, _ := opts["allow_self_messages"].(bool)

	return &Platform{
		url:               strings.TrimRight(rawURL, "/"),
		token:             token,
		allowFrom:         allowFrom,
		sessionScope:      scope,
		botUsername:       strings.TrimPrefix(strings.TrimSpace(botUsername), "@"),
		allowSelfMessages: allowSelfMessages,
	}, nil
}

func normalizeSessionScope(raw any, shareInChannel bool) string {
	fallback := "user"
	if shareInChannel {
		fallback = "channel"
	}
	s, _ := raw.(string)
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "user":
		return "user"
	case "channel":
		return "channel"
	case "thread":
		return "thread"
	case "":
		return fallback
	default:
		slog.Warn("mattermost: unknown session_scope, falling back", "session_scope", s, "using", fallback)
		return fallback
	}
}

func (p *Platform) Name() string { return "mattermost" }

func (p *Platform) Start(handler core.MessageHandler) error {
	p.handler = handler
	if p.channelLookup == nil {
		p.channelLookup = p.getChannel
	}
	if p.userLookup == nil {
		p.userLookup = p.getUser
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	if err := p.ensureSelf(ctx); err != nil {
		cancel()
		return err
	}
	conn, err := p.connectWebSocket(ctx)
	if err != nil {
		cancel()
		return err
	}
	p.mu.Lock()
	p.ws = conn
	p.mu.Unlock()

	go p.readLoop(ctx, conn)
	slog.Info("mattermost: websocket connected")
	return nil
}

func (p *Platform) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ws != nil {
		_ = p.ws.Close()
		p.ws = nil
	}
	return nil
}

func (p *Platform) buildSessionKey(channelID, userID, rootID string) string {
	switch p.sessionScope {
	case "channel":
		return fmt.Sprintf("mattermost:%s", channelID)
	case "thread":
		if rootID != "" {
			return fmt.Sprintf("mattermost:%s:t:%s", channelID, rootID)
		}
		return fmt.Sprintf("mattermost:%s:%s", channelID, userID)
	default:
		return fmt.Sprintf("mattermost:%s:%s", channelID, userID)
	}
}

func (p *Platform) ReconstructReplyCtx(sessionKey string) (any, error) {
	parts := strings.SplitN(sessionKey, ":", 3)
	if len(parts) < 2 || parts[0] != "mattermost" {
		return nil, fmt.Errorf("mattermost: invalid session key %q", sessionKey)
	}
	rc := replyContext{ChannelID: parts[1]}
	if len(parts) == 3 && strings.HasPrefix(parts[2], "t:") {
		rc.RootID = strings.TrimPrefix(parts[2], "t:")
	}
	return rc, nil
}

func (p *Platform) shouldHandlePost(post mattermostPost, channel mattermostChannel) (content string, rootID string, ok bool) {
	if post.ID == "" || post.UserID == "" || post.ChannelID == "" {
		return "", "", false
	}
	if post.DeleteAt != 0 || post.Type != "" {
		return "", "", false
	}
	if !p.allowSelfMessages && p.botUserID != "" && post.UserID == p.botUserID {
		return "", "", false
	}
	if p.dedup.IsDuplicate(post.ID) {
		return "", "", false
	}
	if !core.AllowList(p.allowFrom, post.UserID) {
		slog.Debug("mattermost: message from unauthorized user", "user", post.UserID)
		return "", "", false
	}
	content = strings.TrimSpace(post.Message)
	if content == "" {
		return "", "", false
	}
	rootID = post.RootID
	if rootID == "" {
		rootID = post.ID
	}
	if strings.EqualFold(channel.Type, "D") {
		return content, rootID, true
	}
	stripped, mentioned := p.stripBotMention(content)
	if !mentioned {
		return "", "", false
	}
	stripped = strings.TrimSpace(stripped)
	if stripped == "" {
		return "", "", false
	}
	return stripped, rootID, true
}

func (p *Platform) stripBotMention(text string) (string, bool) {
	candidates := make([]string, 0, 4)
	if p.botUsername != "" {
		candidates = append(candidates, "@"+p.botUsername)
	}
	if p.botUserID != "" {
		candidates = append(candidates, "@"+p.botUserID, "<@"+p.botUserID+">")
	}
	for _, cand := range candidates {
		if strings.Contains(text, cand) {
			return strings.TrimSpace(strings.ReplaceAll(text, cand, "")), true
		}
	}
	return text, false
}

func (p *Platform) handleWebSocketEvent(ctx context.Context, event mattermostWebSocketEvent) error {
	if event.Event != "posted" {
		return nil
	}
	post, err := parsePostedPost(event.Data)
	if err != nil {
		return err
	}
	lookupChannel := p.channelLookup
	if lookupChannel == nil {
		lookupChannel = p.getChannel
	}
	channel, err := lookupChannel(ctx, post.ChannelID)
	if err != nil {
		return fmt.Errorf("mattermost: get channel %s: %w", post.ChannelID, err)
	}
	content, rootID, ok := p.shouldHandlePost(post, channel)
	if !ok {
		return nil
	}
	lookupUser := p.userLookup
	if lookupUser == nil {
		lookupUser = p.getUser
	}
	user, err := lookupUser(ctx, post.UserID)
	if err != nil {
		slog.Debug("mattermost: resolve user failed", "user", post.UserID, "error", err)
		user = mattermostUser{ID: post.UserID, Username: post.UserID}
	}
	msg := &core.Message{
		SessionKey:        p.buildSessionKey(post.ChannelID, post.UserID, rootID),
		Platform:          "mattermost",
		MessageID:         post.ID,
		ChannelID:         post.ChannelID,
		ChannelKey:        mattermostChannelKey(channel),
		UserID:            post.UserID,
		UserName:          user.displayName(),
		ChatName:          channel.displayName(),
		Content:           content,
		ReplyCtx:          replyContext{ChannelID: post.ChannelID, RootID: rootID, PostID: post.ID},
		UserMessageTimeMs: post.CreateAt,
	}
	if p.handler != nil {
		p.handler(p, msg)
	}
	return nil
}

func parsePostedPost(data map[string]any) (mattermostPost, error) {
	var post mattermostPost
	raw, ok := data["post"]
	if !ok {
		return post, fmt.Errorf("mattermost: posted event missing post")
	}
	switch v := raw.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &post); err != nil {
			return post, fmt.Errorf("mattermost: parse post: %w", err)
		}
	case map[string]any:
		buf, _ := json.Marshal(v)
		if err := json.Unmarshal(buf, &post); err != nil {
			return post, fmt.Errorf("mattermost: parse post: %w", err)
		}
	default:
		return post, fmt.Errorf("mattermost: unsupported post payload %T", raw)
	}
	return post, nil
}

func mattermostChannelKey(ch mattermostChannel) string {
	if ch.TeamID != "" {
		return "mattermost:" + ch.TeamID + ":" + ch.ID
	}
	return "mattermost:" + ch.ID
}

func (ch mattermostChannel) displayName() string {
	if strings.TrimSpace(ch.DisplayName) != "" {
		return strings.TrimSpace(ch.DisplayName)
	}
	if strings.TrimSpace(ch.Name) != "" {
		return strings.TrimSpace(ch.Name)
	}
	return ch.ID
}

func (u mattermostUser) displayName() string {
	name := strings.TrimSpace(strings.TrimSpace(u.FirstName + " " + u.LastName))
	if name != "" {
		return name
	}
	if strings.TrimSpace(u.Nickname) != "" {
		return strings.TrimSpace(u.Nickname)
	}
	if strings.TrimSpace(u.Username) != "" {
		return strings.TrimSpace(u.Username)
	}
	return u.ID
}

func (p *Platform) Reply(ctx context.Context, rctx any, content string) error {
	return p.Send(ctx, rctx, content)
}

func (p *Platform) Send(ctx context.Context, rctx any, content string) error {
	rc, ok := rctx.(replyContext)
	if !ok {
		return fmt.Errorf("mattermost: invalid reply context type %T", rctx)
	}
	payload := map[string]any{
		"channel_id": rc.ChannelID,
		"message":    content,
	}
	if rc.RootID != "" {
		payload["root_id"] = rc.RootID
	}
	return p.postJSON(ctx, "/api/v4/posts", payload, nil)
}

func (p *Platform) ensureSelf(ctx context.Context) error {
	var user mattermostUser
	if err := p.getJSON(ctx, "/api/v4/users/me", &user); err != nil {
		return fmt.Errorf("mattermost: get current user: %w", err)
	}
	p.botUserID = user.ID
	if p.botUsername == "" {
		p.botUsername = user.Username
	}
	return nil
}

func (p *Platform) getChannel(ctx context.Context, channelID string) (mattermostChannel, error) {
	if cached, ok := p.channels.Load(channelID); ok {
		return cached.(mattermostChannel), nil
	}
	var ch mattermostChannel
	if err := p.getJSON(ctx, "/api/v4/channels/"+url.PathEscape(channelID), &ch); err != nil {
		return ch, err
	}
	p.channels.Store(channelID, ch)
	return ch, nil
}

func (p *Platform) getUser(ctx context.Context, userID string) (mattermostUser, error) {
	if cached, ok := p.users.Load(userID); ok {
		return cached.(mattermostUser), nil
	}
	var user mattermostUser
	if err := p.getJSON(ctx, "/api/v4/users/"+url.PathEscape(userID), &user); err != nil {
		return user, err
	}
	p.users.Store(userID, user)
	return user, nil
}

func (p *Platform) connectWebSocket(ctx context.Context) (*websocket.Conn, error) {
	wsURL, err := p.websocketURL()
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+p.token)
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, header)
	if err != nil {
		return nil, fmt.Errorf("mattermost: websocket dial: %w", err)
	}
	auth := map[string]any{
		"seq":    1,
		"action": "authentication_challenge",
		"data":   map[string]any{"token": p.token},
	}
	if err := conn.WriteJSON(auth); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mattermost: websocket auth: %w", err)
	}
	return conn, nil
}

func (p *Platform) websocketURL() (string, error) {
	u, err := url.Parse(p.url)
	if err != nil {
		return "", fmt.Errorf("mattermost: parse url: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("mattermost: unsupported url scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v4/websocket"
	u.RawQuery = ""
	return u.String(), nil
}

func (p *Platform) readLoop(ctx context.Context, conn *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var event mattermostWebSocketEvent
		if err := conn.ReadJSON(&event); err != nil {
			if ctx.Err() == nil {
				slog.Error("mattermost: websocket read", "error", err)
			}
			return
		}
		if err := p.handleWebSocketEvent(ctx, event); err != nil {
			slog.Warn("mattermost: handle websocket event", "error", err)
		}
	}
}

func (p *Platform) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url+path, nil)
	if err != nil {
		return err
	}
	p.setAuthHeaders(req)
	resp, err := core.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s", core.RedactToken(err.Error(), p.token))
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("mattermost: close response body", "error", err)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("GET %s status %d: %s", path, resp.StatusCode, core.RedactToken(string(body), p.token))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (p *Platform) postJSON(ctx context.Context, path string, payload any, out any) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	p.setAuthHeaders(req)
	resp, err := core.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s", core.RedactToken(err.Error(), p.token))
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("mattermost: close response body", "error", err)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("POST %s status %d: %s", path, resp.StatusCode, core.RedactToken(string(body), p.token))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (p *Platform) setAuthHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}

var _ core.Platform = (*Platform)(nil)
var _ core.ReplyContextReconstructor = (*Platform)(nil)
