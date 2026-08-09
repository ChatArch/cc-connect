# Mattermost Setup Guide

This guide connects **cc-connect** to Mattermost as a first-class chat platform.
It uses the same local-machine pattern as Slack Socket Mode: cc-connect opens an outbound WebSocket to Mattermost for realtime events and uses the Mattermost REST API v4 to reply.

> Current scope: text messages, thread-aware replies, channel @mention triggers, DM no-mention triggers, allowlist filtering, and self-message filtering. Files, voice, cards, and slash-command entry are not implemented in the first slice.

## Prerequisites

- A Mattermost server reachable from the machine running cc-connect.
- A Mattermost bot account or a dedicated user account with a personal access token.
- The bot/user must be able to access the target team, channels, and DMs.
- An AI agent configured in cc-connect, such as Claude Code, Codex, or another supported agent.

No public IP is required for the cc-connect machine because the connection is outbound:

```text
Mattermost server
  <-> WebSocket /api/v4/websocket
  <-> local cc-connect platform/mattermost
  <-> configured local agent
  <-> Mattermost REST API /api/v4/posts reply
```

## Mattermost permissions

Use a dedicated bot/user identity for cc-connect. At minimum it needs to:

- read target channels/DMs through the WebSocket event stream;
- post messages to target channels/DMs;
- be invited to any channel where you expect it to respond.

Keep the token in your private cc-connect config or secret manager. Do not commit real credentials.

## Configure cc-connect

Add a `mattermost` platform entry to the target project:

```toml
[[projects]]
name = "my-project"

[projects.agent]
type = "claudecode"

[projects.agent.options]
work_dir = "/path/to/your/project"
mode = "default"

[[projects.platforms]]
type = "mattermost"

[projects.platforms.options]
url = "https://mattermost.example.com"
token = "<mattermost-bot-token>"
bot_username = "cc-connect"          # optional; inferred from /users/me when unset
allow_from = "<allowed-user-id>"      # optional; comma-separated user IDs, empty means allow all
session_scope = "thread"              # user | channel | thread
```

### Options

| Option | Required | Meaning |
|--------|----------|---------|
| `url` | Yes | Base URL of the Mattermost server, for example `https://mattermost.example.com`. |
| `token` | Yes | Mattermost bot/user access token. `bot_token` is accepted as an alias. |
| `bot_username` | No | Username used for channel mentions such as `@cc-connect`; inferred when unset. |
| `allow_from` | No | Comma-separated Mattermost user IDs that can trigger the bot; empty or `*` allows all. |
| `session_scope` | No | `user` (default), `channel`, or `thread`. |
| `share_session_in_channel` | No | Backward-compatible boolean; maps unset `session_scope` to `channel` when true. |
| `allow_self_messages` | No | Default `false`. Keep disabled in normal use so bot replies cannot trigger loops. Enable only for controlled smoke tests that use the bot token itself to publish a test trigger. |

## Trigger behavior

Mattermost has different UX from Feishu/Lark:

- **Public/private channels**: mention the bot, for example `@cc-connect summarize this thread`.
- **Threads**: mention the bot inside the thread; replies stay in the same Mattermost thread.
- **DMs**: send a direct message to the bot without mentioning it.

The adapter ignores:

- messages sent by the bot itself;
- duplicate post IDs;
- deleted/system posts;
- senders outside `allow_from` when configured;
- channel messages that do not mention the bot.

For automated smoke tests where no separate human/test-user token is available,
you may temporarily set `allow_self_messages = true` and publish a single channel
message such as `@cc-connect /help` with the same bot token. Do not use this for
DM smoke tests, because DMs intentionally trigger without mention and self replies
could loop.

## Thread and session mapping

The adapter maps Mattermost posts to cc-connect messages like this:

```text
Mattermost WebSocket posted event
  -> platform/mattermost parses post/channel/user
  -> core.Message{Platform: "mattermost", ReplyCtx: replyContext}
  -> cc-connect engine/session
  -> Mattermost REST API /api/v4/posts reply
```

Session keys depend on `session_scope`:

| Scope | Session key shape | Behavior |
|-------|-------------------|----------|
| `user` | `mattermost:<channel_id>:<user_id>` | Separate session per user in a channel/DM. |
| `channel` | `mattermost:<channel_id>` | Shared session for all users in a channel. |
| `thread` | `mattermost:<channel_id>:t:<root_post_id>` | Separate session per Mattermost thread; falls back to user scope when no thread/root exists. |

Replies use `root_id` when present. For a top-level channel or DM trigger, the trigger post becomes the root so the bot reply is threaded under the user's message.

## Start cc-connect

```bash
cc-connect -config /path/to/config.toml
```

Expected logs include:

```text
level=INFO msg="mattermost: websocket connected"
level=INFO msg="platform started" project=my-project platform=mattermost
```

## Troubleshooting

### WebSocket connection fails

- Check that `url` is reachable from the cc-connect machine.
- Check that the token belongs to an active Mattermost user/bot.
- Confirm the server permits WebSocket connections at `/api/v4/websocket`.

### Channel messages do not trigger

- Invite the bot to the channel.
- Mention the configured username, for example `@cc-connect help`.
- Confirm `allow_from` contains the sender's Mattermost user ID, or leave it empty while testing in a trusted environment.

### DM messages do not trigger

- Open a direct message with the bot/user identity configured for cc-connect.
- Send normal text without `@`.
- Confirm `allow_from` permits the sender.

## See Also

- [Slack Setup](./slack.md)
- [Feishu Setup](./feishu.md)
- [Back to README](../README.md)
