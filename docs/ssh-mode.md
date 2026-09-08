# SSH execution mode / SSH 执行模式

CC Connect can run its configured native agent on an explicitly configured SSH target. The messaging connection, conversation history and permission store stay on the gateway. The native agent process, terminal commands and native file tools run on the target.

**This is not a prompt-only environment switch.** The gateway starts `cc-connect ssh worker` through OpenSSH and exchanges bounded JSON-RPC frames over stdio. Each conversation/backend/directory has an independent adapter. Returning to a backend resumes its own native session ID, never an ID from another host.

## 配置

在网关的 `config.toml` 中添加目标（示例全部为占位值）：

```toml
[ssh]
# 可选：显式导入 YAML registry；省略时读取 <data_dir>/ssh/targets.yaml。
# registry = "/path/to/targets.yaml"

[[ssh.targets]]
alias = "dev"
host = "dev.example.com"
user = "agent"
port = 22
identity_file = "~/.ssh/agent_key"
known_hosts = "~/.ssh/known_hosts"
host_key_policy = "strict"
cwd = "~/workspace"
worker_command = "~/.local/bin/cc-connect"

[ssh.targets.agent_options]
# 这些值属于远端，不从网关 agent.options 复制。
# cmd = "/path/on/target/to/native-agent"
# model = "model-name"
# mode = "default"
```

The target needs a compatible build of CC Connect, the project's native agent CLI, and its own completed provider login. Installing this feature does **not** install software, copy keys, copy provider tokens, or log in on other machines. Use a Linux/macOS target with OpenSSH and a POSIX shell. Windows gateway builds remain supported; native Windows remote-worker execution is not a claimed target.

Registry alternatives:

```yaml
targets:
  dev:
    host: dev.example.com
    user: agent
    cwd: ~/workspace
    worker_command: ~/.local/bin/cc-connect
```

The YAML reader also accepts a list of targets containing `alias`, or a `ssh.targets` wrapper. It does not implicitly scan OpenSSH config or another product's home. Inline/registry duplicate aliases and malformed state fail closed. Import deliberately and inspect before use. SSH runs with a clean configuration (`-F /dev/null`): `host` must be a DNS name or address, not an alias defined only in `~/.ssh/config`. Configure user, port, identity and known-hosts paths explicitly; proxy commands, environment/agent forwarding and connection multiplexing are disabled.

## 聊天控制面

```text
/ssh list
/ssh status
/ssh test dev
/ssh use dev --cwd ~/workspace
/ssh on dev
/ssh off all
/ssh use local
```

- `list/status` 展示配置、当前目标和自动切换权限；不输出私钥路径或凭据。
- `test` **仅验证配置**，不是网络连通性、远端安装或真实模型验证。
- `use` 是用户显式切换，遵守现有管理员命令权限；忙碌中需先 `/stop`，不会中断尚未结束的 Agent 来冒充迁移。
- `on/off` 只修改当前会话的**模型自动切换权限**，可指定目标或 `all`。
- **`off` 不会退回 local**；禁用当前目标的自动切换后，当前目标仍可继续执行。退回请用 `use local`。
- 不同平台、聊天、原生 thread 和 project 的绑定互不影响。状态保存在 `<data_dir>/ssh/state/<project-hash>.json`，权限与绑定分别存储。

普通消息进入当前 backend 的 native Agent。远端 `/shell`、`/diff` 和 `/dir` 使用远端执行通道，不落到网关本地。`/show` 当前明确不支持，可改用远端 `/shell` 查看文件。依赖网关原生文件/配置/凭据的未支持管理命令在 SSH 会话中明确拒绝；需要时显式切回 local。此版本不把网关全部插件和管理 API 隧穿到目标。

## Agent / CLI 接口

```bash
cc-connect ssh list
cc-connect ssh status
cc-connect ssh test dev
cc-connect ssh use dev --cwd /workspace/project
cc-connect ssh use local

# 无运行中 daemon 时，仅检查自有配置：
cc-connect ssh list --offline --config /path/to/config.toml
cc-connect ssh test dev --offline --config /path/to/config.toml
```

Online scope defaults to `CC_PROJECT`, `CC_SESSION_KEY` and `CC_DATA_DIR`. Do not guess conversation identifiers. Explicit project/session options cannot override an already supplied active scope. The gateway's owner-only Unix API accepts `POST /ssh` with `project`, `session_key`, `action`, `backend`, `cwd`. It is a same-OS-user control surface, **not** a security sandbox against arbitrary code running as the gateway owner.

Model CLI/API deliberately has **no `on/off`**. When a target lacks a user grant, it returns `approval_required` and provides a human `/ssh use …` approval action in the originating conversation. A granted request from an active native process returns `switch_pending`: finish the current turn; subsequent user input goes to the selected backend. One model turn cannot migrate its existing process to another host. Neither pending nor approval-required is reported as completed execution.

A remote worker exposes a private, short-lived Unix `/ssh` proxy for native adapters that implement session-environment injection. Its narrowly scoped requests travel back over the same stdio connection to the originating gateway conversation. No general gateway socket, arbitrary project selection or permission-grant endpoint is forwarded. Provider credentials remain on their respective hosts.

Output is JSON. Exit codes: `0` completed inspection/switch; `2` approval required or switch pending; `1` malformed arguments, invalid config, unavailable control channel, or execution failure. `worker` is an internal stdio entrypoint, not a daemon.

## 安全与生命周期

- SSH key-only (`BatchMode`), strict host keys by default; `accept-new` is explicit trust-on-first-use. No insecure `no` policy.
- No agent forwarding or environment forwarding. Target options are explicitly validated; the gateway's provider/agent environment is not copied.
- Arguments and target executable paths are validated/quoted; directories expand on the machine that owns them.
- NDJSON frame and captured shell output sizes are bounded. Attachments travel as bytes, not inaccessible gateway file paths.
- EOF, cancellation and engine stop close only owned sessions/processes and the worker's private control socket. Native adapters remain responsible for their own process lifecycles.
- An SSH failure never silently falls back to local execution. A successful configuration test does not imply a remote login or model smoke passed.

## 验证边界

Deterministic tests exercise the real worker protocol with a subprocess fixture, command execution in a controlled directory, event/permission/attachment round trips, cancellation, persistence, and multi-action conversation routing. Fixture model output is not a real provider response. Deployment acceptance additionally requires testing a separately provisioned target and a real native agent, with explicit authorization to access that target.
