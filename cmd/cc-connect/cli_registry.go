package main

import (
	"fmt"
	"strings"

	ccconnect "github.com/chenhg5/cc-connect"
)

type cliCommand struct {
	Name     string
	Args     string
	Summary  string
	Aliases  []string
	Children []cliCommand
	Run      func([]string)
}

func rootFlagRegistry() []cliCommand {
	return []cliCommand{
		{Name: "--config", Args: "<path>", Summary: "Path to config file."},
		{Name: "--force", Summary: "Kill any existing instance with the same config before starting."},
		{Name: "--observe", Summary: "Observe native terminal Claude Code sessions and forward them to Slack."},
		{Name: "--observe-channel", Args: "<channel>", Summary: "Slack channel ID for terminal observations."},
		{Name: "--log-max-size", Args: "<size>", Summary: "Max bytes for the rotating log file."},
		{Name: "--log-max-backups", Args: "<count>", Summary: "Number of rotated log files to retain."},
		{Name: "--version", Summary: "Print version and exit."},
		{Name: "--tree", Summary: "Print the registered command tree."},
		{Name: "--help", Summary: "Show this help message."},
	}
}

func topLevelCommandRegistry() []cliCommand {
	return []cliCommand{
		{
			Name: "ssh", Summary: "Inspect or request a conversation execution backend.", Run: runSSH,
			Children: []cliCommand{
				{Name: "list", Summary: "List configured backends (--offline supported)."},
				{Name: "status", Summary: "Show conversation backend and auto-switch grants."},
				{Name: "test", Args: "<backend>", Summary: "Validate configuration without connecting."},
				{Name: "use", Args: "<backend>", Summary: "Request a switch; user grants still apply."},
				{Name: "worker", Summary: "Serve one remote native-agent connection over stdio."},
			},
		},
		{
			Name:    "daemon",
			Summary: "Manage cc-connect as a background service.",
			Run:     runDaemon,
			Children: []cliCommand{
				{Name: "install", Summary: "Install and start the daemon service."},
				{Name: "uninstall", Summary: "Remove the daemon service."},
				{Name: "start", Summary: "Start the daemon."},
				{Name: "stop", Summary: "Stop the daemon."},
				{Name: "restart", Summary: "Restart the daemon."},
				{Name: "status", Summary: "Show daemon status."},
				{Name: "logs", Summary: "View daemon logs."},
			},
		},
		{
			Name:    "send",
			Summary: "Send a message to an active session via internal API.",
			Run:     runSend,
		},
		{
			Name:    "cron",
			Summary: "Manage scheduled tasks.",
			Run:     runCron,
			Children: []cliCommand{
				{Name: "add", Summary: "Create a scheduled task."},
				{Name: "list", Summary: "List scheduled tasks."},
				{Name: "exec", Summary: "Trigger a scheduled task immediately.", Aliases: []string{"run", "trigger"}},
				{Name: "del", Summary: "Delete a scheduled task by ID."},
			},
		},
		{
			Name:    "sessions",
			Summary: "Browse session history.",
			Run:     runSessions,
			Children: []cliCommand{
				{Name: "list", Summary: "List all sessions."},
				{Name: "show", Args: "<id>", Summary: "Show session messages."},
			},
		},
		{
			Name:    "agent-sid",
			Summary: "Print the agent session ID for the current session.",
			Run:     runAgentSID,
		},
		{
			Name:    "relay",
			Summary: "Cross-project message relay.",
			Run:     runRelay,
			Children: []cliCommand{
				{Name: "send", Summary: "Send a message to another project and get the response."},
			},
		},
		{
			Name:    "provider",
			Summary: "Manage API providers for projects.",
			Run:     runProviderCommand,
			Children: []cliCommand{
				{Name: "add", Summary: "Add a provider."},
				{Name: "list", Summary: "List providers."},
				{Name: "remove", Summary: "Remove a provider."},
				{Name: "import", Summary: "Import providers from cc-switch."},
			},
		},
		{
			Name:    "feishu",
			Summary: "Setup Feishu/Lark bot credentials.",
			Run:     runFeishu,
			Children: []cliCommand{
				{Name: "setup", Summary: "Smart setup for Feishu/Lark bot credentials."},
				{Name: "new", Summary: "Force QR onboarding to create a new bot."},
				{Name: "bind", Summary: "Bind existing app credentials."},
			},
		},
		{
			Name:    "weixin",
			Summary: "Setup Weixin personal bot credentials.",
			Run:     runWeixin,
			Children: []cliCommand{
				{Name: "setup", Summary: "QR login or token bind setup."},
				{Name: "new", Summary: "Force QR login."},
				{Name: "bind", Summary: "Bind an existing ilink bot token."},
			},
		},
		{
			Name:    "config",
			Summary: "Manage configuration.",
			Run:     runConfig,
			Children: []cliCommand{
				{Name: "example", Summary: "Print a complete annotated config example."},
				{Name: "format", Summary: "Format the config file.", Aliases: []string{"fmt"}},
				{Name: "path", Summary: "Print the resolved config file path."},
			},
		},
		{
			Name:    "update",
			Summary: "Check for updates and upgrade the binary.",
			Run:     func([]string) { runUpdate() },
		},
		{
			Name:    "check-update",
			Summary: "Check whether a newer version is available.",
			Run:     func([]string) { checkUpdate() },
		},
		{
			Name:    "config-example",
			Summary: "Deprecated alias for config example.",
			Run:     func([]string) { fmt.Print(ccconnect.ConfigExampleTOML) },
		},
		{
			Name:    "timer",
			Summary: "Manage one-shot delayed tasks.",
			Aliases: []string{"at"},
			Run:     runTimer,
		},
		{
			Name:    "doctor",
			Summary: "Run diagnostic checks.",
			Run:     runDoctor,
			Children: []cliCommand{
				{Name: "user-isolation", Summary: "Audit run_as_user isolation for configured projects."},
			},
		},
		{
			Name:    "web",
			Summary: "Start the built-in web management console.",
			Run:     runWeb,
		},
	}
}

func lookupTopLevelCommand(name string) (cliCommand, bool) {
	for _, cmd := range topLevelCommandRegistry() {
		if cmd.Name == name {
			return cmd, true
		}
		for _, alias := range cmd.Aliases {
			if alias == name {
				return cmd, true
			}
		}
	}
	return cliCommand{}, false
}

func dispatchTopLevelCommand(name string, args []string) bool {
	cmd, ok := lookupTopLevelCommand(name)
	if !ok || cmd.Run == nil {
		return false
	}
	cmd.Run(args)
	return true
}

func renderCLITree() string {
	var b strings.Builder
	b.WriteString("cc-connect  # Bridge messaging platforms to local AI coding agents.\n")
	entries := append(rootFlagRegistry(), topLevelCommandRegistry()...)
	for i, entry := range entries {
		renderCLICommand(&b, "", entry, i == len(entries)-1)
	}
	return b.String()
}

func renderCLICommand(b *strings.Builder, prefix string, cmd cliCommand, last bool) {
	connector := "├──"
	nextPrefix := prefix + "│   "
	if last {
		connector = "└──"
		nextPrefix = prefix + "    "
	}

	label := cmd.Name
	if cmd.Args != "" {
		label += " " + cmd.Args
	}
	fmt.Fprintf(b, "%s%s %s", prefix, connector, label)
	if cmd.Summary != "" {
		fmt.Fprintf(b, "  # %s", cmd.Summary)
	}
	b.WriteByte('\n')

	for i, child := range cmd.Children {
		renderCLICommand(b, nextPrefix, child, i == len(cmd.Children)-1)
	}
}
