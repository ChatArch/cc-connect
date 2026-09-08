package core

import "fmt"

// sshModelHint exposes the real conversation-scoped CLI, not a replacement
// execution environment. Put it in the per-turn prompt, never provider config.
func (e *Engine) sshModelHint(key string) string {
	if e.sshMode == nil || len(e.sshMode.Targets()) == 0 {
		return ""
	}
	return fmt.Sprintf("[CC Connect execution backend: %s. Inspect with `cc-connect ssh list` or `cc-connect ssh status`; validate with `cc-connect ssh test <backend>`; request `cc-connect ssh use <backend> --cwd <remote-path>` or `cc-connect ssh use local`. The injected environment supplies the conversation: do not guess or override identifiers. Only users can grant/revoke automatic switching with /ssh on/off. approval_required needs a human decision. switch_pending is NOT a completed switch: finish this turn; the next turn uses the selected backend. Never claim an existing process migrated.]\n", e.sshMode.CurrentBackend(key))
}
