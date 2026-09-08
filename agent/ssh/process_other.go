//go:build !unix

package sshagent

import (
	"os/exec"
	"time"
)

func configureCommandProcess(cmd *exec.Cmd) {
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error { return killCommandProcess(cmd) }
}
func killCommandProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
