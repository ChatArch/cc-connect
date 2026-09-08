//go:build unix

package sshagent

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Each command owns a new group. Never signal a caller's or sibling's group.
func configureCommandProcess(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error { return killCommandProcess(cmd) }
	cmd.WaitDelay = time.Second
}

func killCommandProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
