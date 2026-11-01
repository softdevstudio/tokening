//go:build !windows

package stdio

import (
	"os/exec"
	"syscall"
)

// setGroup starts the server in its own process group, so stopping it also
// stops what it started (npx starts node, uvx starts python).
func setGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
