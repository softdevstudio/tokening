//go:build windows

package stdio

import "os/exec"

// On Windows the server gets no process group of its own. Servers exit when
// their stdin closes; one that doesn't is killed, and a process it started
// itself may outlive it. docs/server.md says so.
func setGroup(cmd *exec.Cmd) {}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
