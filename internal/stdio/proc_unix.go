//go:build !windows

package stdio

import (
	"os/exec"
	"syscall"
)

// group is the server and what it starts (npx starts node, uvx starts
// python): on Unix, a process group of its own.
type group struct{ cmd *exec.Cmd }

func newGroup(cmd *exec.Cmd) *group {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &group{cmd: cmd}
}

// attach runs right after Start; nothing to do on Unix.
func (g *group) attach() error { return nil }

func (g *group) kill() {
	if g.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-g.cmd.Process.Pid, syscall.SIGKILL)
	_ = g.cmd.Process.Kill()
}

func (g *group) close() {}
