//go:build windows

package stdio

import (
	"os"
	"os/exec"
	"syscall"
)

func fakeChild() int {
	c := exec.Command(os.Args[0], "-test.run=^TestFakeServer$", "--", "fake", "hang")
	c.Start()
	return c.Process.Pid
}

// alive reports whether the process still runs (exit code STILL_ACTIVE).
func alive(pid int) bool {
	h, err := syscall.OpenProcess(0x1000, false, uint32(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if syscall.GetExitCodeProcess(h, &code) != nil {
		return false
	}
	return code == 259
}
