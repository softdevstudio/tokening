//go:build !windows

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

func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	// A killed child that nobody reaped yet is a zombie: not running.
	b, err := os.ReadFile("/proc/" + itoa(pid) + "/stat")
	if err == nil {
		for i := len(b) - 1; i > 0; i-- {
			if b[i] == ')' && i+2 < len(b) {
				return b[i+2] != 'Z'
			}
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
