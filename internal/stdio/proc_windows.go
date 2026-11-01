//go:build windows

package stdio

import (
	"errors"
	"os/exec"
	"syscall"
	"unsafe"
)

// group is the server and what it starts. On Windows npx runs through
// cmd.exe and node is its child, so the server is put in a Job Object that
// kills every process in it when it is terminated or closed.
type group struct {
	cmd *exec.Cmd
	job syscall.Handle
}

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
)

type ioCounters struct{ ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes uint64 }

type jobBasicLimit struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimit struct {
	Basic                 jobBasicLimit
	IO                    ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

func newGroup(cmd *exec.Cmd) *group { return &group{cmd: cmd} }

// attach puts the started server in a new kill-on-close job. Processes it
// starts afterwards join the job too. The few milliseconds between Start
// and attach are not covered; docs/server.md says so.
func (g *group) attach() error {
	h, _, err := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return err
	}
	g.job = syscall.Handle(h)
	var info jobExtendedLimit
	info.Basic.LimitFlags = jobObjectLimitKillOnJobClose
	if ok, _, err := procSetInformationJobObject.Call(h, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); ok == 0 {
		return err
	}
	ph, err := syscall.OpenProcess(0x0001|0x0100, false, uint32(g.cmd.Process.Pid)) // PROCESS_TERMINATE | PROCESS_SET_QUOTA
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(ph)
	if ok, _, err := procAssignProcessToJobObject.Call(h, uintptr(ph)); ok == 0 {
		return errors.Join(errors.New("assign to job"), err)
	}
	return nil
}

func (g *group) kill() {
	if g.job != 0 {
		procTerminateJobObject.Call(uintptr(g.job), 1)
	}
	if g.cmd.Process != nil {
		_ = g.cmd.Process.Kill()
	}
}

func (g *group) close() {
	if g.job != 0 {
		syscall.CloseHandle(g.job)
		g.job = 0
	}
}
