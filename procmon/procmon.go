package procmon

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"syscall"
)

type ProcSnapshot struct {
	Procs []Proc
}

type Proc struct {
	Pid string
	cmd string
	bin string
	CWD string
	uid int
}

func GetExeLink(pid string) string {
	//exe link
	patternforDeleted := regexp.MustCompile(`(deleted)`)

	exelink, err := os.Readlink(path.Join("/proc", pid, "exe"))
	if err != nil {
		return "Kernel Process"
	}
	//return to this later to see if this actually works lmao
	if patternforDeleted.MatchString(exelink) {
		return "deleted"
	}
	return exelink
}

func GetCmdLine(pid string) string {
	//cmdline
	cmdline, err := os.ReadFile(path.Join("/proc", pid, "cmdline"))
	if err != nil {
		return "no cmdline"
	}
	if len(cmdline) == 0 {
		return "no cmdline"
	}
	return string(cmdline)
}

func GetCWD(pid string) string {
	//cwd
	cwd, err := os.Readlink(path.Join("/proc", pid, "cwd"))
	if err != nil {
		return "no cwd"
	}
	return cwd
}

func GetLoginUID(pid string) string {
	//loginuid
	loginuid, err := os.ReadFile(path.Join("/proc", pid, "loginuid"))
	if err != nil {
		return "no loginuid"
	}
	return string(loginuid)
}

func GetProcSnapShot() []Proc {
	dirgrab, err := os.ReadDir("/proc")
	if err != nil {
		panic(err)
	}

	patternforPID := regexp.MustCompile(`^[0-9]*$`)

	ptmp := Proc{
		Pid: "tmp",
		bin: "tmp",
		cmd: "tmp",
		CWD: "tmp",
		uid: 20000,
	}

	var ProcSnap = []Proc{
		ptmp,
	}

	for _, entry := range dirgrab {
		if patternforPID.MatchString(entry.Name()) {
			exelink := GetExeLink(entry.Name())
			loginuid := GetLoginUID(entry.Name())
			uid, err := strconv.Atoi(loginuid)
			if err != nil {
				panic(err)
			}
			//whitelisting system processes
			if exelink == "Kernel Process" {
				continue
			} else if uid > 2000 {
				continue
			}

			cmdline := GetCmdLine(entry.Name())
			cwdlink := GetCWD(entry.Name())

			p := Proc{
				Pid: entry.Name(),
				bin: exelink,
				cmd: cmdline,
				CWD: cwdlink,
				uid: uid,
			}
			ProcSnap = append(ProcSnap, p)
		}
	}
	return ProcSnap
}

func SysTrace(p Proc) {

	/*
		reform to include mapping and categorization of bad syscalls,
		and make it prettier.  Also needs a remidian function.
		Maybe dump memory and kill the process?
	*/

	regs2 := &syscall.PtraceRegs{}
	pid, err := strconv.Atoi(p.Pid)
	if err != nil {
		panic(err)
	}

	println(syscall.PtraceGetRegs(pid, regs2))

	var wopt syscall.WaitStatus
	regs1 := &syscall.PtraceRegs{}
	for regs1 != nil && regs1.Orig_rax != 1 {
		syscall.PtraceSyscall(pid, 0)
		syscall.Wait4(pid, &wopt, 0, nil)
		println(syscall.PtraceGetRegs(pid, regs1))
		println(regs1.Orig_rax)
		if regs1.Orig_rax == 1 {
			fmt.Printf("%v\n", regs1)
			out := make([]byte, int(regs1.Rdx))
			syscall.PtracePeekData(pid, uintptr(regs1.Rsi), out)
			println("Data: ", string(out))
		}
		syscall.PtraceSyscall(pid, 0)
		syscall.Wait4(pid, &wopt, 0, nil)
	}
	syscall.PtraceSyscall(pid, 0)
	syscall.Wait4(pid, &wopt, 0, nil)
}

func ProcMon() {
	/*
		So we are looking for indicators of compromise derived from processes.
		Checklist for things to check:
			- System/Service users running shells. (pretty sus if www-data has a bash
				shell spawned from apache)
			- /proc investigations, where exe shows (deleted) or similar path. Which
				is a tell of fileless malware.  A popular techniqure nowadays.
			- binary running from /tmp or a list of sus directories
			- binaries named '.' or '//' or ' '
			- immutable binaries/hidden binaries

		Steps to take after sus binary is found:
			- Log user information?
			- Raise alert?
		Actual flow for this, send to function InvestigateProc() which will do further analysis with the cmdhist and other
		shit prob.  Then if it passes that send to RaiseProcAlert() which will dump memory of the process, kill it, and then
		send an alert to the user.
	*/
	ProcSnap := GetProcSnapShot()
	for _, p := range ProcSnap {
		patternforDeleted := regexp.MustCompile(`deleted`)
		patternforSystemUserBin := regexp.MustCompile(`bash|sh|.php$|base64|nc|ncat|shell|^python|telnet|ruby`)

		if patternforDeleted.MatchString(p.bin) {
			fmt.Println("deleted binary found")
			println("sus dir: " + p.CWD)
			println("sus pid: " + p.Pid)
			println("sus bin: " + p.bin)
			SysTrace(p)
		}

		if p.CWD == "/tmp" || p.CWD == "/dev" {
			//proc running from a sus dir
			fmt.Println("proc running from a sus dir")
			println("sus dir: " + p.CWD)
			println("sus pid: " + p.Pid)
			println("sus bin: " + p.bin)
			SysTrace(p)
		}

		if p.uid > 0 && p.uid < 1000 {
			//system user running a process
			fmt.Println("system user running a process")
			if patternforSystemUserBin.MatchString(p.bin) {
				fmt.Println("system user running a shell")
				SysTrace(p)
			}
		}

		if p.cmd == "." || p.cmd == "//" || p.cmd == " " {
			fmt.Println("binary named '.' or '//' or ' '")
			SysTrace(p)
		}
	}
}