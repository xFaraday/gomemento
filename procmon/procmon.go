package procmon

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/webmon"
	"github.com/xFaraday/gomemento/config"
	"github.com/xFaraday/gomemento/common"
	"go.uber.org/zap"
	"os/exec"
	"io/ioutil"
)

/*
SYSCALL SHIT IS NOW GOING TO BE IN VER.2:

for now just scan with yara and upload to kapersky
to determine if maliscious or now.  Also run through
the command list.
*/

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
			//fmt.Println("deleted binary found")
			//println("sus dir: " + p.CWD)
			//println("sus pid: " + p.Pid)
			//println("sus bin: " + p.bin)
			zlog := zap.S().With(
				"REASON:", "deleted binary",
				"pid", p.Pid,
				"bin", p.bin,
				"cwd", p.CWD,
			)
			zlog.Warn("Suspicious process found")
			//gen alert
			var inc alertmon.Incident = alertmon.Incident{
				Name:     "Suspicious Process Found",
				User:     "",
				Process:  p.Pid, //maybe fill this later?
				RemoteIP: "",
				Cmd:      p.cmd,
			}

			IP := webmon.GetIP()
			hostname := "host-" + strings.Split(IP, ".")[3]

			var alert alertmon.Alert = alertmon.Alert{
				Host:     hostname,
				Incident: inc,
			}
			webmon.IncidentAlert(alert)
		}

		if p.CWD == "/tmp" || p.CWD == "/dev" {
			//proc running from a sus dir
			fmt.Println("proc running from a sus dir")
			println("sus dir: " + p.CWD)
			println("sus pid: " + p.Pid)
			println("sus bin: " + p.bin)
			zlog := zap.S().With(
				"REASON:", "Running from bad directory",
				"pid", p.Pid,
				"bin", p.bin,
				"cwd", p.CWD,
			)
			zlog.Warn("Suspicious process found")
			var inc alertmon.Incident = alertmon.Incident{
				Name:     "Suspicious Process Found",
				User:     "",
				Process:  p.Pid, //maybe fill this later?
				RemoteIP: "",
				Cmd:      p.cmd,
			}

			IP := webmon.GetIP()
			hostname := "host-" + strings.Split(IP, ".")[3]

			var alert alertmon.Alert = alertmon.Alert{
				Host:     hostname,
				Incident: inc,
			}
			webmon.IncidentAlert(alert)
		}

		if p.uid > 0 && p.uid < 1000 {
			//system user running a process
			fmt.Println("system user running a process")
			if patternforSystemUserBin.MatchString(p.bin) {
				fmt.Println("system user running a shell")
				zlog := zap.S().With(
					"REASON:", "System user running a shell",
					"pid", p.Pid,
					"bin", p.bin,
					"cwd", p.CWD,
				)
				zlog.Warn("Suspicious process found")
				var inc alertmon.Incident = alertmon.Incident{
					Name:     "Suspicious Process Found",
					User:     "",
					Process:  p.Pid, //maybe fill this later?
					RemoteIP: "",
					Cmd:      p.cmd,
				}

				IP := webmon.GetIP()
				hostname := "host-" + strings.Split(IP, ".")[3]

				var alert alertmon.Alert = alertmon.Alert{
					Host:     hostname,
					Incident: inc,
				}
				webmon.IncidentAlert(alert)
			}
		}

		if p.cmd == "." || p.cmd == "//" || p.cmd == " " {
			fmt.Println("binary named '.' or '//' or ' '")
			zlog := zap.S().With(
				"REASON:", "Process suspiciously named",
				"pid", p.Pid,
				"bin", p.bin,
				"cwd", p.CWD,
			)
			zlog.Warn("Suspicious process found")
			var inc alertmon.Incident = alertmon.Incident{
				Name:     "Suspicious Process Found",
				User:     "",
				Process:  p.Pid, //maybe fill this later?
				RemoteIP: "",
				Cmd:      p.cmd,
			}

			IP := webmon.GetIP()
			hostname := "host-" + strings.Split(IP, ".")[3]

			var alert alertmon.Alert = alertmon.Alert{
				Host:     hostname,
				Incident: inc,
			}
			webmon.IncidentAlert(alert)
		}
	}
}


func KillProc(pid int) {
	
	// dump memory of specified process, send to kaspersky API, kill process
	// generating dump doesn't work
	// dumpProcessMemory(pid)
	cmd := "gcore -o file.bin " + strconv.Itoa(pid)
	_, _ = exec.Command("bash", "-c", cmd).Output()
	filename := "file.bin." + strconv.Itoa(pid)
	fhandle, _ := os.Open(filename)
	
	kApiKey := config.GetKaperskyKey()
	// kaspersky api
	common.UploadFile("https://opentip.kaspersky.com/api/v1/scan/file?filename=", fhandle, kApiKey)
	//UploadFile(url string, file *os.File, apikey string)

	// kill process
	err := syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		// get process name
		processPath, _ := ioutil.ReadFile("/proc/" + string(pid) + "/cmdline")
		// send alert to web server that process couldn't be killed
		zlog := zap.S().With(
			"REASON:", "Failed to kill process",
			"pid:", pid,
			"process path:", string(processPath),
			"Error:", err.Error(),
		)
		zlog.Warn("Failed to kill specified process")
		var inc alertmon.Incident = alertmon.Incident{
			Name:	"Failed to kill specified process",
			User:	"",
			Process: string(processPath),
			RemoteIP: "",
			Cmd:	"",
		}
		IP := webmon.GetIP()
		hostname := "host-" + strings.Split(IP, ".")[3]
		var alert alertmon.Alert = alertmon.Alert{
			Host:	hostname,
			Incident: inc,
		}
		webmon.IncidentAlert(alert)
	}
}
