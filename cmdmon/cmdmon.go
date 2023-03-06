package cmdmon

import (
	"strings"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/webmon"
	"go.uber.org/zap"
)

type SuspiciousCmd struct {
	RanCommand     string
	MatchedKeyword string
}

// search command for common obfuscation/evasion techniques
func WindowsFindDeviousCmdParams(cmd string) SuspiciousCmd {
	suspiciousCLParams := []string{
		//https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
		//https://arxiv.org/pdf/1804.04177v2.pdf
		"^",
		"=",
		"%",
		"!",
		"[",
		"(",
		";",
		"http",
		"https",
		"echo",
		"cmd.exe /c",
		"cmd /c",
		"write-host",
		"bypass",
		"exec",
		"create",
		"dumpcreds",
		"downloadstring",
		"invoke-command",
		"getstring",
		"webclient",
		"nop",
		"hidden",
		"encodedcommand",
		"-en",
		"-enc",
		"-enco",
		"downloadfile",
		"iex",
		"replace",
		"wscript.shell",
		"windowstyle",
		"comobject",
		"reg",
		"autorun",
		"psexec",
		"lsadump",
		"wmic",
		"schtask",
		"net",
		"fsutil",
		"dsquery",
		"netsh",
		"del",
		"taskkill",
		"uploadfile",
		"invoke-wmi",
		"enumnetworkdrives",
		"procdump",
		"get-wmiobject",
		"sc",
		"cimv2",
		"-c",
		"certutil",
		"new-itemproperty",
		"invoke-expression",
		"invoke-obfuscation",
		"nop",
		"invoke-webrequest",
		"reflection",
	}

	if len(cmd) != 0 {
		for _, knownParam := range suspiciousCLParams {
			lowerCaseKnownParam := strings.ToLower(knownParam)
			lowerCaseCmd := strings.ToLower(cmd)
			if strings.Contains(lowerCaseCmd, lowerCaseKnownParam) {
				//fmt.Println("[+] Potentially malicious command found:" + cmd)
				//fmt.Println("[+] Keyword match:" + lowerCaseKnownParam
				zlog := zap.S().With(
					"REASON:", "Suspicious Command Ran",
					"Command Ran:", lowerCaseCmd,
					"Matched Keyword:", lowerCaseKnownParam,
				)
				zlog.Warn("Suspicious Command Ran")
				//gen alert
				var inc alertmon.Incident = alertmon.Incident{
					Name:     "Suspicious Command Ran",
					User:     "",
					Process:  "",
					RemoteIP: "",
					Cmd:      lowerCaseCmd,
				}

				IP := webmon.GetIP()
				hostname := "host-" + strings.Split(IP, ".")[3]

				var alert alertmon.Alert = alertmon.Alert{
					Host:     hostname,
					Incident: inc,
				}
				webmon.IncidentAlert(alert)
				return SuspiciousCmd{cmd, lowerCaseKnownParam}
			}
		}
	}
	return SuspiciousCmd{"", ""}
}

func FindDeviousCmd(cmd string) SuspiciousCmd {
	/*
		Load a predefined list of devious commands or *interesting* commands.
		->maybe load the lists from repuatable sources?

		Load the string slice of user bash_history files and compare each line
		for the commands of interest.  Break down each line with slice into words
		and then use that to compare each word.  Treat more suspicious commands using
		this method.  Commands like nc, netcat, nmap, telnet, etc.
		Another interesting case is a ssh -L command.  This is a port forwarding command.
		This is a devious command.  And an easy way to detect it is using for the ssh match
		and the -L match.

		Maybe make this a parrallel operation? Check every history file in parrallel.
		Might be resource intensive.
		Return the number of the line that contain the devious command and repeat.
	*/
	cmds := []string{
		"nc",
		"netcat",
		"nmap",
		"python3",
		"ansible-playbook",
		"curl",
		"wget",
		"alias",
		"dd",
		"unset",
		"linpeas",
		"getfacl",
		"setfacl",
		"linenum",
		"sudo -l",
		"find / -perm -u=s -type f 2>/dev/null",
		"find / -name authorized_keys 2>/dev/null",
		"find / -name id_rsa 2>/dev/null",
		"dpkg -l",
		"pspy", //tool used to find cronjobs: https://github.com/DominicBreuker/psp
		"find / -writable -type f 2>/dev/null",
		"find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \\;",
		"find / -uid 0 -perm -4000 -type f 2>/dev/null",
		"find / -perm -u=s -type f 2>/dev/null",
		"strings /dev/mem -n10 | grep -i PASS",
		"history",
		"ls -la /etc/cron",
		"lsblk",
		"uname",
		"id",
		"find /",
		"/proc/",
		"screen -v",
		"tcpdump",
		"ldd",
		"/dev/tcp",
		"lxc",
		"linprivchecker",
		"awk 'BEGIN {system(\"/bin/bash\")}'",
		"/bin/bash",
		"/bin/sh",
		"perl",
		"vim -c",
		"vim --command",
		"ab -v", //can be used to download file
		"ab -p", //can be used to upload file
		"agetty",
		"alpine -f",
		"ar",
		"aria2c",
		"arj",
		"arp -v -f", //can be used to read a file
		"as",
		"ascii-xfr",
		"ascii85",
		"ash",
		"aspell",
		"at",
		"atobm",
		"awk 'BEGIN {system(\"/bin/sh\")}'",
		"base64",
		"base32",
		"base58",
		"basenc",
		"basez",
		"bash -c",
		"bpftrace",
		"bridge",
		"bundle",
		"busybox",
		"busctl",
		"bzip2 -c",
		"c89",
		"c99",
		"cancel -u",
		"capsh",
		"cdist shell",
		"certbot /bin/sh",
		"check_by_ssh -o",
		"check_cups",
		"check_log",
		"check_memory",
		"check_raid",
		"time /bin/sh",
		"timedatectl list-timezones",
		"tshark -X",
		"vi -c",
		"vimdiff -c",
		"wall --nobanner", //wall --nobanner <file location>
		"watch -x sh",
		"watch exec",
		"whois -h",
		"wc --files",
		"xxd",
		"zathura",
		"zypper x",
		"/etc/lsb-release",
		"mysqldump",
	}
	if len(cmd) != 0 {
		lowerCaseCmd := strings.ToLower(cmd)
		for _, knownCmd := range cmds {
			lowerCaseKnownCmd := strings.ToLower(knownCmd)
			if strings.Contains(lowerCaseCmd, lowerCaseKnownCmd) {
				//fmt.Println("[!] Potential malicious command found. Ran command: " + lowerCaseCmd)
				//fmt.Println("[!] Matched known malicious command: " + lowerCaseKnownCmd)
				zlog := zap.S().With(
					"REASON:", "Suspicious Command Ran",
					"Command Ran:", lowerCaseCmd,
					"Matched Keyword:", lowerCaseKnownCmd,
				)
				zlog.Warn("Suspicious Command Ran")
				//gen alert
				var inc alertmon.Incident = alertmon.Incident{
					Name:     "Suspicious Command Ran",
					User:     "",
					Process:  "",
					RemoteIP: "",
					Cmd:      lowerCaseCmd,
				}

				IP := webmon.GetIP()
				hostname := "host-" + strings.Split(IP, ".")[3]

				var alert alertmon.Alert = alertmon.Alert{
					Host:     hostname,
					Incident: inc,
				}
				if err := webmon.IncidentAlert(alert); err != nil {
					zap.S().Error(err)
				}

				return SuspiciousCmd{cmd, lowerCaseKnownCmd}
			}
		}
	}
	return SuspiciousCmd{"", ""}
	/*
		returnstring := ""
		pcmd := strings.Fields(cmd)
		for _, s := range commands {
			if len(pcmd) != 0 {

				if pcmd[0] == s {
					println("Match: " + s)
					println("Full: " + cmd)
					returnstring = cmd
				} else {
					returnstring = "no"
				}
			} else {
				returnstring = "no"
			}
		return returnstring*/
}
