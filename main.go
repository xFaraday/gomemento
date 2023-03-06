package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xFaraday/gomemento/cmdmon"
	"github.com/xFaraday/gomemento/common"
	"github.com/xFaraday/gomemento/config"
	"github.com/xFaraday/gomemento/filemon"
	"github.com/xFaraday/gomemento/frontend"
	"github.com/xFaraday/gomemento/hookmon"
	"github.com/xFaraday/gomemento/logmon"
	"github.com/xFaraday/gomemento/netmon"
	"github.com/xFaraday/gomemento/permmon"
	"github.com/xFaraday/gomemento/procmon"
	"github.com/xFaraday/gomemento/servicemon"
	"github.com/xFaraday/gomemento/usermon"
	"github.com/xFaraday/gomemento/webmon"
)

func JumpStart() {
	hookmon.EstablishDeceptions()

	filemon.RestoreController("/etc/passwd", true)
	filemon.RestoreController("/etc/shadow", true)
	filemon.RestoreController("/etc/group", true)
	filemon.RestoreController("/etc/ssh/", true)
	filemon.RestoreController("/etc/sudoers", true)
	filemon.RestoreController("/etc/crontab", true)
	filemon.RestoreController("/etc/cron.d/", true)
	filemon.RestoreController("/etc/cron.daily/", true)
	filemon.RestoreController("/etc/cron.hourly/", true)
	filemon.RestoreController("/etc/cron.monthly/", true)
	filemon.RestoreController("/etc/cron.weekly/", true)
	filemon.RestoreController("/etc/pam.conf", true)
	filemon.RestoreController("/etc/pam.d/", true)
	filemon.RestoreController("/etc/hosts", true)
	filemon.RestoreController("/etc/resolv.conf", true)

	var wg sync.WaitGroup
	wg.Add(7)
	go HeartBeatCall()
	go VerifyFilesCall()
	go ProcMonCall()
	go VerifiyRunIntegrityCall()
	go TrackUserLoginCall()
	go FilePermCheckCall()
	go NetworkSurfingCall()
	wg.Wait()
}

func usage() {
	fmt.Printf("\nGoMemento Usage -> \n")
	fmt.Printf("Options:\n")
	flag.PrintDefaults()
	println("\nExamples ->")
	println("\n\tCMD HISTORY CHECK:")
	println("\t\t./gomemento --mode=1")
	println("\n\n\tFILE BACK STUFF:")
	println("\t\t./gomemento --mode=2 --file=/etc/passwd")
	println("\t\t./gomemento --mode=2 --file=/etc/passwd --overwrite")
	println("\t\t./gomemento --mode=3")
	println("\n\n\tProcess check:")
	println("\t\t./gomemento --mode=4")
	println("\n")
}

func VerifyFilesCall() {
	ticker := time.NewTicker(2 * time.Minute)

	for _ = range ticker.C {
		filemon.VerifyFiles()
	}
}

func HeartBeatCall() {
	ticker := time.NewTicker(1 * time.Minute)

	for _ = range ticker.C {
		webmon.HeartBeat()
	}
}

func ProcMonCall() {
	ticker := time.NewTicker(2 * time.Minute)

	for _ = range ticker.C {
		procmon.ProcMon()
	}
}

func VerifiyRunIntegrityCall() {
	ticker := time.NewTicker(5 * time.Minute)

	for _ = range ticker.C {
		hookmon.VerifiyRunIntegrity()
	}
}

func TrackUserLoginCall() {
	ticker := time.NewTicker(30 * time.Second)

	for _ = range ticker.C {
		usermon.TrackUserLogin(30)
	}
}

func FilePermCheckCall() {
	ticker := time.NewTicker(1 * time.Minute)

	for _ = range ticker.C {
		permmon.FilePermCheck()
	}
}

func NetworkSurfingCall() {
	ticker := time.NewTicker(1 * time.Minute)

	for _ = range ticker.C {
		netmon.GetNetworkSurfing()
	}
}

//add command history

func main() {
	if os.Getegid() != 0 {
		println("You must be root to run this program.")
		os.Exit(1)
	}

	logmon.InitLogger()

	var (
		mode           int
		file           string
		overwrite      bool
		configlocation string
		APIKey         string
		IP             string
		UserAgent      string
		YaraRules      string
	)

	flag.StringVar(&file, "file", "", "File path for backup or verify")
	flag.IntVar(&mode, "mode", 0, "Mode to run in. 1 = cmd history check, 2 = file store, 3 = verify files, 4 = process check")
	flag.BoolVar(&overwrite, "overwrite", true, "Specify overwrite flag to overwrite existing backup")
	flag.StringVar(&configlocation, "config web location", "https://raw.githubusercontent.com/xFaraday/gomemento/master/config/config.json", "Specify the location of the config file Ex: https://webserverIP/config.json")
	flag.StringVar(&APIKey, "api", "", "Specify the API key for authenticating to kaspersky")
	flag.StringVar(&IP, "IP", "", "Specify the IP address of the server")
	flag.StringVar(&UserAgent, "ua", "", "Specify the user agent for the server")
	flag.StringVar(&YaraRules, "yara", "", "Specify the URL to download yara rules file")
	flag.Parse()

	if APIKey != "" || IP != "" || UserAgent != "" || YaraRules != "" {
		config.MakeConfig(APIKey, IP, UserAgent, YaraRules)
	}

	if len(os.Args) <= 1 {
		usage()
		os.Exit(1)
	}

	switch mode {
	case 1:
		//filemon.JumpStart()
		println("bruh no mode 1 :(")
	case 2:
		filemon.RestoreController(file, overwrite)
	case 3:
		filemon.VerifyFiles()
		//go VerifyFilesCall()
	case 4:
		procmon.ProcMon()
	case 5:
		netmon.GetNetworkSurfing()
	case 6:
		usermon.TrackUserLogin(30)
	case 7:
		hookmon.EstablishDeceptions()
	case 8:
		hookmon.VerifiyRunIntegrity()
	case 9:
		IP := config.GetSerialScripterIP()
		println(IP)
	case 10: // tampering detection for following files: /var/run/utmp, /var/log/wtmp/, /var/log/btmp
		badLoginFileSlice := logmon.FindBadLoginFile()
		for _, file := range badLoginFileSlice {
			logmon.DetectTampering(file)
		}
	case 11: // run faillog on all users on system, if the failure count exceeds 3, send alert
		logmon.ReportFailedLoginCount("all")
	case 12:
		permmon.FilePermCheck()
		permmon.UserPermIntegrityCheck()
	case 13:
		servicemon.ServiceMonitor(30)
	case 14:
		yaracompiler := common.YaraCompile("/home/xfaraday/coding/gomemento/all-yara.yar")
		if rules, err := yaracompiler.GetRules(); err != nil {
			fmt.Println(err)
		} else {
			files := common.PerformFileScan(rules, "/home/xfaraday/coding/gomemento/notes.txt")
			fmt.Println(files.Rulename)
		}
	case 1337:
		frontend.QuickInterface()
	case 31337:
		JumpStart()
	case 69:
		// get cmd hist & run cmdmon
		// attacker may install another shell & not set it as default in order to evade detection, TODO: Determine if other shells are installed but not set as default & examine those
		shell := common.GetShell()
		homeDir := common.GetHomeDir()
		homeDirSplit := strings.Split(homeDir, "/")
		// TODO: modify so we can loop through each user & examine their hist file
		username := homeDirSplit[len(homeDirSplit)-1]
		fmt.Println("[+] Shell: " + shell)
		fmt.Println("[+] Home directory: " + homeDir)
		fmt.Println("[+] Username: " + username)

		histFilePath := common.GetHistFile(username, shell, strings.Split(homeDir, "\n")[0])
		fmt.Println("[+] Hist file path: " + histFilePath)
		histFileData := common.OpenFile(histFilePath)
		for _, cmd := range histFileData {
			fmt.Println("[+] Examining " + cmd)
			cmdmon.FindDeviousCmd(cmd)
		}
	default:
		usage()
		os.Exit(1)
	}
}
