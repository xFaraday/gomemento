package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/robfig/cron"
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
	"github.com/xFaraday/gomemento/usermon"
)

func ArtifactHunt() {
	/*
		to be run after FindDeviousCmd returns positive.
		scans file system for interesting artifacts. Like a ssh key being added to
		AuthorizedKeys file.
		Analyze Cron as well

		One idea might be taking the process id of the maliscious cmd and then listing
		open files.  Analyze the open files for interesting artifacts.


	*/

}

func ccdc() {
	hookmon.EstablishDeceptions()

	filemon.JumpStart()

	EstablishPersistence()
}

func EstablishPersistence() {
	/*
		Establish cronjob for now, maybe look into getting some type of systemd service?
	*/
	c := cron.New()
	c.AddFunc("@every 2m", filemon.VerifyFiles)
	c.Start()
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
	)

	flag.StringVar(&file, "file", "", "File path for backup or verify")
	flag.IntVar(&mode, "mode", 0, "Mode to run in. 1 = cmd history check, 2 = file store, 3 = verify files, 4 = process check")
	flag.BoolVar(&overwrite, "overwrite", true, "Specify overwrite flag to overwrite existing backup")
	flag.StringVar(&configlocation, "config web location", "https://raw.githubusercontent.com/xFaraday/gomemento/master/config/config.json", "Specify the location of the config file Ex: https://webserverIP/config.json")
	flag.Parse()

	if len(os.Args) <= 1 {
		usage()
		os.Exit(1)
	}

	switch mode {
	case 1:
		filemon.JumpStart()
	case 2:
		filemon.RestoreController(file, overwrite)
	case 3:
		filemon.VerifyFiles()
	case 4:
		procmon.ProcMon()
	case 5:
		netmon.GetNetworkSurfing()
	case 6:
		usermon.TrackUserLogin(30)
	case 7:
		hookmon.EstablishDeceptions()
		EstablishPersistence()
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
	case 1337:
		frontend.QuickInterface()
	case 31337:
		ccdc()
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
