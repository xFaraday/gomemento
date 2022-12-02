package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/robfig/cron"
	"github.com/xFaraday/gomemento/cmdmon"
	"github.com/xFaraday/gomemento/common"
	"github.com/xFaraday/gomemento/filemon"
	"github.com/xFaraday/gomemento/frontend"
	"github.com/xFaraday/gomemento/hookmon"
	"github.com/xFaraday/gomemento/logmon"
	"github.com/xFaraday/gomemento/netmon"
	"github.com/xFaraday/gomemento/procmon"
	"github.com/xFaraday/gomemento/usermon"
)

func cmdhist() {
	user := usermon.GetUserInfo(1)
	for _, u := range user {
		histfile := common.GetHistFile(u.Username, u.ShellVar, u.Homedir)
		strlist := common.OpenFile(histfile)
		for _, str := range strlist {
			cmd := cmdmon.FindDeviousCmd(str)
			if cmd != "no" {
				println(cmd)
			}
		}
	}
}

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
	c.AddFunc("@every 2m", cmdhist)
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
		mode      int
		file      string
		overwrite bool
	)

	flag.StringVar(&file, "file", "", "File path for backup or verify")
	flag.IntVar(&mode, "mode", 0, "Mode to run in. 1 = cmd history check, 2 = file store, 3 = verify files, 4 = process check")
	flag.BoolVar(&overwrite, "overwrite", true, "Specify overwrite flag to overwrite existing backup")
	flag.Parse()

	if len(os.Args) <= 1 {
		usage()
		os.Exit(1)
	}

	switch mode {
	case 1:
		cmdhist()
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
	case 8:
		hookmon.VerifiyRunIntegrity()
	case 1337:
		frontend.QuickInterface()
	case 31337:
		ccdc()
	default:
		usage()
		os.Exit(1)
	}
}
