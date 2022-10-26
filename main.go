package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/xFaraday/gomemento/filemon"
	"github.com/xFaraday/gomemento/frontend"
	"github.com/xFaraday/gomemento/netmon"
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

	if mode != 1 &&
		mode != 2 &&
		mode != 3 &&
		mode != 4 &&
		mode != 5 &&
		mode != 6 &&
		mode != 1337 {
		usage()
		os.Exit(1)
	}

	if mode == 1 {
		cmdmon.cmdhist()
	} else if mode == 2 {
		if len(file) == 0 {
			usage()
			os.Exit(1)
		}
		filemon.RestoreController(file, overwrite)
	} else if mode == 3 {
		filemon.VerifyFiles()
	} else if mode == 4 {
		procmon.ProcMon()
	} else if mode == 5 {
		netmon.GetNetworkSurfing()
	} else if mode == 6 {
		usermon.TrackUserLogin(30)
	} else if mode == 1337 {
		frontend.QuickInterface()
	}
}
