package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron"
	"github.com/weaveworks/procspy"
)

type finfo struct {
	name string
	size int64
	time string
	hash string
}

type uinfo struct {
	username  string
	userid    string
	groupid   string
	homedir   string
	shellpath string
}

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

func PostToServ(m map[int]string) {
	//post files to web server

	/*
		stuff to add to this POC

		-> Add way to poll webserver first, to check if server is up and reachable
		-> Add authentication mechanism, maybe just custom header?
		-> Add way to give json and file name to server
		--> Maybe to do it like this:
			Post filename, file path, and hostname | /api/v1/store
			Post json /api/v1/store/{filename+hostname}
	*/
	jsonStr, err := json.Marshal(m)
	if err != nil {
		panic(err)
	} else {
		//println(string(jsonStr))
	}

	resp, err := http.Post("http://localhost:80", "application/json", bytes.NewBuffer(jsonStr))

	if err != nil {
		panic(err)
	} else {
		println(resp.Status)
	}

	defer resp.Body.Close()
}

func OpenFile(file string) []string {
	var s []string
	stats := CheckFile(file)
	if stats.size != 0 {
		f, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		// remember to close the file at the end of the program
		defer f.Close()

		// read the file line by line using scanner
		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			// do something with a line
			s = append(s, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			panic(err)
		}

		//print slice with contents of file
		//for _, str := range s {
		//	println(str)
		//}
	}
	return s
}

//https://gist.github.com/ndarville/3166060

func GetDiff(file, storepath string) {
	cmdout, err := exec.Command("diff", "--unified", storepath, file).CombinedOutput()
	if err != nil {
		switch err.(type) {
		case *exec.ExitError:
		default:
			panic(err)
		}
	}
	println(string(cmdout))
	//maybe parse this in the future i dunno, make it nicer to read
	//and also be able to send output to serv
}

func VerifyFiles() {
	safestats := CheckFile("/opt/memento/index.safe")
	if safestats.size != 0 {
		f := OpenFile("/opt/memento/index.safe")
		for _, str := range f {
			var m = make(map[int]string)
			splittysplit := strings.Split(str, "-:-")
			//original file path
			m[0] = splittysplit[0]
			//file store name
			m[1] = splittysplit[1]
			//file mod date
			m[2] = splittysplit[2]
			//file hash b64
			m[3] = splittysplit[3]
			fCurrentStats := CheckFile(m[0])
			if fCurrentStats.hash != m[3] {
				//file has been modified, figure out how
				//get the diffs my guy
				storepath := "/opt/memento/" + m[1] + ".txt"
				GetDiff(m[0], storepath)
				//actions once the difference is logged
				OverWriteOriginal(m[0], storepath)
				println("File: " + m[0] + " has been restored to original state")
			}
		}
	}
}

func BackFile(storename string, file string, mode int) {
	dirforbackups := "/opt/memento"
	if mode == 1 {
		backupname := dirforbackups + "/" + storename + ".txt"
		raw, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		defer raw.Close()
		outfile, err := os.Create(backupname)
		if err != nil {
			panic(err)
		}
		if _, err = io.Copy(outfile, raw); err != nil {
			panic(err)
		}
		outfile.Close()
	} else if mode == 2 {
		backupname := storename
		raw, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		defer raw.Close()
		outfile, err := os.Create(backupname)
		if err != nil {
			panic(err)
		}
		if _, err = io.Copy(outfile, raw); err != nil {
			panic(err)
		}
		outfile.Close()
	}
}

func ExistsInIndex(indexfile string, file string) string {
	strsplit := strings.Split(file, "/")
	storename := strsplit[len(strsplit)-1]
	strlist := OpenFile(indexfile)

	for _, str := range strlist {
		splittysplit := strings.Split(str, "-:-")
		if splittysplit[0] == file {
			println("exact file exists in index")
			return "newback"
		}
		if splittysplit[1] == storename {
			println("duplicate file name")
			return "filename"
		}
	}
	return "new"
}

func OverWriteOriginal(original string, storepath string) {
	//delete original
	//call modified BackFile function
	os.Remove(original)
	BackFile(original, storepath, 2)

}

func OverWriteBackup(storename string, file string) {
	f := OpenFile("/opt/memento/index.safe")
	for _, str := range f {
		var m = make(map[int]string)
		splittysplit := strings.Split(str, "-:-")
		//original file path
		m[0] = splittysplit[0]
		//file store name
		m[1] = splittysplit[1]
		if file == m[0] {
			os.Remove("/opt/memento" + "/" + m[1] + ".txt")
			BackFile(storename, file, 1)
		}
	}
}

func CreateRestorePoint(file string, overwrite string) {
	indexfile := "/opt/memento/index.safe"
	stats := CheckFile(file)
	if stats.size != 0 {
		/*
			Index file format:
			Simple ->
			fullpath:localfilenamewithoutthejson:thetimeoflastmodification
			file:storename:stats.time
			using -:- for easier splitting
		*/
		//indexstr := strings.Split(file, "/")
		strsplit := strings.Split(file, "/")
		storename := strsplit[len(strsplit)-1]

		// /etc/passwd-:-passwd.txt-:-some date-:-hash
		indexstr := file + "-:-" + storename + "-:-" + stats.time + "-:-" + string(stats.hash) + "\n"
		newindextstr := []byte(indexstr)

		if _, err := os.Stat(indexfile); os.IsNotExist(err) {
			werr := ioutil.WriteFile(indexfile, newindextstr, 0644)
			if werr != nil {
				panic(werr)
			}

			BackFile(storename, file, 1)
		} else {
			checkresult := ExistsInIndex(indexfile, file)
			//do the checks if it already exists in the indexfile
			//if result is new, then prompt user to overwrite prev
			//backup.  Also would be a good idea to pull this from params
			//else then its not a new file just has the same storename
			//so easy solution would be to gen a random number and use
			//that as the storename or append that to the original storename.
			//it might actually be a good idea in general to use random numbers
			//for all the storename completely as a layer of obfuscation.  Although
			//if permissions are set correctly on the backup directory then it is
			//slightly redundant.

			if checkresult == "newback" {
				//prompt user to overwrite

				if overwrite == "n" {
					println("overwrite is set to n, exiting")
					os.Exit(0)
				}

				if overwrite == "y" {
					println("Overwriting previous backup of :" + file)
					OverWriteBackup(storename, file)
				}

				if overwrite == "" {
					println("File already exists in index.  Overwrite?")
					println("y/n")
					var overwriteinput string
					fmt.Scanln(&overwriteinput)
					if overwriteinput == "y" {
						println("Overwriting previous backup of :" + file)
						OverWriteBackup(storename, file)
					} else {
						println("Exiting")
						os.Exit(0)
					}
				}
				//overwrite and delete previous entry, and then add new entry
				//or maybe just overwrite the original entry in indexfile
			} else if checkresult == "filename" {
				s1 := rand.NewSource(time.Now().UnixNano())
				r1 := rand.New(s1)
				storename = storename + "-" + strconv.Itoa(r1.Intn(100))

				println("BACKING UP FILE: " + file)

				BackFile(storename, file, 1)
				//PostToServ(m)
			} else if checkresult == "new" {
				appendfile, err := os.OpenFile(indexfile, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					panic(err)
				}
				println("APPENDING TO INDEX FILE")
				appendfile.WriteString(indexstr)
				defer appendfile.Close()

				println("BACKING UP FILE: " + file)

				BackFile(storename, file, 1)
				//PostToServ(m)
			}
		}
	}
}

func RestoreController(file string, overwrite string) {
	dirforbackups := "/opt/memento"
	if _, err := os.Stat(dirforbackups); err != nil {
		if os.IsNotExist(err) {
			os.Mkdir(dirforbackups, 0777)
		} else {
			panic(err)
		}
	}

	filecheckstats := CheckFile(file)
	if filecheckstats.size != 0 {
		CreateRestorePoint(file, overwrite)
	} else {
		println("Nothing to backup (ツ)_/¯")
	}
}

func GetHistFile(username string, shellname string, homedir string) string {
	// for the future, refernce the $HISTFILE variable for each users env
	switch {
	case shellname == "bash" || shellname == "sh":
		shellpathfull := homedir + "/.bash_history"
		return shellpathfull
	case shellname == "zsh":
		shellpathfull := homedir + "/.zsh_history"
		return shellpathfull
	case shellname == "fish":
		shellpathfull := homedir + "/.local/share/fish/fish_history"
		return shellpathfull
	}
	return "shell not found"
}

func GetUserInfo(mode int) uinfo {
	strlist := OpenFile("/etc/passwd")
	if mode == 1 {
		var expr = regexp.MustCompile(`sh$`)

		for _, str := range strlist {
			//Does user have a default shell?
			if expr.MatchString(str) {
				strsplit := strings.Split(str, ":")
				username := strsplit[0]
				userid := strsplit[2]
				groupid := strsplit[3]
				homedir := strsplit[5]
				shell := strsplit[6]
				shellsplit := strings.Split(shell, "/")
				shellname := shellsplit[len(shellsplit)-1]

				shellpathfull := GetHistFile(username, shellname, homedir)

				u := uinfo{
					username:  username,
					userid:    userid,
					groupid:   groupid,
					homedir:   homedir,
					shellpath: shellpathfull,
				}
				return u
			}
		}
	} else if mode == 2 {
		for _, str := range strlist {
			//Does user have a default shell?
			strsplit := strings.Split(str, ":")
			username := strsplit[0]
			userid := strsplit[2]
			groupid := strsplit[3]
			homedir := strsplit[5]
			shell := strsplit[6]
			shellsplit := strings.Split(shell, "/")
			shellname := shellsplit[len(shellsplit)-1]

			shellpathfull := GetHistFile(username, shellname, homedir)

			u := uinfo{
				username:  username,
				userid:    userid,
				groupid:   groupid,
				homedir:   homedir,
				shellpath: shellpathfull,
			}
			return u
		}
	}
	return uinfo{}

}

func CheckFile(name string) finfo {
	fileInfo, _ := os.Stat(name)
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	if err != nil {
		if os.IsNotExist(err) {
			println("file not found:", fileInfo.Name())
		}
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		panic(err)
	}
	hash := h.Sum(nil)
	Enc := base64.StdEncoding.EncodeToString(hash)

	t := fileInfo.ModTime().String()
	b := fileInfo.Size()

	i := finfo{
		name: name,
		size: b,
		time: t,
		hash: Enc,
	}
	return i
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

func FindDeviousCmd(cmd string) string {
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
	commands := []string{
		"nc",
		"nmap",
		"python3",
		"ansible-playbook",
		"curl",
		"alias", "dd"}
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
	}
	return returnstring
}

func cmdhist() {
	user := GetUserInfo(1)
	strlist := OpenFile(user.shellpath)
	for _, str := range strlist {
		cmd := FindDeviousCmd(str)
		if cmd != "no" {
			println(cmd)
		}
	}
}

func LogGuardian() {
	/*
		Parse logs for maliscious activity, also check for log tampering.
		/var/log/wtmp
		/var/log/lastlog
		/var/log/btmp
		/var/log/utmp
		/var/log/*

		Check logs overwritten by Zero Bytes. Obvious sign of log tampering.
		date time modificiation date of all logs are identical.
		Null Erased logins.

		probably should also check file permissions for all the logs

		Method to read log files:
		https://stackoverflow.com/questions/17863821/how-to-read-last-lines-from-a-big-file-with-go-every-10-secs
	*/

	/*
		dirgrab, err := os.ReadDir("/var/log")
		if err != nil {
			panic(err)
		}
		for _, dir := range dirgrab {
			switch dir.Name() {
			case "apache2":
				//pattern for scans
				PatternforScannerz := regexp.MustCompile(`[nN]map|masscan|curl|[gG]o-http-client`)
				PatternforShellshock := regexp.MustCompile(``)
				PatternforWebshell := regexp.MustCompile(``)

				//develop regex from requests lists developed from old apache server logs

					something for:
					cgi-bin
					cmd=
					shell
					jndi for log4j

					CONNECT request

					start of tls handshake
					\x16\x03\x01


			case "auth.log":

					monitor accepted publickeys for sshd
					and password auth

					bruteforce attempts? eh just install fail2ban


			}
		}
	*/
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

func GetNetworkSurfing() {
	lookupProcesses := true
	cs, err := procspy.Connections(lookupProcesses)
	if err != nil {
		panic(err)
	}

	fmt.Printf("TCP Connections:\n")
	for c := cs.Next(); c != nil; c = cs.Next() {
		fmt.Printf(" - %v\n", c)
	}
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
		}

		if p.CWD == "/tmp" || p.CWD == "/dev" {
			//proc running from a sus dir
			fmt.Println("proc running from a sus dir")
		}

		if p.uid > 0 && p.uid < 1000 {
			//system user running a process
			fmt.Println("system user running a process")
			if patternforSystemUserBin.MatchString(p.bin) {
				fmt.Println("system user running a shell")
			}
		}

		if p.cmd == "." || p.cmd == "//" || p.cmd == " " {
			fmt.Println("binary named '.' or '//' or ' '")
		}
	}
}

func EstablishPersistence() {
	/*
		Establish cronjob for now, maybe look into getting some type of systemd service?
	*/
	c := cron.New()
	c.AddFunc("@every 2m", cmdhist)
	c.AddFunc("@every 2m", VerifyFiles)
	c.Start()
}

func VerifiyRunIntegrity() {
	/*
		Function run every ? minutes to verify the integrity of the EDR solution.
		So are file permissions correct??
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
	println("\t\t./gomemento --mode=2 --file=/etc/passwd --overwrite=y")
	println("\t\t./gomemento --mode=3")
	println("\n\n\tProcess check:")
	println("\t\t./gomemento --mode=4")
	println("\n")
}

/*
stuff to do:
	- Flesh out EstablishPersistence() | ✓
	-- Add systemd service with loggin set as rsyslog
	- Create VerifyFiles() function instead of VerifyFile() | ✓
	-- Also CheckFile() should capture the hash in addition to the other stats. | ✓

	- Fix bug when storing a txt file. Stores it in index.safe as "example.txt" but
	-- but stores it as "example.txt.txt" in /opt/memento.

	- Finish cmdhist()

	- Add process monitoring | ✓ (sorta)
	-- Investigate /proc for "interesting" artifacts
	-- Interrogate new processes, especially subprocesses that contain network capabilities
	-- maybe layer this ability with cmdhist()
	- Add Logging in /opt/memento/logs/

	- Network mapper
	-- Based on network connections over time, create a network profile for the host
	-- Once the network profile is created and has a solid baseline, anomalies can
	-- be detected.  The anomalies under extra scrutiny can be analyzed for easy
	-- detection of maliscious activity.

	- Add support for limited yara rules for detecting general things like use
	-- of cobolt strike or exploit kits.  A lot of yara rules seems to be focused
	-- on specific malware or specific threat actors. Better to focus for general
	-- because we dont have threat data on threat actors in CCDC.

	- All these things once developed can be aggregated by the scripting engine.
	-- One end goal beyond have a fun interface with a bunch of datapoints organized
	-- by host is to manufacture CTI in real time.  Blacklist users, block IPs, etc.
	-- Even categorize TTPs.

	- Would be nice section
	-- Figure out a nice way to take advantage of concurrency. Maybe have a
	-- task scheduler of sorts that takes all possible tasks and runs them
	-- with go routines
*/

func main() {
	if os.Getegid() != 0 {
		println("You must be root to run this program.")
		os.Exit(1)
	}

	var (
		mode      int
		file      string
		overwrite string
	)

	flag.StringVar(&file, "file", "", "File path for backup or verify")
	flag.IntVar(&mode, "mode", 0, "Mode to run in. 1 = cmd history check, 2 = file store, 3 = verify files, 4 = process check")
	flag.StringVar(&overwrite, "overwrite", "", "Overwrite backup; perform new backup [y/n]")
	flag.Parse()

	if len(os.Args) <= 1 {
		usage()
		os.Exit(1)
	}

	if mode != 1 && mode != 2 && mode != 3 && mode != 4 && mode != 5 {
		usage()
		os.Exit(1)
	}

	if mode == 1 {
		cmdhist()
	} else if mode == 2 {
		if len(file) == 0 {
			usage()
			os.Exit(1)
		}
		RestoreController(file, overwrite)
	} else if mode == 3 {
		VerifyFiles()
	} else if mode == 4 {
		ProcMon()
	} else if mode == 5 {
		GetNetworkSurfing()
	}
}
