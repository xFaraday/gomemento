package main

// #include <stdlib.h>
// #include <pwd.h>
import "C"

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
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"encoding/binary"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/klauspost/compress/zstd"
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

type Passwd struct {
	Name    string
	Passwd  string
	Uid     uint32
	Gid     uint32
	Comment string
	Home    string
	Shell   string
}

func passwdC2Go(passwdC *C.struct_passwd) *Passwd {
	return &Passwd{
		Name:    C.GoString(passwdC.pw_name),
		Passwd:  C.GoString(passwdC.pw_passwd),
		Uid:     uint32(passwdC.pw_uid),
		Gid:     uint32(passwdC.pw_gid),
		Comment: C.GoString(passwdC.pw_gecos),
		Home:    C.GoString(passwdC.pw_dir),
		Shell:   C.GoString(passwdC.pw_shell),
	}
}

type record struct {
	time int32
	line [32]byte
	host [256]byte
}

type UserInfo struct {
	Name string
	Line string
	Host string
	Last string
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

type Beat struct {
	IP string
}

type incident struct {
	Name     string
	User     string
	Process  string
	RemoteIP string
	Cmd      string
}

type alert struct {
	Host     string
	Incident incident
}

type model struct {
	Tabs       []string
	TabContent []string
	activeTab  int
}

func PostToServ(jsonblob []uint8) {
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

	resp, err := http.Post("https://httpbin.org/post", "application/json", bytes.NewBuffer(jsonblob))

	if err != nil {
		panic(err)
	} else {
		println(resp.Status)
		println(resp.Request)
	}

	defer resp.Body.Close()
}

func GetIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ipaddr := localAddr.IP
	return ipaddr.String()
}

func HeartBeat() {
	m := Beat{IP: GetIP()}
	jsonStr, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	resp, err := http.Post("http://localhost:80/heartbeat", "application/json", bytes.NewBuffer(jsonStr))

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
		for _, indexstr := range f {
			var m = make(map[int]string)
			splittysplit := strings.Split(indexstr, "-:-")

			//original file path
			m[0] = splittysplit[0]
			//file store name
			m[1] = splittysplit[1]
			//backup name
			m[2] = splittysplit[2]
			//mod date
			m[3] = splittysplit[3]
			//hash
			m[4] = splittysplit[4]

			fCurrentStats := CheckFile(m[0])
			if fCurrentStats.hash != m[4] {
				CompressedBackup := "/opt/memento/" + m[2]
				//get uncompressed version
				tmpcmpfile, _ := os.Create("/tmp/" + m[1] + ".tmp")
				RevertCompressedFile, _ := os.Open(CompressedBackup)

				Decompress(RevertCompressedFile, tmpcmpfile)

				//FIGURE OUT IF TXT FILE THEN TRY TO GET DIFF
				GetDiff(m[0], tmpcmpfile.Name())

				//actions once the difference is logged
				OverWriteModifiedFile(m[0], tmpcmpfile.Name())
				println("File: " + m[0] + " has been restored to original state")
				os.Remove(tmpcmpfile.Name())
			}
		}
	}
}

/*
	Improve Compress and Decompress later:
		-> Add dictionary method for better compression
		-> Better manage encoders and decoders
*/

func Compress(in io.Reader, out io.Writer) error {
	enc, err := zstd.NewWriter(out)
	if err != nil {
		return err
	}
	//gets data from in and writes it to enc, which is out
	_, err = io.Copy(enc, in)
	if err != nil {
		enc.Close()
		return err
	}
	return enc.Close()
}

func Decompress(in io.Reader, out io.Writer) error {
	d, err := zstd.NewReader(in)
	if err != nil {
		return err
	}
	defer d.Close()

	// Copy content...
	_, err = io.Copy(out, d)
	return err
}

func BackFile(storename string, file string /*, mode int*/) {
	/*dirforbackups := "/opt/memento"
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
	*/
	dirforbackups := "/opt/memento/"
	OriginFile, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	CompressedFile, err := os.Create(dirforbackups + storename)
	if err != nil {
		panic(err)
	}

	PointData := bufio.NewReader(OriginFile)
	Compress(PointData, CompressedFile)

	defer OriginFile.Close()
	defer CompressedFile.Close()
}

func ExistsInIndex(indexfile string, file string) string {
	strlist := OpenFile(indexfile)

	for _, indexstr := range strlist {
		splittysplit := strings.Split(indexstr, "-:-")
		if splittysplit[0] == file {
			println("exact file exists in index")
			return "newback"
		}
	}
	return "new"
}

func OverWriteModifiedFile(OriginalPath string, FileBackup string) {
	//delete original
	//call modified BackFile function
	os.Remove(OriginalPath)
	BytesToCopy, _ := os.Open(FileBackup)
	NewFile, _ := os.Create(OriginalPath)
	if _, err := io.Copy(NewFile, BytesToCopy); err != nil {
		panic(err)
	}
	defer BytesToCopy.Close()
	defer NewFile.Close()
}

func OverWriteBackup(storename string, file string) {
	f := OpenFile("/opt/memento/index.safe")
	for _, indexstr := range f {
		var m = make(map[int]string)
		splittysplit := strings.Split(indexstr, "-:-")
		//original file path
		m[0] = splittysplit[0]
		//file backup name
		m[1] = splittysplit[2]
		if file == m[0] {
			os.Remove("/opt/memento/" + m[1])
			BackFile(m[1], file)
		}
	}
}

func BackDir(file string, overwrite bool) {
	fdir, _ := os.ReadDir(file)

	for _, f := range fdir {
		fpath := filepath.Join(file, f.Name())
		CreateRestorePoint(fpath, overwrite)
	}
}

func GenRandomName() string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]rune, 15)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func CreateRestorePoint(file string, overwrite bool) {
	indexfile := "/opt/memento/index.safe"
	stats := CheckFile(file)
	if stats.size != 0 {
		/*
			Index file format:
			Simple ->
			fullpath-:-filename w/extension-:-CompressedBackupName-:-LastModTime-:-hash
			Ex:
			/opt/memento/index.safe-:-index.safe-:-ADZOPRJ13SMF.zst-:-2021-01-01 00:00:00-:-9pN02HFtrhT4EGw+SdIECoj0HV8PBLY8qkZjwaKGRvo=
		*/
		//indexstr := strings.Split(file, "/")
		if stats.hash == "directory" {
			//loop through each subdir for files, because
			//the full path is stored inside of the index
			//there is no need to actually store directories
			//although with this method, the restore functions
			//would need to verify directory structure still exists
			BackDir(file, overwrite)
		} else {
			strsplit := strings.Split(file, "/")
			storename := strsplit[len(strsplit)-1]

			// /etc/passwd-:-passwd.txt-:-some date-:-hash
			backname := GenRandomName() + ".zst"
			indexstr := file + "-:-" + storename + "-:-" + backname + "-:-" + stats.time + "-:-" + string(stats.hash) + "\n"
			newindextstr := []byte(indexstr)

			if _, err := os.Stat(indexfile); os.IsNotExist(err) {
				werr := ioutil.WriteFile(indexfile, newindextstr, 0644)
				if werr != nil {
					panic(werr)
				}

				BackFile(backname, file)
			} else {
				checkresult := ExistsInIndex(indexfile, file)

				switch checkresult {
				case "newback":
					if overwrite {
						println("Overwriting previous backup of :" + file)
						OverWriteBackup(storename, file)
					} else {
						println("overwrite is set to n, exiting")
						os.Exit(0)
					}
				case "new":
					appendfile, err := os.OpenFile(indexfile, os.O_APPEND|os.O_WRONLY, 0644)
					if err != nil {
						panic(err)
					}
					println("APPENDING TO INDEX FILE")
					appendfile.WriteString(indexstr)
					defer appendfile.Close()

					println("BACKING UP FILE: " + file)

					BackFile(backname, file)
					//PostToServ(m)
				}
			}
		}
	} else {
		println("Nothing to backup :(")
	}
}

func RestoreController(file string, overwrite bool) {
	VerifiyRunIntegrity()
	//filecheckstats := CheckFile(file)
	//if filecheckstats.size != 0 {
	CreateRestorePoint(file, overwrite)
	//} else {
	//	println("Nothing to backup (ツ)_/¯")
	//}
}

func GetHistFile(username string, shellname string, homedir string) string {
	// for the future, refernce the $HISTFILE variable for each users env
	switch {
	case shellname == "bash" || shellname == "sh":
		shellpathfull := homedir + "/.bash_history"
		return shellpathfull
	case shellname == "ash":
		shellpathfull := homedir + "/.ash_history"
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

var rsize = unsafe.Sizeof(record{})

func TimeDiff(uobject *UserInfo) int {
	/*
		Time package is much more accomodating than I previously thought.
		Probably change this function to user time.after() or maybe using
		the UnixMili() function.
	*/

	dt := time.Now()
	cTime := dt.Format("15:04:06")
	lTimeUnformatted := uobject.Last
	lTime := strings.Split(lTimeUnformatted, " ")

	cTimeSplit := strings.Split(cTime, ":")
	lTimeSplit := strings.Split(lTime[1], ":")

	SecPHour := 3600

	//println("Current Time: " + cTime)
	cTimehr, _ := strconv.Atoi(cTimeSplit[0])
	cTimemin, _ := strconv.Atoi(cTimeSplit[1])
	cTimesec, _ := strconv.Atoi(cTimeSplit[2])
	//println(cTimehr * SecPHour)
	//println(cTimemin * 60)
	//println(cTimesec)
	//println("Last Time: " + lTimeUnformatted)
	lTimehr, _ := strconv.Atoi(lTimeSplit[0])
	lTimemin, _ := strconv.Atoi(lTimeSplit[1])
	lTimesec, _ := strconv.Atoi(lTimeSplit[2])

	cTimeSecTotal := (SecPHour * cTimehr) + (60 * cTimemin) + cTimesec
	lTimeSecTotal := (SecPHour * lTimehr) + (60 * lTimemin) + lTimesec

	//println(cTimeSecTotal)
	//println(lTimeSecTotal)
	diff := cTimeSecTotal - lTimeSecTotal

	return diff
}

func UserLoginEvent(uobject *UserInfo) {
	//generating alert for user login
	var inc incident = incident{
		Name:     "UserLogin",
		User:     uobject.Name,
		Process:  "", //maybe fill this later?
		RemoteIP: uobject.Host,
		Cmd:      "",
	}

	IP := GetIP()
	hostname := "host-" + strings.Split(IP, ".")[3]

	var al alert = alert{
		Host:     hostname,
		Incident: inc,
	}

	//generate json
	json, _ := json.Marshal(al)

	//send alert to webserv
	PostToServ(json)

	//shit to track
}

func TrackUserLogin(TimeInterval int) {
	//parse lastlog file or maybe perhaps the [a-z]tmp files
	//https://github.com/akamajoris/lastlogparser
	//take the file parsing out of this project, the rest of the functions are unncecessary
	f, err := os.Open("/var/log/lastlog")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	stats, err := f.Stat()
	if err != nil {
		panic(err)
	}
	size := stats.Size()

	passwds := make([]*Passwd, 0)
	C.setpwent()
	for passwdC, err := C.getpwent(); passwdC != nil && err == nil; passwdC, err = C.getpwent() {
		passwd := passwdC2Go(passwdC)
		passwds = append(passwds, passwd)
	}
	C.endpwent()

	for _, p := range passwds {
		last, line, host, err := getLogByUID(int64(p.Uid), f, size)
		if err != nil {
			panic(err)
		}

		var lastlog string
		if last == time.Unix(0, 0) {
			lastlog = "**Never logged in**"
		} else {
			lastlog = last.String()
			var info = &UserInfo{
				Name: p.Name,
				Line: line,
				Host: host,
				Last: lastlog,
			}
			//log.Printf("%#v", info)
			diff := TimeDiff(info)
			//println(diff)
			if diff < TimeInterval && diff > 0 {
				//call functions to track user
				println("USER: " + info.Name + " LOGGED IN FROM: " + info.Host)
				//backup history file
				//reccurently monitor user processes
				//check for new files
				UserLoginEvent(info)
			}
		}
	}
}

func getLogByUID(uid int64, lastLog *os.File, lastLogSize int64) (time.Time, string, string, error) {
	offset := uid * int64(rsize)
	if offset+int64(rsize) <= lastLogSize {
		_, err := lastLog.Seek(offset, 0)
		if err != nil {
			return time.Unix(0, 0), "", "", err
		}
		rawRecord := make([]byte, rsize)
		_, err = lastLog.Read(rawRecord)
		if err != nil {
			return time.Unix(0, 0), "", "", err
		}
		return bytes2time(rawRecord[:4]), string(bytes.Trim(rawRecord[4:36], "\x00")), string(bytes.Trim(rawRecord[36:], "\x00")), nil
	}
	return time.Unix(0, 0), "", "", nil
}

func bytes2time(b []byte) time.Time {
	return time.Unix(int64(binary.LittleEndian.Uint32(b)), 0)
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
	fileInfo, err := os.Stat(name)
	if err != nil {
		panic(err)
	}
	println(name)
	if fileInfo.IsDir() {

		t := fileInfo.ModTime().String()
		b := fileInfo.Size()

		i := finfo{
			name: name,
			size: b,
			time: t,
			hash: "directory",
		}

		return i
	} else {
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

func UpdateNetworkIndex(constore []string) {
	networkfile := "/opt/memento/networkprof.safe"
	stats := CheckFile(networkfile)
	if stats.size == 0 {
		file, err := os.OpenFile(networkfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		for _, str := range constore {
			file.WriteString(str)
		}
	}
	//add other logic to analyze the networkprof.safe file against constore and update it
}

func AnalyzeNetworkConnsPre(constore []string) {
	//network connections
	//localIP:localPort-:-remoteIP:remotePort-:-protocol-:-state-:-pid-:-processname-:-exactcounter-:-sameRemoteIPCounter-:-sameLocalIPCounter
	//
	for i := 0; i < len(constore); i++ {
		a := i + 1
		isplit := strings.Split(constore[i], "-:-")
		for j := a; j < len(constore); j++ {
			jsplit := strings.Split(constore[j], "-:-")
			if isplit[0] == jsplit[0] &&
				isplit[2] == jsplit[2] &&
				isplit[3] == jsplit[3] {
				num := isplit[6]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + num + "-:-" + isplit[7] + "-:-" + isplit[8] + "\n"
			} else if isplit[2] == jsplit[2] &&
				isplit[3] == jsplit[3] {
				num := isplit[7]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + num + "-:-" + isplit[8] + "\n"
			} else if isplit[0] == jsplit[0] &&
				isplit[1] == jsplit[1] {
				num := isplit[8]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				//rewrite file
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + isplit[7] + "-:-" + num + "\n"
			}
		}
	}
	//print out
	for _, str := range constore {
		print(str)
	}

	UpdateNetworkIndex(constore)
}

func GetNetworkSurfing() {
	lookupProcesses := true
	cs, err := procspy.Connections(lookupProcesses)
	if err != nil {
		panic(err)
	}
	networkfile := "/opt/memento/networkprof.safe"
	if _, err := os.Stat(networkfile); os.IsNotExist(err) {
		//create file
		file, err := os.OpenFile(networkfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
	}

	var constore []string
	for c := cs.Next(); c != nil; c = cs.Next() {
		newindexstr := c.LocalAddress.String() + "-:-" + strconv.Itoa(int(c.LocalPort)) + "-:-" + c.RemoteAddress.String() + "-:-" + strconv.Itoa(int(c.RemotePort)) + "-:-" + c.Name + "-:-" + strconv.Itoa(int(c.PID)) + "-:-" + "1" + "-:-" + "1" + "-:-" + "1" + "\n"
		constore = append(constore, newindexstr)
	}
	AnalyzeNetworkConnsPre(constore)
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

func EstablishDeceptionMechanisms() {
	//hide /opt/memento directory
	lsAlias := []byte("alias ls='ls -I memento'")
	println(string(lsAlias))

	//seed fake credentials

	//seed fake user account

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
	//EstablishPersistance() and VerifyRunIntegrity() must have a symbiotic relationship
	//because they are two halves of the same coin.  VerifyRunIntegrity() will check to
	//see if the persistence mechanism is still in place, and if not, it will re-establish
	//it.  This is to ensure that the persistence mechanisms are always in place.

	dirforbackups := "/opt/memento"
	if _, err := os.Stat(dirforbackups); err != nil {
		if os.IsNotExist(err) {
			os.Mkdir(dirforbackups, 0700)
		} else {
			panic(err)
		}
	}

}

/*
############################################################
#                                                          #
#                                                          #
#                    interface shit                        #
#                                                          #
#                                                          #
############################################################
*/

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "right", "l", "n", "tab":
			m.activeTab = min(m.activeTab+1, len(m.Tabs)-1)
			return m, nil
		case "left", "h", "p", "shift+tab":
			m.activeTab = max(m.activeTab-1, 0)
			return m, nil
		}
	}

	return m, nil
}

func tabBorderWithBottom(left, middle, right string) lipgloss.Border {
	border := lipgloss.RoundedBorder()
	border.BottomLeft = left
	border.Bottom = middle
	border.BottomRight = right
	return border
}

func (m model) View() string {
	doc := strings.Builder{}

	var renderedTabs []string

	for i, t := range m.Tabs {
		var style lipgloss.Style
		isFirst, isLast, isActive := i == 0, i == len(m.Tabs)-1, i == m.activeTab
		if isActive {
			style = activeTabStyle.Copy()
		} else {
			style = inactiveTabStyle.Copy()
		}
		border, _, _, _, _ := style.GetBorder()
		if isFirst && isActive {
			border.BottomLeft = "│"
		} else if isFirst && !isActive {
			border.BottomLeft = "├"
		} else if isLast && isActive {
			border.BottomRight = "│"
		} else if isLast && !isActive {
			border.BottomRight = "┤"
		}
		style = style.Border(border)
		renderedTabs = append(renderedTabs, style.Render(t))
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	doc.WriteString(row)
	doc.WriteString("\n")
	doc.WriteString(windowStyle.Width((lipgloss.Width(row) - windowStyle.GetHorizontalFrameSize())).Render(m.TabContent[m.activeTab]))
	return docStyle.Render(doc.String())
}

var (
	defaultWidth      = 20
	inactiveTabBorder = tabBorderWithBottom("┴", "─", "┴")
	activeTabBorder   = tabBorderWithBottom("┘", " ", "└")
	docStyle          = lipgloss.NewStyle().Padding(1, 2, 1, 2)
	highlightColor    = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	inactiveTabStyle  = lipgloss.NewStyle().Border(inactiveTabBorder, true).BorderForeground(highlightColor).Padding(0, 1)
	activeTabStyle    = inactiveTabStyle.Copy().Border(activeTabBorder, true)
	windowStyle       = lipgloss.NewStyle().BorderForeground(highlightColor).Padding(2, 0).Align(lipgloss.Center).Border(lipgloss.NormalBorder()).UnsetBorderTop()
)

func QuickInterface() {
	tabs := []string{"Status", "Cmdhist", "Procmon", "Filemon", "Netmon", "Sysmon"}
	tabContent := []string{"bruhhhh", "cmdhistbruh", "procmonbruh", "filemonbruh", "netmonbruh", "sysmonbruh"}

	m := model{Tabs: tabs, TabContent: tabContent}
	if err := tea.NewProgram(m).Start(); err != nil {
		fmt.Println("error:", err)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

/*
stuff to do:
	- Flesh out EstablishPersistence() | ✓
	-- Add systemd service with loggin set as rsyslog
	- Create VerifyFiles() function instead of VerifyFile() | ✓
	-- Also CheckFile() should capture the hash in addition to the other stats. | ✓

	-- add linux command "stat" functionality, that is when a file was modified
	-- to check if it was a good user or a bad boy or unknown boy
	-- IMPORTANT, ADD FUNCTIONALITY TO BACK ENTIRE DIRECTORIES

------------------------------------------------

	-big needed change ✓ EXCEPT THE ALERT PART
	-- okay so because the hash of each file is stored in index.safe the
	-- actual file does not needed to be stored exactly.  Some type of minimal
	-- compression would be great.  Another entry would needed to be added to
	-- index.safe to have the random generated compressed file equivalent. EX: asdf123894fsaj.compressed
	-- then if the hash stored in index.safe does not equal the hash of the check file:
	--- archive uncompressed
	--- diff is taken
	--- alert is generated
	--- file restored to original state

	The above would also fix the txt duplication bug where the txt extension is added
	to files that already have a txt extension because the stored file name is now random
	with the custom extension.  index.safe stores original file name

------------------------------------------------

	- Finish cmdhist()

	- Hella more user auditing
	-- check for user last login, if a new login occurs then we should take appropriate actions
	-- to monitor user activity
	-- Avenues for monitoring user
	--- check for processes spawned by that user
	--- check for files created and access by that user
	--- have history file saved and checked against new history file to see if anything has changed
	---- https://askubuntu.com/questions/67283/is-it-possible-to-make-writing-to-bash-history-immediate
	---- https://unix.stackexchange.com/questions/1055/how-to-make-bash-history-instantly-persistent

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

	- Add an alias to the bashrc files with ls -I /opt/gomemento so that any users
	- would not be able to see the directory.  This would be a good way to hide
	- the files we are generating.

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
	} else if mode == 6 {
		TrackUserLogin(30)
	} else if mode == 1337 {
		QuickInterface()
	}
}
