package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type finfo struct {
	name string
	size int64
	time string
}

type uinfo struct {
	username  string
	userid    string
	groupid   string
	homedir   string
	shellpath string
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

func GetDiff(strlist []string, m map[int]string) []string {
	lenofcurrent := len(strlist)
	lenofbackup := len(m)
	offset := 0
	for i := 0; i < lenofcurrent; i++ {
		if i > lenofbackup {
			//println(offset)
		}
	}
}

func VerifyFile(file string, m map[int]string) {
	//file = new version
	//m = backup version
	strlist := OpenFile(file)
	println(len(strlist))
	println(len(m))
	if len(strlist) != len(m) {
		//line numbers added or subtracted
		if len(strlist) > len(m) {
			diff := len(strlist) - len(m)
			println("lines added:", strconv.Itoa(diff))
		}
		if len(m) > len(strlist) {
			diff := len(m) - len(strlist)
			println("lines removed:", strconv.Itoa(diff))
		}
	} else {
		//line numbers are the same, nice
	}
}

func BackFile(name string, file string, m map[int]string) {
	dirforbackups := "/opt/memento"
	strsplit := strings.Split(file, "/")
	storename := strsplit[len(strsplit)-1]
	backupname := dirforbackups + "/" + storename + ".txt"

	for line, lineval := range m {
		i := strconv.Itoa(line)
		newline := i + "-:-" + lineval + "\n"
		newlinebyte := []byte(newline)
		if _, err := os.Stat(backupname); os.IsNotExist(err) {
			werr := ioutil.WriteFile(backupname, newlinebyte, 0644)
			if werr != nil {
				panic(werr)
			}
		} else {
			appendfile, err := os.OpenFile(backupname, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				panic(err)
			}
			appendfile.WriteString(newline)
			defer appendfile.Close()
		}
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

		indexstr := file + "-:-" + storename + "-:-" + stats.time + "\n"
		newindextstr := []byte(indexstr)

		if _, err := os.Stat(indexfile); os.IsNotExist(err) {
			werr := ioutil.WriteFile(indexfile, newindextstr, 0644)
			if werr != nil {
				panic(werr)
			}
			strlist := OpenFile(file)

			var m = make(map[int]string)

			i := 0
			for _, str := range strlist {
				i++
				m[i] = str
			}
			println("BACKING UP FILE: " + file)

			BackFile(storename, file, m)
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
				}

				if overwrite == "" {
					println("File already exists in index.  Overwrite?")
					println("y/n")
					var overwriteinput string
					fmt.Scanln(&overwriteinput)
					if overwriteinput == "y" {
						println("Overwriting previous backup of :" + file)
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
				println(storename)

				strlist := OpenFile(file)

				var m = make(map[int]string)

				i := 0
				for _, str := range strlist {
					i++
					m[i] = str
				}
				println("BACKING UP FILE: " + file)

				BackFile(storename, file, m)
				//PostToServ(m)
			} else if checkresult == "new" {
				appendfile, err := os.OpenFile(indexfile, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					panic(err)
				}
				println("APPENDING TO INDEX FILE")
				appendfile.WriteString(indexstr)
				defer appendfile.Close()

				strlist := OpenFile(file)

				var m = make(map[int]string)

				i := 0
				for _, str := range strlist {
					i++
					m[i] = str
				}
				println("BACKING UP FILE: " + file)

				BackFile(storename, file, m)
				//PostToServ(m)
			}
		}
	}
}

func RestoreController(i int, file string, overwrite string) {
	indexfile := "/opt/memento/index.safe"
	dirforbackups := "/opt/memento"
	if _, err := os.Stat(dirforbackups); err != nil {
		if os.IsNotExist(err) {
			os.Mkdir(dirforbackups, 0777)
		} else {
			panic(err)
		}
	}

	switch i {
	case 1:
		CreateRestorePoint(file, overwrite)
	case 2:
		//index file logic
		stats := CheckFile(file)
		println(stats.time)
		strlist := OpenFile(indexfile)

		for _, str := range strlist {
			strpre := str
			tex := strings.Split(strpre, "-:-")
			if tex[0] == file {
				println("file found in index file: " + tex[0])
				if tex[2] != stats.time {
					println("file:" + tex[0] + " MODIFIED")
					backupfile := dirforbackups + "/" + tex[1] + ".txt"
					println(backupfile)
					statsback := CheckFile(backupfile)
					if statsback.size != 0 {
						/*
							Gets contents of the file's present location. tex[0].
							Transfer the contents into a [int]string map called m.
							Pass this to VerifyFile.  VerifyFile compares the new
							interface with the saved json file at /opt/memento.
						*/
						packlist := OpenFile(backupfile)
						var m = make(map[int]string)

						i := 0
						for _, pack := range packlist {
							m[i] = pack
							i++
						}
						VerifyFile(file, m)
					}
				} else {
					println("file:" + tex[0] + " NOT MODIFIED")
					println("\n\n" + "NO ACTION TAKEN")
				}
			}
		}

	case 3:
		strlist := OpenFile(file)
		for _, str := range strlist {
			//do concurrent shit
			println(str)
		}
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

func GetUserInfo() uinfo {
	var expr = regexp.MustCompile(`sh$`)

	strlist := OpenFile("/etc/passwd")
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
	return uinfo{}
}

func CheckFile(name string) finfo {
	fileInfo, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			println("file not found:", fileInfo.Name())
		}
	}
	t := fileInfo.ModTime().String()
	b := fileInfo.Size()

	i := finfo{
		name: name,
		size: b,
		time: t,
	}
	return i
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
	user := GetUserInfo()
	strlist := OpenFile(user.shellpath)
	i := 0
	for _, str := range strlist {
		i++
		cmd := FindDeviousCmd(str)
		if cmd != "no" {
			println(cmd)
		}
	}
}

func main() {
	id := os.Geteuid()
	if id != 0 {
		println("You must be root to run this program.")
		os.Exit(1)
	}
	//args

	var (
		file      string
		mode      int
		overwrite string
	)

	flag.StringVar(&file, "file", "", "File to check")
	flag.IntVar(&mode, "mode", 0, "Mode to run")
	flag.StringVar(&overwrite, "overwrite", "", "Overwrite backup; perform new backup")
	flag.Parse()
	println(mode)
	println(file)
	println(overwrite)

	RestoreController(mode, file, overwrite)

	//indexstr := strings.Split(file, "/")
	//println(indexstr[len(indexstr)-1])
	//bruh := OpenFile(file)

	//for _, str := range bruh {
	//	println(str)
	//}

	//cmdhist()
}
