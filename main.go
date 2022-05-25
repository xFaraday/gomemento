package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type finfo struct {
	name string
	size int64
	time string
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

func VerifyFile(file string, m map[int]string, jsonfile string) {
	//dirforbackups := "/opt/memento"
	//fullfilename := dirforbackups + "/" + jsonfile + ".json"
	//indexfile := "/opt/memento/index.safe"
	//	jsonstr := OpenFile(fullfilename)

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
			return "new"
		}
		if splittysplit[1] == storename {
			println("duplicate file name")
			return "filename"
		}
	}
}

func CreateRestorePoint(file string) {
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
		} else {
			checkresult := ExistsInIndex(indexfile, file)
			appendfile, err := os.OpenFile(indexfile, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				panic(err)
			}
			println("APPENDING TO INDEX FILE")
			appendfile.WriteString(indexstr)
			defer appendfile.Close()
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
		//PostToServ(m)
	}
}

func RestoreController(i int, file string) {
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
		CreateRestorePoint(file)
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
					statsback := CheckFile(tex[0])
					if statsback.size != 0 {
						/*
							Gets contents of the file's present location. tex[0].
							Transfer the contents into a [int]string map called m.
							Pass this to VerifyFile.  VerifyFile compares the new
							interface with the saved json file at /opt/memento.
						*/
						//VerifyFile(file, m)
						packlist := OpenFile(tex[0])
						var m = make(map[int]string)

						i := 0
						for _, pack := range packlist {
							i++
							m[i] = pack
						}
						VerifyFile(file, m, tex[1])
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

func GetUserWithHome() []string {
	out, err := exec.Command("ls", "/home").Output()
	if err != nil {
		panic(err)
	}
	s := strings.Fields(string(out))
	return s
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
	ufiles := GetUserWithHome()
	for _, ufile := range ufiles {
		newfile := "/home/" + ufile + "/.bash_history"
		strlist := OpenFile(newfile)
		i := 0
		for _, str := range strlist {
			i++
			cmd := FindDeviousCmd(str)
			if cmd != "no" {
				println(cmd)
			}
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
		file string
		mode int
	)

	flag.StringVar(&file, "file", "", "File to check")
	flag.IntVar(&mode, "mode", 0, "Mode to run")
	flag.Parse()
	println(mode)
	println(file)
	//cmdhist()
	//indexstr := strings.Split(file, "/")
	//println(indexstr[len(indexstr)-1])
	RestoreController(mode, file)
	//bruh := OpenFile(file)

	//for _, str := range bruh {
	//	println(str)
	//}
}
