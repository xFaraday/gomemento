package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

func VerifyFile(file string) {
	newfile := "/etc/passwd"
	stats := CheckFile(newfile)
	if stats {
		hfile, err := os.Open(newfile)
		if err != nil {
			panic(err)
		}
		defer hfile.Close()

		scanner := bufio.NewScanner(hfile)

		scanner.Split(bufio.ScanLines)

		success := scanner.Scan()
		if !success {
			err = scanner.Err()
			if err != nil {
				panic(err)
			}
		}
		i := 1
		for scanner.Scan() {
			i++
			//if m[i] != scanner.Text() {
			//	println(i)
			//	println(": line does not match")
			//}
		}
	}
}

func CreateRestorePoint(file string) {
	dirforbackups := "/opt/memento"
	indexfile := "/opt/memento/index.safe"
	/*
		Index file format:
		Simple ->
		fullpath:localfile
		file:storename
	*/
	//indexstr := strings.Split(file, "/")
	strsplit := strings.Split(file, "/")
	storename := strsplit[len(strsplit)-1]

	indexstr := file + "-:-" + storename // + "-:-" + datemodified
	newindextstr := []byte(indexstr)
	if _, err := os.Stat(indexfile); err != nil {
		if os.IsNotExist(err) {
			werr := ioutil.WriteFile(indexfile, newindextstr, 0644)
			if werr != nil {
				panic(werr)
			}
		} else {
			panic(err)
		}
		if os.IsExist(err) {
			//append to the index file
			appendfile, err := os.OpenFile(indexfile, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				panic(err)
			}
			println("Appending to index file")
			appendfile.WriteString("\n" + indexstr)
			defer appendfile.Close()
		} else {
			panic(err)
		}
	}
	newfile := file
	stats := CheckFile(newfile)
	if stats {
		hfile, err := os.Open(newfile)
		if err != nil {
			panic(err)
		}
		defer hfile.Close()

		scanner := bufio.NewScanner(hfile)

		scanner.Split(bufio.ScanLines)

		success := scanner.Scan()
		if !success {
			err = scanner.Err()
			if err != nil {
				panic(err)
			}
		}

		var m = make(map[int]string)

		i := 1
		for scanner.Scan() {
			i++
			m[i] = scanner.Text()
		}

		//VerifyFile(m)
		//export the map to a file as json for later
		// verification.  Maybe use a database? Idk.
		//then if the file has been modified, like the
		//mod date doesnt match up.  Then call VerifiyFile
		jsonStr, err := json.Marshal(m)
		if err != nil {
			panic(err)
		} else {
			println(string(jsonStr))
		}
		werr := ioutil.WriteFile(dirforbackups+"/"+storename+".json", jsonStr, 0644)
		if werr != nil {
			panic(werr)
		}

	}
}

func RestoreController(i int, file string) {
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
		VerifyFile(file)
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

func CheckFile(name string) bool {
	fileInfo, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			println("file not found:", fileInfo.Name())
			return false
		}
	}
	t := fileInfo.ModTime().String()
	println("File:", name)
	println("Size:", fileInfo.Size(), "bytes")
	println("Last modified:", t)
	//call other function with channels
	return true
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
		stats := CheckFile(newfile)
		if stats {
			hfile, err := os.Open(newfile)
			if err != nil {
				panic(err)
			}
			defer hfile.Close()

			scanner := bufio.NewScanner(hfile)

			scanner.Split(bufio.ScanLines)

			success := scanner.Scan()
			if !success {
				err = scanner.Err()
				if err != nil {
					panic(err)
				}
			}

			i := 0
			for scanner.Scan() {
				i++
				cmd := FindDeviousCmd(scanner.Text())
				if cmd != "no" {
					println(cmd)
					//println(i)
				}
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
}
