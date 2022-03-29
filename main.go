package main

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

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

func FindDeviousCmd(cmdlist []string) /*int*/ {
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

	for _, cmd := range cmdlist {
		if strings.Contains(cmd, "vi") {
			println("Devious command:", cmd)
		}
	}
}

func main() {
	ufiles := GetUserWithHome()
	for _, ufile := range ufiles {
		newfile := "/home/" + ufile + "/.bash_history"
		stats := CheckFile("/home/" + ufile + "/.bash_history")
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
			//for scanner.Scan() {
			//	println(scanner.Text())
			// analyze lines for interesting commands
			//}
		}
	}
}
