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

type finfo struct {
	name string
	size int64
	time string
}

func VerifyFile(file string, m map[int]string) {

}

func CreateRestorePoint(file string) {
	dirforbackups := "/opt/memento"
	indexfile := "/opt/memento/index.safe"
	newfile := file
	stats := CheckFile(newfile)
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
			appendfile, err := os.OpenFile(indexfile, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				panic(err)
			}
			println("Appending to index file")
			appendfile.WriteString(indexstr)
			defer appendfile.Close()
		}

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
			//println(string(jsonStr))
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
		stats := CheckFile(file)
		indexfile := "/opt/memento/index.safe"
		println(stats.time)
		ifile, err := os.Open(indexfile)
		if err != nil {
			panic(err)
		}
		defer ifile.Close()

		scanner := bufio.NewScanner(ifile)
		// optionally, resize scanner's capacity for lines over 64K, see next example
		for scanner.Scan() {
			a := 0
			println(scanner.Text())
			strpre := scanner.Text()
			tex := strings.Split(strpre, "-:-")
			if tex[0] == file {
				println("file found in index file: " + tex[0])
				if tex[2] != stats.time {
					println("file:" + tex[0] + " MODIFIED")
					statsback := CheckFile(tex[0])
					if statsback.size != 0 {
						//REFACTOR EVERYTHING WITH FUNCTION THAT READS AND RETURNS THE SCANNER
						//VerifyFile(file, m)
					}
				} else {
					println("file:" + tex[0] + " NOT MODIFIED")
				}
				a++
			}
			if a == 0 {
				println("file not found in index file, perform backup first")
			}
		}

		if err := scanner.Err(); err != nil {
			panic(err)
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
		stats := CheckFile(newfile)
		if stats.size != 0 {
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
