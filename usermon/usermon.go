package usermon

// #include <stdlib.h>
// #include <pwd.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/gomemento/common"
	"github.com/gomemento/webmon"
)

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

type record struct {
	time int32
	line [32]byte
	host [256]byte
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

type UserInfo struct {
	Name string
	Line string
	Host string
	Last string
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

func UserLoginEvent(uobject *UserInfo) {
	//generating alert for user login
	var inc incident = incident{
		Name:     "UserLogin",
		User:     uobject.Name,
		Process:  "", //maybe fill this later?
		RemoteIP: uobject.Host,
		Cmd:      "",
	}

	IP := common.GetIP()
	hostname := "host-" + strings.Split(IP, ".")[3]

	var al alert = alert{
		Host:     hostname,
		Incident: inc,
	}

	//generate json
	json, _ := json.Marshal(al)

	//send alert to webserv
	webmon.PostToServ(json)

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
	strlist := common.OpenFile("/etc/passwd")
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

				shellpathfull := common.GetHistFile(username, shellname, homedir)

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

			shellpathfull := common.GetHistFile(username, shellname, homedir)

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
