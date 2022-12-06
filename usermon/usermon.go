package usermon

import (
	"bytes"
	"encoding/binary"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/common"
	"github.com/xFaraday/gomemento/webmon"
	"go.uber.org/zap"
)

type uinfo struct {
	Username  string
	Userid    string
	Groupid   string
	Homedir   string
	Shellpath string
	ShellVar  string
}

type Uinfosnap struct {
	users []uinfo
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

type UserInfo struct {
	Name string
	Line string
	Host string
	Last string
}

var rsize = unsafe.Sizeof(record{})

func UserLoginEvent(uobject *UserInfo) {
	//generating alert for user login
	var inc alertmon.Incident = alertmon.Incident{
		Name:     "UserLogin",
		User:     uobject.Name,
		Process:  "dum", //maybe fill this later?
		RemoteIP: uobject.Host,
		Cmd:      "dum",
	}

	IP := webmon.GetIP()
	hostname := "host-" + strings.Split(IP, ".")[3]

	var alert alertmon.Alert = alertmon.Alert{
		Host:     hostname,
		Incident: inc,
	}

	//send alert to webserv
	//webmon.IncidentAlert(alert)

	webmon.IncidentAlert(alert)
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

	passwds := GetUserInfo(1)

	for _, p := range passwds {
		Uid, _ := strconv.Atoi(p.Userid)
		last, line, host, err := getLogByUID(int64(Uid), f, size)
		if err != nil {
			panic(err)
		}

		var lastlog string
		if last == time.Unix(0, 0) {
			lastlog = "**Never logged in**"
		} else {
			lastlog = last.String()
			var info = &UserInfo{
				Name: p.Username,
				Line: line,
				Host: host,
				Last: lastlog,
			}

			diff := TimeDiff(info)
			TimeIntervalInMillis := TimeInterval * 1000
			if diff < TimeIntervalInMillis && diff > 0 {
				//call functions to track user
				println("USER: " + info.Name + " LOGGED IN FROM: " + info.Host)
				zlog := zap.S().With(
					"User", info.Name,
					"From Host", info.Host,
					"Last", info.Last,
				)
				zlog.Warn("USER LOGGED IN")

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

func GetUserInfo(mode int) []uinfo {
	strlist := common.OpenFile("/etc/passwd")

	var uinfos []uinfo

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
				shellz := strsplit[6]
				shellsplit := strings.Split(shellz, "/")
				shellname := shellsplit[len(shellsplit)-1]

				shellpathfull := common.GetHistFile(username, shellname, homedir)

				u := uinfo{
					Username:  username,
					Userid:    userid,
					Groupid:   groupid,
					Homedir:   homedir,
					Shellpath: shellpathfull,
					ShellVar:  shellname,
				}
				uinfos = append(uinfos, u)
			}
		}
		//return all users with shell
		return uinfos

	} else if mode == 2 {
		for _, str := range strlist {
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
				Username:  username,
				Userid:    userid,
				Groupid:   groupid,
				Homedir:   homedir,
				Shellpath: shellpathfull,
			}
			uinfos = append(uinfos, u)
		}
		return uinfos
	}
	return uinfos
}

func TimeDiff(uobject *UserInfo) int {
	/*
		Time Format = RFC 3339
	*/
	lTimeUnformatted := uobject.Last
	lTime := strings.Split(lTimeUnformatted, " ")

	lZoneUnformatted := lTime[2]
	lZone := lZoneUnformatted[:3] + ":" + lZoneUnformatted[3:]

	lPLS := lTime[0] + "T" + lTime[1] + lZone

	t, err := time.Parse(time.RFC3339, lPLS)
	if err != nil {
		println(err)
	}
	difference := int(time.Now().UnixMilli() - t.UnixMilli())
	return difference
}
