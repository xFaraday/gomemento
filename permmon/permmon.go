package permmon

import (
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/xFaraday/gomemento/common"
	"github.com/xFaraday/gomemento/usermon"
	"go.uber.org/zap"
)

var (
	dirforbackups = "/opt/memento/"
	indexfile     = "/opt/memento/index.safe"
	fileindexfile = "/opt/memento/fileindex.safe"
)

/*
	func PermSnapShot(SystemFiles map[string]int) {
		for file, _ := range SystemFiles {
			stats, err := os.Stat(file)
			if err != nil {
				panic(err)
			}
			perm := stats.Mode().Perm()

			if _, err := os.Stat(fileindexfile); err != nil {
				werr := ioutil.WriteFile(fileindexfile, []byte(file+"|-:-|"+perm.String()), 0644)
				if werr != nil {
					panic(werr)
				}
			}
		}
	}

	func FilePermChangeWide(SystemFiles map[string]int) {
		for file, perm := range SystemFiles {
			os.Chmod(file, os.FileMode(perm))
		}
		PermSnapShot(SystemFiles)
	}
*/
func FindUserID() int {
	var UID []int
	users := usermon.GetUserInfo(2)
	for _, user := range users {
		id, err := strconv.Atoi(user.Userid)
		if err != nil {
			panic(err)
		}
		UID = append(UID, id)
	}
	for i := 1000; i < 2000; i++ {
		val := common.ContainsInt(UID, i)
		if val == false {
			return i
		}
	}
	return 2000
}

func ChangeID(username string, realid string, homedir string, shellpath string, Userdesc string) {
	lines := common.OpenFile("/etc/passwd")
	for i, line := range lines {
		println(line)
		if strings.Contains(line, username) {
			println("found")
			lines[i] = username + ":x:" + realid + ":" + realid + ":" + Userdesc + ":" + homedir + ":" + shellpath
			println(lines[i])
		}
	}
	output := strings.Join(lines, "\n")
	println(output)
	err := ioutil.WriteFile("/etc/passwd", []byte(output), 0644)
	if err != nil {
		panic(err)
	}
}

func UserPermIntegrityCheck() {
	//check if index.safe exists
	//if not, create it
	//if yes, compare it to the current state of the system
	//if there is a difference, log it and reset the permissions
	users := usermon.GetUserInfo(2)
	for _, user := range users {
		if user.Username == "root" {
			if user.Userid != "0" {
				zlog := zap.S().With(
					"REASON:", "User: "+user.Username+" does not have userid 0",
				)
				zlog.Warn("USER MODIFIED")
				ChangeID(user.Username, "0", user.Homedir, user.Shellpathfull, user.Userdesc)
			}
			if user.Groupid != "0" {
				zlog := zap.S().With(
					"REASON:", "Group: "+user.Username+" does not have groupid 0",
				)
				zlog.Warn("USER MODIFIED")
				ChangeID(user.Username, "0", user.Homedir, user.Shellpathfull, user.Userdesc)
			}
		} else {
			if user.Userid == "0" {
				zlog := zap.S().With(
					"REASON:", "User: "+user.Username+" has userid 0",
				)
				zlog.Warn("USER MODIFIED")
				if user.Groupid == "0" {
					id := FindUserID()
					idstring := strconv.Itoa(id)
					ChangeID(user.Username, idstring, user.Homedir, user.Shellpathfull, user.Userdesc)
				} else if user.Groupid != "0" {
					println("changing UID by GID")
					ChangeID(user.Username, user.Groupid, user.Homedir, user.Shellpathfull, user.Userdesc)
				}
			}
			if user.Groupid == "0" {
				zlog := zap.S().With(
					"REASON:", "Group: "+user.Username+" has groupid 0",
				)
				zlog.Warn("USER MODIFIED")
				if user.Userid == "0" {
					id := FindUserID()
					idstring := strconv.Itoa(id)
					ChangeID(user.Username, idstring, user.Homedir, user.Shellpathfull, user.Userdesc)
				} else if user.Userid != "0" {
					ChangeID(user.Username, user.Userid, user.Homedir, user.Shellpathfull, user.Userdesc)
				}
			}
		}
	}
}

func FilePermChangeSingle(file string, perm int) {
	os.Chmod(file, os.FileMode(perm))
	zap.S().Info("Reset permissions for: " + file)
}

func CheckPermDifference(SystemFiles map[string]int) {
	for file := range SystemFiles {
		fileInfo, err := os.Stat(file)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			panic(err)
		}
		permString := strconv.FormatInt(int64(fileInfo.Mode().Perm()), 8)
		//convert SystemFiles[file] to a string
		permString2 := strconv.Itoa(SystemFiles[file])
		if permString != permString2 {
			zlog := zap.S().With(
				"REASON:", "File Permission: "+file+" has been changed",
			)
			zlog.Warn("WEAK PERMISSION FOUND")
			FilePermChangeSingle(file, SystemFiles[file])
		}
	}
}

func FilePermCheck() {
	//-rw--r--r-- 1 root root
	var SystemFiles = map[string]int{
		"/etc/passwd":        0644,
		"/etc/group":         0644,
		"/etc/sudoers":       0644,
		"/etc/hosts":         0644,
		"/etc/shadow":        0640,
		"/etc/gshadow":       0640,
		"/etc/crontab":       0600,
		"/etc/cron.hourly/":  0700,
		"/etc/cron.daily/":   0700,
		"/etc/cron.weekly/":  0700,
		"/etc/cron.monthly/": 0700,
		"/etc/cron.d/":       0700,
	}

	//FilePermChangeWide(SystemFiles)
	CheckPermDifference(SystemFiles)
}
