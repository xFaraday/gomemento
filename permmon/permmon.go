package permmon

import (
	"io/ioutil"
	"os"

	"go.uber.org/zap"
)

var (
	dirforbackups = "/opt/memento/"
	indexfile     = "/opt/memento/index.safe"
	fileindexfile = "/opt/memento/fileindex.safe"
)

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

func FilePermChangeSingle(file string, perm int) {
	os.Chmod(file, os.FileMode(perm))
	zap.S().Info("Reset permissions for: " + file)
}

func CheckPermDifference(SystemFiles map[string]int) {
	for file, _ := range SystemFiles {
		stat, _ := os.Stat(file)
		Currentperm := int(stat.Mode().Perm())
		if Currentperm != SystemFiles[file] {
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
	/*
		UserFiles := []string{
			"/etc/passwd",
			"/etc/group",
			"/etc/sudoers",
			"/etc/hosts",
		}
		//-rw-r----- 1 root root
		UserFilesSafe := []string{
			"/etc/shadow",
			"/etc/gshadow",
		}
		//-rw------- 1 root root
		CronTabFiles := []string{
			"/etc/crontab",
		}
		//rwx------ 1 root root
		CronTabDirs := []string{
			"/etc/cron.hourly/",
			"/etc/cron.daily/",
			"/etc/cron.weekly/",
			"/etc/cron.monthly/",
			"/etc/cron.d/",
		}
	*/
	//FilePermChangeWide(SystemFiles)
	CheckPermDifference(SystemFiles)
}
