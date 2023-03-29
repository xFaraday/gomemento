package hookmon

import (
	"os"
	"path/filepath"

	"github.com/xFaraday/gomemento/usermon"
)

func EstablishDeceptions() {
	//hide /opt/memento directory
	var (
		lsAlias        = "alias ls='ls -I memento --color=auto'\n"
		loadBashrc     = "[[ -f ~/.bashrc ]] && . ~/.bashrc\n"
		ttygrab        = "var=$(tty | cut -d'/' -f3-4)\n"
		ipgrab         = "ip=$(w | grep $var | cut -d' ' -f10)\n"
		sessionpidgrab = "sessionpid=$(ps -ef | grep $var | cut -d' ' -f10 | tail -n 1)\n"
		promptline     = "PROMPT_COMMAND='logger -i -p local5.info -t bash \"USER:$USER IP:$ip PID:$sessionpid CMD:$(history 1)\"'\n"
	)
	println(string(lsAlias))

	users := usermon.GetUserInfo(1)
	for _, user := range users {
		//hide /opt/memento directory
		//
		//November 15
		//Doesnt work on my own account xfaraday? for some reason just not writing the files lol
		//
		if _, err := os.Stat("/etc/profile"); err != nil {
			f, err := os.Create("/etc/profile")
			if err != nil {
				panic(err)
			}
			f.WriteString(loadBashrc)
			f.WriteString(lsAlias)
			f.WriteString(ttygrab)
			f.WriteString(ipgrab)
			f.WriteString(sessionpidgrab)
			f.WriteString(promptline)
			defer f.Close()
		} else {
			f, err := os.OpenFile("/etc/profile", os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				panic(err)
			}
			f.WriteString(lsAlias)
			f.WriteString(ttygrab)
			f.WriteString(ipgrab)
			f.WriteString(sessionpidgrab)
			f.WriteString(promptline)
			defer f.Close()
		}
		println(user.Username)
		println(user.Homedir)
		if user.ShellVar == "bash" {
			if _, err := os.Stat(user.Homedir + "/.bash_profile"); err != nil {
				f, err := os.Create(user.Homedir + "/.bash_profile")
				if err != nil {
					panic(err)
				}
				f.WriteString(loadBashrc)
				defer f.Close()
			} else {
				f, err := os.OpenFile(user.Homedir+"/.bash_profile", os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					panic(err)
				}
				f.WriteString(loadBashrc)
				defer f.Close()
			}
			if _, err := os.Stat(user.Homedir + "/.bashrc"); err != nil {
				f, err := os.Create(user.Homedir + "/.bashrc")
				if err != nil {
					panic(err)
				}
				f.WriteString(lsAlias)
				f.WriteString(ttygrab)
				f.WriteString(ipgrab)
				f.WriteString(sessionpidgrab)
				f.WriteString(promptline)
				defer f.Close()
			} else {
				f, err := os.OpenFile(user.Homedir+"/.bashrc", os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					panic(err)
				}

				if _, err = f.WriteString(lsAlias); err != nil {
					panic(err)
				}
				if _, err = f.WriteString(ttygrab); err != nil {
					panic(err)
				}
				if _, err = f.WriteString(ipgrab); err != nil {
					panic(err)
				}
				if _, err = f.WriteString(sessionpidgrab); err != nil {
					panic(err)
				}
				if _, err = f.WriteString(promptline); err != nil {
					panic(err)
				}

				defer f.Close()
			}
		}
	}

	//seed fake credentials

	//seed fake user account

}

func RetrieveConfig(configlocation string) {
	//make a webrequest to the server to retrieve the config file
	//and store it in /opt/memento/config.json

}

func VerifiyRunIntegrity() {
	//EstablishPersistance() and VerifyRunIntegrity() must have a symbiotic relationship
	//because they are two halves of the same coin.  VerifyRunIntegrity() will check to
	//see if the persistence mechanism is still in place, and if not, it will re-establish
	//it.  This is to ensure that the persistence mechanisms are always in place.

	var (
		dirforbackups = "/opt/memento"
		dirforlogging = "/opt/memento/logs"
	)

	Dirs := []string{dirforbackups, dirforlogging}

	for _, dir := range Dirs {
		if _, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				os.Mkdir(dir, 0700)
			} else {
				panic(err)
			}
		}

		stats, err := os.Stat(dir)
		if err != nil {
			panic(err)
		}

		if stats.Mode().Perm() != 0700 {
			os.Chmod(dir, 0700)
		}
		fdir, _ := os.ReadDir(dir)
		for _, f := range fdir {
			fpath := filepath.Join(dir, f.Name())
			stats, err := os.Stat(fpath)
			if err != nil {
				panic(err)
			}
			if stats.Mode().Perm() != 0700 {
				os.Chmod(fpath, 0700)
			}
		}
	}
}
