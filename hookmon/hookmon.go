package hookmon

import (
	"os"

	"github.com/robfig/cron"
	"github.com/xFaraday/gomemento/filemon"
)

func EstablishDeceptionMechanisms() {
	//hide /opt/memento directory
	lsAlias := []byte("alias ls='ls -I memento'")
	println(string(lsAlias))

	//seed fake credentials

	//seed fake user account

}

func EstablishPersistence() {
	/*
		Establish cronjob for now, maybe look into getting some type of systemd service?
	*/
	c := cron.New()
	c.AddFunc("@every 2m", cmdmon.cmdhist)
	c.AddFunc("@every 2m", filemon.VerifyFiles)
	c.Start()
}

func VerifiyRunIntegrity() {
	//EstablishPersistance() and VerifyRunIntegrity() must have a symbiotic relationship
	//because they are two halves of the same coin.  VerifyRunIntegrity() will check to
	//see if the persistence mechanism is still in place, and if not, it will re-establish
	//it.  This is to ensure that the persistence mechanisms are always in place.

	dirforbackups := "/opt/memento"
	if _, err := os.Stat(dirforbackups); err != nil {
		if os.IsNotExist(err) {
			os.Mkdir(dirforbackups, 0700)
		} else {
			panic(err)
		}
	}

}
