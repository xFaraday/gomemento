package hookmon

import (
	"os"
)

func EstablishDeceptionMechanisms() {
	//hide /opt/memento directory
	lsAlias := []byte("alias ls='ls -I memento'")
	println(string(lsAlias))

	//seed fake credentials

	//seed fake user account

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
