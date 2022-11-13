package servicemon

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
	"os"
	"io/ioutil"
	"encoding/hex"
	"crypto/sha1"
)

type ServiceStats struct {
	serviceName	string
	serviceStatus	string
}

func ListServices() []ServiceStats {
	serviceListOut, _ := exec.Command("bash", "-c", "systemctl list-unit-files --type=service").Output()
	serviceListSplit := strings.Split(string(serviceListOut), "\n")
	services := []ServiceStats{}
	for _, service := range serviceListSplit {
		if len(service) != 0 && strings.Contains(service, "unit files listed") != true && strings.Contains(service, "VENDOR PRESET") != true  {
			serviceFields := strings.Fields(service)
			serviceStruct := ServiceStats{serviceFields[0], serviceFields[1]}
			/*
			[0] - Unit file
			[1] - State
			[2] - Vendor preset
			*/
			services = append(services, serviceStruct)
		}
	}
	return services
}

// Take service snapshot
// Sleep for specified amount of time
// Take another service snapshot & compare against previous one to check for changes
// Output changes (TODO)
// Call ServiceMonitor(), it'll handle the rest
 func ServiceMonitor(sleepDuration time.Duration) {
	serviceSnapHashOrig := ServiceSnap()
	for {
		if len(serviceSnapHashOrig) != 0 {
			time.Sleep(sleepDuration * time.Second)
			serviceSnapHashNew := ServiceSnap()
			fmt.Println(serviceSnapHashOrig)
			fmt.Println(serviceSnapHashNew)
			fmt.Println("[+] Checking hashes...")
			if serviceSnapHashOrig != serviceSnapHashNew {
				fmt.Println("[!] Hashes for service files do not match!")
			} else {
				fmt.Println("[+] Hashes match. Resuming rest...")
			}
		}
	}
}


// create service file, return hash of it
func CreateServiceFile(serviceFileName string) string {
	fileHandle, err := os.Create(serviceFileName)
		if err != nil {
			fmt.Println(err)
		} else {
			serviceSnap := ListServices()
			for _, service := range serviceSnap {
				fileHandle.Write([]byte(service.serviceName))
				fileHandle.Write([]byte("\n"))
			}
		}
		fileHandle.Close()
		serviceFileData, err := ioutil.ReadFile(serviceFileName)
		if err != nil {
			fmt.Println(err)
		}
		// read the new snapshot file, return hash of it
		serviceDataHashByte := sha1.Sum([]byte(serviceFileData))
		serviceDataHashStr := hex.EncodeToString(serviceDataHashByte[:])
		return serviceDataHashStr
}

// Take service snapshot, place it in a file
// Return hash of the service snapshot
//func ServiceSnap(serviceSnapshotFile string = "/tmp/servicesnap.orig") string {
func ServiceSnap() string {
	serviceSnapshotFile := "/tmp/servicesnap.orig"
	_, err := os.Stat(serviceSnapshotFile)
	// create the service snap file if it doesn't already exist
	if os.IsNotExist(err) {
		fmt.Println("[+] Original service file doesn't exist. Creating...")
		CreateServiceFile(serviceFileName string) 
		serviceDataHash := CreateServiceFile(serviceSnapshotFile)
		return serviceDataHash
	} else {
		// if servicesnap.orig exists, create updated one to check
		fmt.Println("[+] Original service file exists. Creating updated one...")
		serviceDataHash := CreateServiceFile("/tmp/servicesnap.duplicate")
		return serviceDataHash
	}
}

