package servicemon

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/common"
	"github.com/xFaraday/gomemento/webmon"
	"go.uber.org/zap"
)

/*
	Notes for Next Maintainer: (e.g. Issac)

	Does not detect changes in state. is this intended?
		- if so, we need to account for changes in service state, not just the preset.
		- For example, servicemon is unable to detect systemctl start sshd, or vice versa.
		- Only systemctl disable sshd

	We need to change the ListServices() function to find the list of services and their state without systemctl.
	A lot of distros don't have systemctl installed by default or wont have the tool functional in legacy environments.
		- We can use the /usr/lib/systemd/system directory to find the list of services.
*/

type ServiceStats struct {
	serviceName   string
	serviceStatus string
}

func ListServices() []ServiceStats {
	serviceListOut, _ := exec.Command("bash", "-c", "systemctl list-unit-files --type=service").Output()
	serviceListSplit := strings.Split(string(serviceListOut), "\n")
	services := []ServiceStats{}
	for _, service := range serviceListSplit {
		if len(service) != 0 && strings.Contains(service, "unit files listed") != true && strings.Contains(service, "VENDOR PRESET") != true {
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
// Call ServiceMonitor(), it'll handle the rest
func ServiceMonitor(sleepDuration time.Duration) {
	serviceSnapHashOrig := ServiceSnap()
	for {
		if len(serviceSnapHashOrig) != 0 {
			time.Sleep(sleepDuration * time.Second)
			serviceSnapHashNew := ServiceSnap()
			//fmt.Println("[+] Checking hashes...")
			if serviceSnapHashOrig != serviceSnapHashNew {
				//fmt.Println("[!] Hashes for service files do not match!")
				//func GetDifference(fileInput1 string, fileInput2 string) string {
				diff, _ := common.GetDiff("/tmp/servicesnap.orig", "/tmp/servicesnap.duplicate")
				zlog := zap.S().With(
					"REASON:", "Service snapshots do not match! Potential tampering with services!",
					"Diff output:", diff,
				)
				zlog.Warn("Service snapshot mismatch!")
				user, _ := exec.Command("/usr/bin/whoami").Output()
				var inc alertmon.Incident = alertmon.Incident{
					Name:        "Potentially Malicious Service Added",
					CurrentTime: "",
					User:        string(user),
					Severity:    "",
					Payload:     "",
				}
				IP := webmon.GetIP()
				hostname := "host-" + strings.Split(IP, ".")[3]

				var alert alertmon.Alert = alertmon.Alert{
					Host:     hostname,
					Incident: inc,
				}
				webmon.IncidentAlert(alert)
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
			fileHandle.Write([]byte(service.serviceName + " " + service.serviceStatus))
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
// func ServiceSnap(serviceSnapshotFile string = "/tmp/servicesnap.orig") string {
func ServiceSnap() string {
	serviceSnapshotFile := "/tmp/servicesnap.orig"
	_, err := os.Stat(serviceSnapshotFile)
	// create the service snap file if it doesn't already exist
	if os.IsNotExist(err) {
		fmt.Println("[+] Original service file doesn't exist. Creating...")
		CreateServiceFile(serviceSnapshotFile)
		serviceDataHash := CreateServiceFile(serviceSnapshotFile)
		return serviceDataHash
	} else {
		// if servicesnap.orig exists, create updated one to check
		fmt.Println("[+] Original service file exists. Creating updated one...")
		serviceDataHash := CreateServiceFile("/tmp/servicesnap.duplicate")
		return serviceDataHash
	}
}
