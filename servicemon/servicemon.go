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

// Will/Should use /etc/init.d to find service names <- seems to work for Alpine Linux too (Have to test on Slackware)
// Then we differentiate between the different system managers to find the status of the service since /sbin/service <service> status output varies between Linux distributions
func ListServices() []ServiceStats {
	serviceDir := "/etc/init.d"
	// Find system manager
	pstree := exec.Command("pstree")
	head := exec.Command("head", "-n", "1")
	pipe, _ := pstree.StdoutPipe()
	
	head.Stdin = pipe
	pstree.Start()
	
	systemManagerUnparsed, _ := head.Output()
	pipe.Close()
	systemManager := strings.Split(string(systemManagerUnparsed), "-+-")[0]
	fmt.Println(systemManager + " is being used!")

	dirHandle, err := os.Open(serviceDir)
	if err != nil {
		fmt.Println(err)
	}
	files, err := dirHandle.Readdir(-1)
	if err != nil {
		fmt.Println(err)
	}
	services := []ServiceStats{}
	status := ""
	for _, file := range files { // each file represents a service
		// differentiate between system managers, then find status of service
		if systemManager == "systemd" {
			statusBytes, _ := exec.Command("systemctl", "is-active", file.Name()).Output()
			status = string(statusBytes)
		} else if systemManager == "init" {
			statusOut, _ := exec.Command("service", file.Name(), "status").Output()
			statusSplit := strings.Split(string(statusOut), ":")
			status = statusSplit[len(statusSplit)-1]
		} else {
			fmt.Println("Unaccounted for system manager! HELP!")
		}

		serviceStruct := ServiceStats{file.Name(), status}
		services = append(services, serviceStruct)
	}
	dirHandle.Close()
	return services
}

// Take a service config file with whitelisted services
// Enumerate each service, determine whether or not it's whitelisted. If not, disable/block it & remove it
func GetServiceConfig(path string) {
	// read service file & store whitelisted services in string slice
	fHandle, _ := os.Open(path)
	whitelistedServices := []string{}
	scanner := bufio.NewScanner(fHandle)
	for scanner.Scan() {
		whitelistedServices = append(whitelistedServices, scanner.Text())
	}
	
	// enumerate services on system
	services := ListServices("/etc/init.d")
	for _, service := range services {
		if slices.Contains(whitelistedServices, service.serviceName) != true {
			// non-scored service found, disable it
			fmt.Println("Non-scored service found: " + service.serviceName)
		}
	}

	fHandle.Close()

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
				diff := GetDifference("/tmp/servicesnap.orig", "/tmp/servicesnap.duplicate")
				zlog := zap.S().With(
					"REASON:", "Service snapshots do not match! Potential tampering with services!",
					"Diff output:", diff,
				)
				zlog.Warn("Service snapshot mismatch!")
				user, _ := exec.Command("/usr/bin/whoami").Output()
				var inc alertmon.Incident = alertmon.Incident{
					Name:     "Potentially Malicious Service Added",
					User:     string(user),
					Process:  "",
					RemoteIP: "",
					Cmd:      "",
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

func GetDifference(fileInput1 string, fileInput2 string) string {
	// diff cmd is error'ing out here but still works
	/* diff will output original file content on 1 line, then modified file content on 2nd line
	// Example:
		test	enable
		test	disable
	Service test was modified and disabled
	*/
	diffOut, err := exec.Command("/usr/bin/diff", "--line=%L", fileInput1, fileInput2).Output()
	if err != nil {
		fmt.Println(err)
	}
	return string(diffOut)
}
