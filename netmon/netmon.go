package netmon

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/weaveworks/procspy"
	"github.com/xFaraday/gomemento/common"
)

func UpdateNetworkIndex(constore []string) {
	networkfile := "/opt/memento/networkprof.safe"
	stats := common.CheckFile(networkfile)
	fmt.Printf("%v", stats)
	if stats.Size == 0 {
		file, err := os.OpenFile(networkfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		for _, str := range constore {
			file.WriteString(str)
		}
	}
	//add other logic to analyze the networkprof.safe file against constore and update it
}

func AnalyzeNetworkConnsPre(constore []string) {
	//network connections
	//localIP:localPort-:-remoteIP:remotePort-:-protocol-:-state-:-pid-:-processname-:-exactcounter-:-sameRemoteIPCounter-:-sameLocalIPCounter
	//
	for i := 0; i < len(constore); i++ {
		a := i + 1
		isplit := strings.Split(constore[i], "-:-")
		for j := a; j < len(constore); j++ {
			jsplit := strings.Split(constore[j], "-:-")
			if isplit[0] == jsplit[0] &&
				isplit[2] == jsplit[2] &&
				isplit[3] == jsplit[3] {
				num := isplit[6]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + num + "-:-" + isplit[7] + "-:-" + isplit[8] + "\n"
			} else if isplit[2] == jsplit[2] &&
				isplit[3] == jsplit[3] {
				num := isplit[7]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + num + "-:-" + isplit[8] + "\n"
			} else if isplit[0] == jsplit[0] &&
				isplit[1] == jsplit[1] {
				num := isplit[8]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				//rewrite file
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + isplit[7] + "-:-" + num + "\n"
			}
		}
	}
	//print out
	for _, str := range constore {
		print(str)
	}

	UpdateNetworkIndex(constore)
}

func GetNetworkSurfing() {
	lookupProcesses := true
	cs, err := procspy.Connections(lookupProcesses)
	if err != nil {
		panic(err)
	}
	networkfile := "/opt/memento/networkprof.safe"
	if _, err := os.Stat(networkfile); os.IsNotExist(err) {
		//create file
		file, err := os.OpenFile(networkfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
	}

	var constore []string
	for c := cs.Next(); c != nil; c = cs.Next() {
		newindexstr := c.LocalAddress.String() + "-:-" + strconv.Itoa(int(c.LocalPort)) + "-:-" + c.RemoteAddress.String() + "-:-" + strconv.Itoa(int(c.RemotePort)) + "-:-" + c.Name + "-:-" + strconv.Itoa(int(c.PID)) + "-:-" + "1" + "-:-" + "1" + "-:-" + "1" + "\n"
		constore = append(constore, newindexstr)
	}
	AnalyzeNetworkConnsPre(constore)
}
