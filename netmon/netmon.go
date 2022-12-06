package netmon

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/weaveworks/procspy"
	"github.com/xFaraday/gomemento/common"
)

var (
	networkfile = "/opt/memento/networkprof.safe"
)

/*
12-06 10 am
Notes:
- This is a work in progress, and is not yet complete.
- Same exact counter needs some work.  Not due to the fact it fails but because
it never removes the old counter line.
Ex:
192.168.1.3-:-41230-:-20.80.64.28-:-443-:-code-:-86615-:-1-:-1-:-1
192.168.1.3-:-41230-:-20.80.64.28-:-443-:-code-:-86615-:-2-:-1-:-1
192.168.1.3-:-41230-:-20.80.64.28-:-443-:-code-:-86615-:-3-:-1-:-1
192.168.1.3-:-41230-:-20.80.64.28-:-443-:-code-:-86615-:-4-:-1-:-1

same exact line but version 1,2, and 3 are kept in the file.  So rip performance :( and statiscal relavance.

- Also big oversight.  Due to HOW the logic is structured with if, else if the other counters are NEVER incremented.
Probably better to add the logic to a separate function and structure it differently.

- Needs the alert function.  What are we supposed to derive from this network information? THE GOAL ultimately is to
find the network connections that are not normal.  An easy test to start with is to find the remote IPs that are not
public IPs.  Then cross reference the counters with that private IP.  If the counter is high, then it is likely that
the box has some interconnected dependency on the network.  Like a website to database.  This information should most likely
be logged somehow because its extremely useful for debugging broken applications. If the counter is low, then
it is more likely that it is some type of red team activity.  Hopefully we could find the C2 server and then ban their
red team asses lol.
*/

func UpdateNetworkIndex(constore []string) {
	constorePost := AnalyzeNetworkConnsPost(constore)
	stats := common.CheckFile(networkfile)
	//fmt.Printf("%v", stats)
	if stats.Size == 0 {
		file, err := os.OpenFile(networkfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		for _, str := range constorePost {
			if len(str) > 1 {
				file.WriteString(str)
			}
		}
	} else {
		file, err := os.OpenFile(networkfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		for _, str := range constorePost {
			if len(str) > 1 {
				file.WriteString(str)
			}
		}
	}
	//add other logic to analyze the networkprof.safe file against constore and update it
}

func AnalyzeNetworkConnsPost(constore []string) []string {
	//network connections
	//localIP:localPort-:-remoteIP:remotePort-:-protocol-:-state-:-pid-:-processname-:-exactcounter-:-sameRemoteIPCounter-:-sameLocalIPCounter
	//

	//past connections
	netConnection := common.OpenFile(networkfile)

	//constore = append(constore, netConnection...,"\n")

	for _, conn := range netConnection {
		constore = append(constore, conn+"\n")
	}

	for i := 0; i < len(constore); i++ {
		a := i + 1
		isplit := strings.Split(constore[i], "-:-")
		println("new: " + constore[i])
		for j := a; j < len(constore); j++ {
			jsplit := strings.Split(constore[j], "-:-")
			println(isplit[1] + " " + jsplit[1])
			println(constore[j])
			if isplit[0] == jsplit[0] &&
				isplit[2] == jsplit[2] &&
				isplit[3] == jsplit[3] {
				num := isplit[6]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + num + "-:-" + isplit[7] + "-:-" + isplit[8]
			} else if isplit[2] == jsplit[2] &&
				isplit[3] == jsplit[3] {
				num := isplit[7]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + num + "-:-" + isplit[8]
			} else if isplit[0] == jsplit[0] &&
				isplit[1] == jsplit[1] {
				num := isplit[8]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				//rewrite file
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + isplit[7] + "-:-" + num
			}
		}
	}
	//print out
	for _, str := range constore {
		print(str)
	}

	return constore
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
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + num + "-:-" + isplit[7] + "-:-" + isplit[8]
			} else if isplit[2] == jsplit[2] &&
				isplit[3] == jsplit[3] {
				num := isplit[7]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + num + "-:-" + isplit[8]
			} else if isplit[0] == jsplit[0] &&
				isplit[1] == jsplit[1] {
				num := isplit[8]
				numint, _ := strconv.Atoi(num)
				numint++
				num = strconv.Itoa(numint)
				//rewrite file
				constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + isplit[6] + "-:-" + isplit[7] + "-:-" + num
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
