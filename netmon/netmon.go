package netmon

import (
	"log"
	"os"
	"regexp"
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

12-08 8 am
- Segmented the logic for incrementing the counters.  Helps readability a lot.
- New problem.  Need to change logic for the actual incrementing of the counters in the if statements.
- - perhaps the ExactMatch...etc functions should return the new value of the counter itself.  Then
if statements would not have to be used in the main function and scope can be retained properly


2-23
- new way to store things. Much better on the eyes.  Please implement |-:-| as the delimiter
instead of -:-.

- Experiment with line 129.  Specifically the use of ElimateDuplicate.  It might stop all counter
values from incrementing without some adjustment.  Also is it the most statistically relevant
to get rid of duplicates at this stage? Or should it be done before the counters are incremented?
*/

func DuplicateCheck(constore []string, file []string) []string {
	for _, conn := range file {
		conn1split := strings.Split(conn, "-:-")
		for i, conn2 := range constore {
			conn2split := strings.Split(conn2, "-:-")
			if conn1split[0] == conn2split[0] &&
				conn1split[1] == conn2split[1] &&
				conn1split[2] == conn2split[2] &&
				conn1split[3] == conn2split[3] &&
				conn1split[4] == conn2split[4] &&
				conn1split[5] == conn2split[5] {
				//overwrite last element with element to delete
				constore[i] = constore[len(constore)-1]
				//set last element to empty string
				constore[len(constore)-1] = ""
				//truncate slice
				constore = constore[:len(constore)-1]
				return constore
			}
		}
	}
	return constore
}

func ElimateDuplicate(constore []string) []string {
	stats := common.CheckFile(networkfile)
	//fmt.Printf("%v", stats)
	if stats.Size == 0 {
		return constore
	} else {
		//past connections
		file := common.OpenFile(networkfile)
		prelen := len(constore)
		constore = DuplicateCheck(constore, file)
		postlen := len(constore)
		/*
			Basically, if the length of the constore before
			the check and removal has been made is the same
			afterwards.  This means that there are no
			duplicates among the network connections
			currently taken and the network connections
			stored in the networkprof.safe file.
		*/
		if prelen == postlen {
			return constore
		} else {
			return ElimateDuplicate(constore)
		}
	}
}

func UpdateNetworkIndex(constore []string) {
	stats := common.CheckFile(networkfile)
	//fmt.Printf("%v", stats)
	if stats.Size == 0 {
		file, err := os.OpenFile(networkfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		for _, str := range constore {
			if len(str) > 1 {
				file.WriteString(str + "\n")
			}
		}
	} else {
		constorePost := AnalyzeNetworkConnsPost(constore)
		file, err := os.OpenFile(networkfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		for _, str := range ElimateDuplicate(constorePost) {
			if len(str) > 1 {
				file.WriteString(str + "\n")
			}
		}
	}
	//add other logic to analyze the networkprof.safe file against constore and update it
}

func FFTAlgo() {
	//basic Kernel wdswdwa
	//1 2 1
	//2 4 2
	//1 2 1
	//var Kernel [3][3]int = [3][3]int{{1, 2, 1},{2, 4, 2},{1, 2, 1}}

}

func FirstTest(conn string) {
	//FirstTest consists of:
	//1. Check if the remote IP is a private IP
	//2. Check if the counters are 1

	regexPrivateIP := regexp.MustCompile(`(^127\.0\.0\.1)|(^192\.168)|(^10\.)|(^172\.1[6-9])|(^172\.2[0-9])|(^172\.3[0-1])`)
	connsplit := strings.Split(conn, "-:-")

	if regexPrivateIP.MatchString(connsplit[2]) {
		SecondTest(conn)
	} else if connsplit[6] == "1" || connsplit[7] == "1" || connsplit[8] == "1" {
		SecondTest(conn)
	}
}

func SecondTest(conn string) {
	println(conn)
}

func ExactMatch(conn1 []string, conn2 []string) string {
	if conn1[0] == conn2[0] &&
		conn1[2] == conn2[2] &&
		conn1[3] == conn2[3] {
		numint, _ := strconv.Atoi(conn1[6])
		numint++
		return strconv.Itoa(numint)
	}
	println("ExactMatch")
	return conn1[6]
}

func SameRemoteIP(conn1 []string, conn2 []string) string {
	if conn1[2] == conn2[2] &&
		conn1[3] == conn2[3] {
		numint, _ := strconv.Atoi(conn1[7])
		numint++
		return strconv.Itoa(numint)
	}
	println("SameRemoteIP")
	return conn1[7]
}

func SameLocalIP(conn1 []string, conn2 []string) string {
	if conn1[0] == conn2[0] &&
		conn1[1] == conn2[1] {
		numint, _ := strconv.Atoi(conn1[8])
		numint++
		return strconv.Itoa(numint)
	}
	println("SameLocalIP")
	return conn1[8]
}

func SameProcess(conn1 []string, conn2 []string) string {
	if conn1[4] == conn2[4] &&
		conn1[5] == conn2[5] {
		numint, _ := strconv.Atoi(conn1[9])
		numint++
		return strconv.Itoa(numint)
	}
	println("SameProcess")
	return conn1[9]
}

func AnalyzeNetworkConnsPost(constore []string) []string {
	//network connections
	//localIP:localPort-:-remoteIP:remotePort-:-protocol-:-state-:-pid-:-processname-:-exactcounter-:-sameRemoteIPCounter-:-sameLocalIPCounter
	//

	//past connections
	netConnection := common.OpenFile(networkfile)

	constore = append(constore, netConnection...)

	//for _, conn := range netConnection {
	//if strings.HasSuffix(conn, "\n") {
	//	constore = append(constore, conn)

	//}
	//constore = append(constore, conn+"\n")
	//}

	for i := 0; i < len(constore); i++ {
		a := i + 1
		isplit := strings.Split(constore[i], "-:-")
		println("new: " + constore[i])
		for j := a; j < len(constore); j++ {
			jsplit := strings.Split(constore[j], "-:-")
			println(isplit[1] + " " + jsplit[1])
			println(constore[j])

			/*
				var (
					numExact    = isplit[6]
					numRemoteIP = isplit[7]
					numLocalIP  = isplit[8]
				)
			*/

			var (
				numExact    = "9"
				numRemoteIP = "9"
				numLocalIP  = "9"
				numProcess  = "9"
			)

			numExact = ExactMatch(isplit, jsplit)

			numRemoteIP = SameRemoteIP(isplit, jsplit)

			numLocalIP = SameLocalIP(isplit, jsplit)

			numProcess = SameProcess(isplit, jsplit)
			constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + numExact + "-:-" + numRemoteIP + "-:-" + numLocalIP + "-:-" + numProcess
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

			/*
				var (
					numExact    = isplit[6]
					numRemoteIP = isplit[7]
					numLocalIP  = isplit[8]
				)
			*/

			var (
				numExact    = "9"
				numRemoteIP = "9"
				numLocalIP  = "9"
				numProcess  = "9"
			)

			numExact = ExactMatch(isplit, jsplit)

			numRemoteIP = SameRemoteIP(isplit, jsplit)

			numLocalIP = SameLocalIP(isplit, jsplit)

			numProcess = SameProcess(isplit, jsplit)

			constore[i] = isplit[0] + "-:-" + isplit[1] + "-:-" + isplit[2] + "-:-" + isplit[3] + "-:-" + isplit[4] + "-:-" + isplit[5] + "-:-" + numExact + "-:-" + numRemoteIP + "-:-" + numLocalIP + "-:-" + numProcess
			//println("NEW CONSTORE")
			//println(constore[i])
			//println("")
		}
	}
	//print out
	for _, str := range constore {
		print(str + "\n")
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
		newindexstr := c.LocalAddress.String() + "-:-" + strconv.Itoa(int(c.LocalPort)) + "-:-" + c.RemoteAddress.String() + "-:-" + strconv.Itoa(int(c.RemotePort)) + "-:-" + c.Name + "-:-" + strconv.Itoa(int(c.PID)) + "-:-" + "0" + "-:-" + "0" + "-:-" + "0" + "-:-" + "0"
		constore = append(constore, newindexstr)
	}
	AnalyzeNetworkConnsPre(constore)
}
