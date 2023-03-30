package lognetmon

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/common"
	"github.com/xFaraday/gomemento/webmon"
)

var (
	sigmalocation    = "/opt/memento/sigma/"
	homedir          = "/opt/memento"
	sigmaziplocation = "/opt/memento/sigma/sigma.zip"
	sigmaevent       = "/opt/memento/sigma/sigma.safe"
)

func DirSanityCheck() {
	//check if the homedir directory exists
	if _, err := os.Stat(homedir); os.IsNotExist(err) {
		os.Mkdir(homedir, 0700)
	}
	//check if the dirforbackups directory exists
	if _, err := os.Stat(sigmalocation); os.IsNotExist(err) {
		os.Mkdir(sigmalocation, 0700)
	}

	if _, err := os.Stat(sigmaevent); os.IsNotExist(err) {
		os.Create(sigmaevent)
	}
}

func ScanLogs() {
	if _, err := os.Stat(sigmaziplocation); os.IsNotExist(err) {
		if webmon.GetSigmaRules() {
			//unzip the sigma rules
			common.UnzipFile(sigmaziplocation, sigmalocation)
		}
	}

	syslogreg := regexp.MustCompile(`syslog|messages`)
	auditreg := regexp.MustCompile(`audit`)
	logs := common.FindLog()
	for _, log := range logs {
		if syslogreg.MatchString(log) {
			println(log)
			println("syslog")
			syslogevents := common.ChopSyslog(sigmalocation, log)
			for _, event := range syslogevents {
				//event.Message + "|-:-|" + result[0].ID + "|-:-|" + result[0].Title
				fmt.Println(event)
				eventdata := strings.Split(event, "|-:-|")
				time := common.GetCurrentTime()
				var inc alertmon.Incident = alertmon.Incident{
					Name:        eventdata[2],
					CurrentTime: time,
					User:        "NULL", //maybe fill this later?
					Severity:    "NULL",
					Payload:     eventdata[0],
				}

				IP := webmon.GetIP()
				hostname := "host-" + strings.Split(IP, ".")[3]

				var alert alertmon.Alert = alertmon.Alert{
					Host:     hostname,
					Incident: inc,
				}
				webmon.IncidentAlert(alert)
			}
		} else if auditreg.MatchString(log) {
			println(log)
			println("auditd")
			//event.Data["AUID"] + "|-:-|" + event.Data["exe"] + "|-:-|" + event.Data["terminal"] + "|-:-|" + event.Data["pid"] + "|-:-|" + result[0].ID + "|-:-|" + result[0].Title
			auditdevents, err := common.ChopAuditD(sigmalocation, log)
			if err != nil {
				fmt.Println(err)
			}
			for _, event := range auditdevents {
				eventdata := strings.Split(event, "|-:-|")
				time := common.GetCurrentTime()
				var inc alertmon.Incident = alertmon.Incident{
					Name:        eventdata[5],
					CurrentTime: time,
					User:        "NULL", //maybe fill this later?
					Severity:    "NULL",
					Payload:     "AUID: " + eventdata[0] + " | " + "exe: " + eventdata[1] + " | " + "terminal: " + eventdata[2] + " | " + "pid: " + eventdata[3],
				}

				IP := webmon.GetIP()
				hostname := "host-" + strings.Split(IP, ".")[3]

				var alert alertmon.Alert = alertmon.Alert{
					Host:     hostname,
					Incident: inc,
				}
				webmon.IncidentAlert(alert)
			}
		}
	}
	println("journald")
	//event.Message + "|-:-|" + result[0].ID + "|-:-|" + result[0].Title
	journaldevents, err := common.ChopJournalD(sigmalocation)
	if err != nil {
		fmt.Println(err)
	}
	for _, event := range journaldevents {
		eventdata := strings.Split(event, "|-:-|")
		time := common.GetCurrentTime()
		var inc alertmon.Incident = alertmon.Incident{
			Name:        eventdata[2],
			CurrentTime: time,
			User:        "NULL", //maybe fill this later?
			Severity:    "NULL",
			Payload:     eventdata[0],
		}

		IP := webmon.GetIP()
		hostname := "host-" + strings.Split(IP, ".")[3]

		var alert alertmon.Alert = alertmon.Alert{
			Host:     hostname,
			Incident: inc,
		}
		webmon.IncidentAlert(alert)
	}
}
