package logmon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/hookmon"
	"github.com/xFaraday/gomemento/webmon"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

/*
Logging level reference
    DebugLevel: are usually present only on development environments.
    InfoLevel: default logging priority.
    WarnLevel: more important than InfoLevel, but still doesn't need individual human attention.
    ErrorLevel: these are high-priority and shouldn't be present in the application.
    DPanicLevel: these are particularly important errors and in the development environment logger will panic.
    PanicLevel: logs a message, then panics.
    FatalLevel: logs a message, then calls os.Exit(1).
*/

func InitLogger() {
	hookmon.VerifiyRunIntegrity()
	writerSync := getLogWriter()
	encoder := getEncoder()

	core := zapcore.NewCore(encoder, writerSync, zapcore.DebugLevel)
	logg := zap.New(core, zap.AddCaller())

	zap.ReplaceGlobals(logg)
}

func getLogWriter() zapcore.WriteSyncer {
	path := "/opt/memento/logs/gomemento.log"

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		panic(err)
	}

	return zapcore.AddSync(file)
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoder(func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.UTC().Format("2006-01-02T15:04:05z0700"))
	})

	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

// filepath should be a utmp, wtmp, or btmp file which has info about logins
// /var/run/utmp
// /var/log/wtmp
// /var/log/btmp
// Resource: https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering/
func DetectTampering(filepath string) {
	fmt.Println("[+] Inspecting: " + filepath)
	fileBytes, _ := exec.Command("bash", "-c", "utmpdump "+filepath).Output()
	// loop through each line of the log file, attempt to find the date which indicates tampering
	for _, line := range strings.Split(string(fileBytes), "\n") {
		// last log file field contains the date, we only want that
		if len(line) != 0 {
			logFileFields := strings.Fields(line)
			timestampField := logFileFields[len(logFileFields)-1]
			// if log file timestamp field contains suspicious date, may be indication of tampering
			if strings.Contains(timestampField, "1970-01-01") {
				// send alert about potential tampering w/log files
				/* alert should contain:
				* log file tampered with
				* IP addr of machine
				* hostname of machine
				 */
				fmt.Println("[!] Potential tampering has occurred!")
				// generate log report
				zlog := zap.S().With(
					"REASON:", "Potential login log file tampering",
					"Log File Location:", filepath,
					"Metholodgy:", "The log file contained the timestamp 1970-01-01 which indicates that an event was nulled out",
				)
				zlog.Warn("Potential log file tampering detected with login log files")

				// generate alert
				var inc alertmon.Incident = alertmon.Incident{
					Name:        "Log file tampering with the following log file: " + filepath,
					CurrentTime: "",
					User:        "",
					Severity:    "High",
					Payload:     "",
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
}

/* determine which log file(s) to use:
/var/run/utmp
/var/log/wtmp
/var/log/btmp
*/
// First run FindBadLoginFile(), it'll return a slice w/the locations in which bad logins are logged
// Then loop through that slice & run DetectTampering() on each log path returned by FindBadLoginFile()
func FindBadLoginFile() []string {
	fmt.Println("[+] Finding bad login log files...")
	possibleLogFileLocations := []string{"/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"}
	validLogFileLocations := []string{}
	for _, file := range possibleLogFileLocations {
		// create slice of all log files that exist, return it
		_, err := os.Stat(file)
		// if file doesn't exist
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("[!] " + file + " doesn't exist on this system!")
		} else {
			validLogFileLocations = append(validLogFileLocations, file)
		}

	}

	return validLogFileLocations
}

type FailLogData struct {
	user        string
	failct      string
	latestlogin string
}

func ReportFailedLoginCount(username string) {
	if username == "all" {
		failLogOut, err := exec.Command("bash", "-c", "user=$(awk -F ':' '{ print $1}' /etc/passwd);for i in $user; do faillog -u $i; done").Output()
		if err != nil {
			fmt.Println(err)
		}
		failLogOutSplit := strings.Split(string(failLogOut), "\n")
		// loop through each user's faillog stats
		for _, line := range failLogOutSplit {
			if line != "Login       Failures Maximum Latest                   On" && len(line) != 0 {
				// split on each space so we can parse each log
				fields := strings.Fields(line)
				// check if the amount of failures is over 3
				failureCtInt, _ := strconv.Atoi(fields[1])
				if failureCtInt > 3 {
					// send alert since login failures is over 3
					fmt.Println("[!] Login failures for user: " + fields[0] + " is over 3!")
					// generate log report
					zlog := zap.S().With(
						"REASON:", "Failed login count exceeds 3!",
						"Username:", fields[0],
						"Metholodgy:", "Used faillog to detect amount of failed logins",
					)
					zlog.Warn("Failed login count exceeds 3!")

					// generate alert
					var inc alertmon.Incident = alertmon.Incident{
						Name:        "Failed login count for following user exceeds 3: " + fields[0],
						CurrentTime: fields[0],
						User:        "",
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
					fmt.Println("[+] Failed logins are below 3 for user: " + fields[0])
				}
			}
		}
	} else {
		failLogOut, err := exec.Command("bash", "-c", "faillog -u "+username).Output()
		if err != nil {
			fmt.Println(err)
		}
		failLogOutSplit := strings.Split(string(failLogOut), "\n")
		for _, line := range failLogOutSplit {
			if line != "Login       Failures Maximum Latest                   On" && len(line) != 0 {
				fields := strings.Fields(line)
				// check if amount of failures is over 3
				failureCtInt, _ := strconv.Atoi(fields[1])
				if failureCtInt > 3 {
					// send alert since login failures is over 3
					fmt.Println("[!] Login failures for user: " + fields[0] + " is over 3!")
					// generate log report
					zlog := zap.S().With(
						"REASON:", "Failed login count exceeds 3!",
						"Username:", fields[0],
						"Metholodgy:", "Used faillog to detect amount of failed logins",
					)
					zlog.Warn("Failed login count exceeds 3!")

					// generate alert
					var inc alertmon.Incident = alertmon.Incident{
						Name:        "Failed login count for following user exceeds 3: " + fields[0],
						CurrentTime: fields[0],
						User:        "",
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
					fmt.Println("[+] Failed login count is below 3 for user: " + fields[0])
				}
			}
		}
	}
}

func LogGuardian() {
	/*
		Parse logs for maliscious activity, also check for log tampering.
		/var/log/wtmp
		/var/log/lastlog
		/var/log/btmp
		/var/log/utmp
		/var/log/*

		Check logs overwritten by Zero Bytes. Obvious sign of log tampering.
		date time modificiation date of all logs are identical.
		Null Erased logins.

		probably should also check file permissions for all the logs

		Method to read log files:
		https://stackoverflow.com/questions/17863821/how-to-read-last-lines-from-a-big-file-with-go-every-10-secs
	*/

	/*
		dirgrab, err := os.ReadDir("/var/log")
		if err != nil {
			panic(err)
		}
		for _, dir := range dirgrab {
			switch dir.Name() {
			case "apache2":
				//pattern for scans
				PatternforScannerz := regexp.MustCompile(`[nN]map|masscan|curl|[gG]o-http-client`)
				PatternforShellshock := regexp.MustCompile(``)
				PatternforWebshell := regexp.MustCompile(``)

				//develop regex from requests lists developed from old apache server logs

					something for:
					cgi-bin
					cmd=
					shell
					jndi for log4j

					CONNECT request

					start of tls handshake
					\x16\x03\x01


			case "auth.log":

					monitor accepted publickeys for sshd
					and password auth

					bruteforce attempts? eh just install fail2ban


			}
		}
	*/
}
