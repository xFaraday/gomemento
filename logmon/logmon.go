package logmon

import (
	"os"
	"time"

	"github.com/xFaraday/gomemento/hookmon"
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
