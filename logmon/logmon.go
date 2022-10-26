package logmon

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
