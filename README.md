# GoMemento
## EDR for linux/unix systems

Early development stages of an EDR for linux systems written in golang.

Detailed information about current features January 10th, 2023:
- File Watch Mechanism
- Process Monitoring
- Network Monitoring
- Command Monitoring
- Service Monitoring
- Self-Protection Deception Mechanism
- Alerting
- Future Work


### File Watch Mechanism

Allows for backup of any file or directory with the following command:

```
./gomemento --mode=2 --file=/etc/passwd
```
This command effectively stores a frozen backup that can be overwritten at anytime with the --overwrite flag.

At certain time intervals gomemento will check on the status of all frozen backups and the actual unfrozen files.  If there is a discrepency between the two, gomemento will automatically overwrite the changed file to match the frozen file.

Files can also be added through the config...

### Process Monitoring

Gomemento analyzes metadata about ongoing process at certain time intervals.  An example of important metadata that is collected is the current working directory of the process and the process name.

If some type of bad pattern is matched, the memory of the process is dumped and sent to kaspersky which will analyze the raw binary.  

If the process is confirmed to be maliscious the process is killed and logged.

### Network Monitoring

Collection of ongoing network information is solid however at the time of writing this I lack insight into an accurate algorithm to identify maliscious network connections. 

### User Monitoring

User login activity is logged and alerted upon.  Metadata is collected about the individuals sessions such as commands used upon login and source IP address.

### Command Monitoring

An ongoing effort is made to develop a running wordlist of all popular red team tools and techniques so that we can capture red team activity by simply matching regex patterns and commands.  A modest list has been created in cmdmon to exemplify this but further work needs to be done curating the list for practical use.

### Service Monitoring

In an attempt to catch abuse of services and red team persistence, the state and listing of all services is monitored.  If the state of any process changtes, then an alert will be generated and logged.

### Self-Protection Deception Mechanisms

When gomemento is installed into a system, it makes use of the directory **/opt/memento** which is maintained by the program over its lifecycle.

To protect the data housed inside of this directory, several checks are made whenever another monitoring cycle is called.  The permissions for the directory are recursively checked and restored to 600 for the root user.

In addition to these checks, some deception methods are introduced to any system gomemento is installed on.  One of the more developed deception methods is to add an alias for all users bash profiles.  The alias is for the **ls** command.
<br>
The alias:
```
alias ls='ls -I memento --color=auto'\n
```
The above alias will effectively render the directory to be invisible with the listing command.

### Alerting

The alerts gomemento generates are logged locally using Zap, and sent over https to a respective webserver capable of catching post requests.

The setup for alerting can be configured in the config file.

### Future Work

Most of the future work for this tool will be done on the above features.  Some of the features are lacking depth and the appropriate cross matching pattern analysis required to identify maliscious activity.
<br>
Other Features may be added in the future such as support for yara rules or a terminal based interface instead of command line flags.

