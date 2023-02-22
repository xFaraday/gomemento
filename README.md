# GoMemento
## EDR for linux/unix systems

Early development stages of an Userland EDR for linux systems written in golang.

### EDR Mode
For the use of each of the below modes and the hidden modes that accompany them the following can be utilized:
```
./gomemento --mode=31337
```

### File Watch Mechanism

Allows for backup of any file or directory with the following command:

**File Backup**
```
./gomemento --mode=2 --file=/etc/passwd
```
**Directory Backup**
```
./gomemento --mode=2 --file=/etc/
```

All files and their directory structures are preserved in isolated and compressed backups located in */opt/memento*.  At certain time intervals, gomemento will enforce an integriy check on all files previously index by the above commands.  If a change as been made or the file has been deleted, gomemento will take a difference(in the case of a text file) and overwrite the changed file.  Following these set of actions, an alert will be posted to the respective webserver and it will be logged to */opt/memento/logs*.

Currently there is not support for following symlinks, however this is intentional for now because user error can lead to the entire filesystem being index due to the recursive nature of the backup functionality.  A maliscious adversary could easily point a symlink to '/'.

### Process Monitoring

Allows for process metadata to be checked and analyze for traces of implants, reverse shells, or otherwise malcontent.

**Process Check**
```
./gomemento --mode=4
```
In practice, gomemento collects metadata from the /proc directory such as binary symlink path, the user who spawned the process, and cwd of the process.  One example of a case that gomemento would alert on is if the symlink for the process reads as (deleted).  This indicates that the process is running within memory and has no presence on the filesystem besides the open files it interacts with.

If gomemento detected such a process the following measures would be taken:
- The processes memory would be dumped and uploaded to kaspesky
- The process would be stopped
- Alert would be posted to webserver and logged locally

### Network Monitoring

Allows for network metadata to be checked and analyzed against a rolling baseline of network connections.  *algorithm is still in development*

**Network Check**
```
./gomemento --mode=5
```
Each time the network check is ran, ongoing network connection metadata is checked and appended to */opt/memento/networkprof.safe*.  The idea of this module is that a baseline of network connection would be developed overtime and can be used as a threshhold to spot new and maliscious connections.  

### User Monitoring

**User Login Check**
```
./gomemento --mode=6
```
When the user login check is ran, any remote logins in the past 30 seconds will generate an Alert and will be logged locally.

*Work is being done to monitor the activity of any user that successfully authenticates*

### Command Monitoring

**Analyze Commands**
```
./gomemento --mode=69
```
By identifying the history files of user's with the ability to login, their command history can be analyzed against a long list of regex patterns.  In current development the balance of precision vs. recall has not been properly finished.  The result is a long list of false positives, however development is being made to avoid this.

If a supposedly maliscious command is found then an alert is generated and logged.

### Service Monitoring

**Service baseline and check**
```
./gomemento --mode=13
```
In an attempt to uncover impact and persistence techniques by maliscious adversaries, an ongoing index of services and their respective states are checked and analyzed against an established baseline.

If there is a mismatch of states or another unknown service has been found, steps will be taken to return to the baseline and an alert will be generated and logged.

### Permission Monitoring

**Permission check and restore**
```
./gomemento --mode=12
```

**File system checks**
The compromise of various system files and the directories that house them can lead to compromise of the system they reside in.  An example of this is poorly configured permissions on the file */etc/shadow* or the file */etc/passwd* both of which are used to managing users.  An adversary may also choose to lower the permissions of these files in order to gain persistence or extract passwords.

To prevent this, an array of system files like the above are checked against known permissions.  If there is a discrepancy, the permissions of the file are corrected and an Alert is generated and logged.

**User checks**
In addition to file system checks, the integrity of the /etc/passwd file is checked to ensure that the root user has the uid and gid 0.  It also ensures that no other user has the uid and gid 0.  

**File System ACL**
*Work is being done to develop automatic ACL generation and file access checks*


### Self-Protection Deception Mechanisms

When gomemento is installed into a system, it makes use of the directory */opt/memento* which is maintained by the program over its lifecycle.

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

