package filemon

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/common"
	"github.com/xFaraday/gomemento/hookmon"
	"github.com/xFaraday/gomemento/webmon"
	"go.uber.org/zap"
)

var (
	dirforbackups = "/opt/memento/backups"
	indexfile     = "/opt/memento/index.safe"
)

/*
	Add edge case check in VerifyFiles() to see if the file has been deleted
		- if so, unzip compressed file back to original spot
		- if not, proceed as normal
*/

func VerifyFiles() {
	safestats := common.CheckFile(indexfile)
	if safestats.Size != 0 {
		f := common.OpenFile(indexfile)
		for _, indexstr := range f {
			var m = make(map[int]string)
			splittysplit := strings.Split(indexstr, "-:-")

			//original file path
			m[0] = splittysplit[0]
			//file store name
			m[1] = splittysplit[1]
			//backup name
			m[2] = splittysplit[2]
			//mod date
			m[3] = splittysplit[3]
			//hash
			m[4] = splittysplit[4]

			if _, err := os.Stat(m[0]); err != nil {
				if os.IsNotExist(err) {
					CompressedBackup := dirforbackups + m[2]
					tmpcmpfile, _ := os.Create("/tmp/" + m[1] + ".tmp")
					RevertCompressedFile, _ := os.Open(CompressedBackup)
					common.Decompress(RevertCompressedFile, tmpcmpfile)
					oGfile, _ := os.Create(m[0])

					zap.S().Warn("File:" + m[0] + " has been deleted, restoring from backup")

					var inc alertmon.Incident = alertmon.Incident{
						Name:     "FILE DELETED: " + m[0],
						User:     "",
						Process:  "", //maybe fill this later?
						RemoteIP: "",
						Cmd:      "",
					}

					IP := webmon.GetIP()
					hostname := "host-" + strings.Split(IP, ".")[3]

					var alert alertmon.Alert = alertmon.Alert{
						Host:     hostname,
						Incident: inc,
					}
					if err := webmon.IncidentAlert(alert); err != nil {
						zap.S().Error(err)
					}

					OverWriteModifiedFile(oGfile.Name(), tmpcmpfile.Name())
					os.Remove(tmpcmpfile.Name())
				} else {
					panic(err)
				}
			}

			fCurrentStats := common.CheckFile(m[0])
			if fCurrentStats.Hash != m[4] {
				CompressedBackup := dirforbackups + m[2]
				//get uncompressed version
				tmpcmpfile, _ := os.Create("/tmp/" + m[1] + ".tmp")
				RevertCompressedFile, _ := os.Open(CompressedBackup)

				common.Decompress(RevertCompressedFile, tmpcmpfile)

				//FIGURE OUT IF TXT FILE THEN TRY TO GET DIFF
				diff, _ := GetDiff(m[0], tmpcmpfile.Name())
				if diff == "binary, no diff" {
					zap.S().Warn("File:" + m[0] + " has been modified, but is binary, no diff available")
				} else {
					zlog := zap.S().With(
						"file", m[0],
						"diff", diff,
					)
					zlog.Warn("File has been modified, diff below")
				}

				var inc alertmon.Incident = alertmon.Incident{
					Name:     "FILE MODIFIED: " + m[0],
					User:     "",
					Process:  "", //maybe fill this later?
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

				//actions once the difference is logged
				OverWriteModifiedFile(m[0], tmpcmpfile.Name())
				os.Remove(tmpcmpfile.Name())
				zap.S().Info("File: " + m[0] + " has been restored to original state")
			}
		}
	}
}

/*
	Improve Compress and Decompress later:
		-> Add dictionary method for better compression
		-> Better manage encoders and decoders
*/

func BackFile(storename string, file string /*, mode int*/) {
	OriginFile, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	CompressedFile, err := os.Create(dirforbackups + storename)
	if err != nil {
		panic(err)
	}

	PointData := bufio.NewReader(OriginFile)
	common.Compress(PointData, CompressedFile)

	defer OriginFile.Close()
	defer CompressedFile.Close()
}

func ExistsInIndex(indexfile string, file string) string {
	strlist := common.OpenFile(indexfile)

	for _, indexstr := range strlist {
		splittysplit := strings.Split(indexstr, "-:-")
		if splittysplit[0] == file {
			println("exact file exists in index")
			return "newback"
		}
	}
	return "new"
}

func OverWriteModifiedFile(OriginalPath string, FileBackup string) {
	//delete original
	//call modified BackFile function
	os.Remove(OriginalPath)
	BytesToCopy, _ := os.Open(FileBackup)
	NewFile, _ := os.Create(OriginalPath)
	if _, err := io.Copy(NewFile, BytesToCopy); err != nil {
		panic(err)
	}
	defer BytesToCopy.Close()
	defer NewFile.Close()
}

func OverWriteBackup(storename string, file string) {
	f := common.OpenFile(indexfile)
	for _, indexstr := range f {
		var m = make(map[int]string)
		splittysplit := strings.Split(indexstr, "-:-")
		//original file path
		m[0] = splittysplit[0]
		//file backup name
		m[1] = splittysplit[2]
		if file == m[0] {
			os.Remove(dirforbackups + m[1])
			BackFile(m[1], file)
		}
	}
}

func BackDir(file string, overwrite bool) {
	fdir, _ := os.ReadDir(file)

	for _, f := range fdir {
		fpath := filepath.Join(file, f.Name())
		CreateRestorePoint(fpath, overwrite)
	}
}

func GenRandomName() string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]rune, 15)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func CreateRestorePoint(file string, overwrite bool) {
	stats := common.CheckFile(file)
	if stats.Size != 0 {
		/*
			Index file format:
			Simple ->
			fullpath-:-filename w/extension-:-CompressedBackupName-:-LastModTime-:-hash
			Ex:
			/opt/memento/index.safe-:-index.safe-:-ADZOPRJ13SMF.zst-:-2021-01-01 00:00:00-:-9pN02HFtrhT4EGw+SdIECoj0HV8PBLY8qkZjwaKGRvo=
		*/
		//indexstr := strings.Split(file, "/")
		if stats.Hash == "directory" {
			BackDir(file, overwrite)
		} else {
			strsplit := strings.Split(file, "/")
			storename := strsplit[len(strsplit)-1]

			// /etc/passwd-:-passwd.txt-:-some date-:-hash
			backname := GenRandomName() + ".zst"
			indexstr := file + "-:-" + storename + "-:-" + backname + "-:-" + stats.Time + "-:-" + string(stats.Hash) + "\n"
			newindextstr := []byte(indexstr)

			if _, err := os.Stat(indexfile); os.IsNotExist(err) {
				werr := ioutil.WriteFile(indexfile, newindextstr, 0644)
				if werr != nil {
					panic(werr)
				}

				BackFile(backname, file)
			} else {
				checkresult := ExistsInIndex(indexfile, file)

				switch checkresult {
				case "newback":
					if overwrite {
						zap.S().Info("Overwriting backup for file: " + file)
						//println("Overwriting previous backup of :" + file)
						OverWriteBackup(storename, file)
					} else {
						zap.S().Error("Skipping backup for file, overwrite set to n: " + file)
						println("overwrite is set to n, exiting")
						os.Exit(0)
					}
				case "new":
					appendfile, err := os.OpenFile(indexfile, os.O_APPEND|os.O_WRONLY, 0644)
					if err != nil {
						panic(err)
					}
					appendfile.WriteString(indexstr)
					defer appendfile.Close()

					zap.S().Info("File: " + file + " has been backed up")
					//println("BACKING UP FILE: " + file)

					BackFile(backname, file)
					//PostToServ(m)
				}
			}
		}
	} else {
		println("Nothing to backup :(, file is empty")
	}
}

func RestoreController(file string, overwrite bool) {
	hookmon.VerifiyRunIntegrity()
	//filecheckstats := CheckFile(file)
	//if filecheckstats.size != 0 {
	CreateRestorePoint(file, overwrite)
	//} else {
	//	println("Nothing to backup (ツ)_/¯")
	//}
}

func JumpStart() {
	hookmon.VerifiyRunIntegrity()
	//files := config.GetFilesForBackup()

	//for _, file := range files {
	//CreateRestorePoint(file, true)
	//	println("Backing up file: " + file)
	//}

}


func GetDiff(file1, file2 string) (string, error) {
	// Read the contents of both files into memory
	content1, err := ioutil.ReadFile(file1)
	if err != nil {
		return "", err
	}
	content2, err := ioutil.ReadFile(file2)
	if err != nil {
		return "", err
	}

	// Split the file contents into lines
	lines1 := splitLines(string(content1))
	lines2 := splitLines(string(content2))

	// Perform the diff
	var output string
	var start1, start2, length int
	for i, j := 0, 0; i < len(lines1) || j < len(lines2); {
		if i < len(lines1) && j < len(lines2) && lines1[i] == lines2[j] {
			// Lines are the same
			i++
			j++
		} else {
			// Lines are different
			start1 = i
			start2 = j
			for i < len(lines1) && j < len(lines2) && lines1[i] != lines2[j] {
				i++
				j++
			}
			length = i - start1
			if i < len(lines1) || j < len(lines2) {
				// There is another hunk after this one
				length = min(length, min(len(lines1)-start1, len(lines2)-start2))
			}
			output += printHunk(lines1, lines2, start1, start2, length)
		}
	}

	return output, nil
}

func splitLines(text string) []string {
	var lines []string
	start := 0
	for i, c := range text {
		if c == '\n' {
			lines = append(lines, text[start:i])
			start = i + 1
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

func printHunk(lines1, lines2 []string, start1, start2, length int) string {
	var output string
	output += fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", start1+1, length, start2+1, length)
	for i := start1; i < start1+length; i++ {
		output += fmt.Sprintf("-%s\n", lines1[i])
	}
	for i := start2; i < start2+length; i++ {
		output += fmt.Sprintf("+%s\n", lines2[i])
	}
	return output
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
