package common

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/zcalusic/sysinfo"
)

type finfo struct {
	Name string
	Size int64
	Time string
	Hash string
}

func ContainsInt(s []int, e int) bool {
	sort.Ints(s)
	i := sort.SearchInts(s, e)
	return i < len(s) && s[i] == e
}

func CheckFile(name string) finfo {
	fileInfo, err := os.Stat(name)
	if err != nil {
		i := finfo{
			Name: "",
			Size: 0,
			Time: "",
			Hash: "",
		}
		return i
	}
	println(name)
	if fileInfo.IsDir() {

		t := fileInfo.ModTime().String()
		b := fileInfo.Size()

		i := finfo{
			Name: name,
			Size: b,
			Time: t,
			Hash: "directory",
		}

		return i
	} else {
		f, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		if err != nil {
			if os.IsNotExist(err) {
				println("file not found:", fileInfo.Name())
			}
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			panic(err)
		}
		hash := h.Sum(nil)
		Enc := base64.StdEncoding.EncodeToString(hash)

		t := fileInfo.ModTime().String()
		b := fileInfo.Size()

		i := finfo{
			Name: name,
			Size: b,
			Time: t,
			Hash: Enc,
		}
		return i
	}
}

func FindTrueBinary(name string) string {
	dirgrab, err := os.ReadDir("/bin")
	if err != nil {
		panic(err)
	}
	for _, file := range dirgrab {
		if file.Name() == name {
			return "/bin/" + file.Name()
		}
	}
	dirgrab, err = os.ReadDir("/usr/bin")
	if err != nil {
		panic(err)
	}
	for _, file := range dirgrab {
		if file.Name() == name {
			return "/usr/bin/" + file.Name()
		}
	}
	dirgrab, err = os.ReadDir("/usr/local/bin")
	if err != nil {
		panic(err)
	}
	for _, file := range dirgrab {
		if file.Name() == name {
			return "/usr/local/bin/" + file.Name()
		}
	}
	dirgrab, err = os.ReadDir("/sbin")
	if err != nil {
		panic(err)
	}
	for _, file := range dirgrab {
		if file.Name() == name {
			return "/sbin/" + file.Name()
		}
	}
	return ""
}

func Compress(in io.Reader, out io.Writer) error {
	enc, err := zstd.NewWriter(out)
	if err != nil {
		return err
	}
	//gets data from in and writes it to enc, which is out
	_, err = io.Copy(enc, in)
	if err != nil {
		enc.Close()
		return err
	}
	return enc.Close()
}

func Decompress(in io.Reader, out io.Writer) error {
	d, err := zstd.NewReader(in)
	if err != nil {
		return err
	}
	defer d.Close()

	// Copy content...
	_, err = io.Copy(out, d)
	return err
}

func GetHistFile(username string, shellname string, homedir string) string {
	// for the future, refernce the $HISTFILE variable for each users env
	switch {
	case strings.Contains(shellname, "bash") || strings.Contains(shellname, "sh"):
		shellpathfull := homedir + "/.bash_history"
		return shellpathfull
	case strings.Contains(shellname, "ash"):
		shellpathfull := homedir + "/.ash_history"
		return shellpathfull
	case strings.Contains(shellname, "zsh"):
		shellpathfull := homedir + "/.zsh_history"
		return shellpathfull
	case strings.Contains(shellname, "fish"):
		shellpathfull := homedir + "/.local/share/fish/fish_history"
		return shellpathfull
	}
	return "shell not found"
}

func GetShell() string {
	// TODO: Implement error handling for exec.Command
	shellBytes, _ := exec.Command("bash", "-c", "echo $0").Output()
	return string(shellBytes)
}

func GetHomeDir() string {
	homeDirBytes, _ := exec.Command("bash", "-c", "echo $HOME").Output()
	return string(homeDirBytes)
}

func OpenFile(file string) []string {
	var s []string
	stats := CheckFile(file)
	if stats.Size != 0 {
		f, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		// remember to close the file at the end of the program
		defer f.Close()

		// read the file line by line using scanner
		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			// do something with a line
			s = append(s, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			panic(err)
		}

		//print slice with contents of file
		//for _, str := range s {
		//	println(str)
		//}
	}
	return s
}

func IsHumanReadable(file string) bool {
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	b := make([]byte, 4)
	_, err = f.Read(b)
	if err != nil {
		panic(err)
	}
	// text := string(b)
	// 60 = E, 76 = L, 70 = F
	// ELF check
	if (b[1] == 69) && (b[2] == 76) && (b[3] == 70) {
		return false
	}
	// check for crazy ass bytes in file
	// 0x00 = null byte
	// 0x01 = start of heading
	// 0x02 = start of text

	r := bufio.NewReader(f)
	for {
		if c, _, err := r.ReadRune(); err != nil {
			if err == io.EOF {
				break
			}
		} else {
			if string(c) == "\x00" || string(c) == "\x01" || string(c) == "\x02" {
				return false
			}
		}
	}
	return true
}

// Use to interact with Kaspersky API
func UploadFile(url string, file *os.File, apikey string) error {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	// Create a new form file using the file's name and add it to the multipart writer
	fw, err := w.CreateFormFile("file", file.Name())
	if err != nil {
		return err
	}

	// Copy the file's contents to the form file
	_, err = io.Copy(fw, file)
	if err != nil {
		return err
	}

	// Close the multipart writer to finalize the form data
	w.Close()

	// Create a new HTTP request with the multipart/form-data as the request body
	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		return err
	}

	// Set the Content-Type header to indicate that the request body is a multipart/form-data
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Add("x-api-key", apikey)

	// Send the HTTP request and get the response
	client := http.DefaultClient
	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return nil
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
			output += getHunk(lines1, lines2, start1, start2, length)
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

func getHunk(lines1, lines2 []string, start1, start2, length int) string {
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

func GetCurrentTime() string {
	t := time.Now()
	return t.Format("2006-01-02 15:04:05")
}

func GetDistroVendor() string {
	var SystemInfo sysinfo.SysInfo
	SystemInfo.GetSysInfo()
	return SystemInfo.OS.Vendor
}

func FindLogAuditD() (string, error) {
	// Open the auditd.conf file
	file, err := os.Open("/etc/audit/auditd.conf")
	if err != nil {
		return "", fmt.Errorf("failed to open auditd.conf: %v", err)
	}
	defer file.Close()

	// Scan the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Look for the log_file option
		if strings.HasPrefix(line, "log_file ") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "log_file = "))
			return path, nil
		}
	}

	// If the log_file option is not found, return an error
	return "", fmt.Errorf("log_file option not found in auditd.conf")
}

func FindLogSyslog() string {
	pathtocheck := []string{"/var/log/syslog", "/var/log/messages"}
	for _, path := range pathtocheck {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "not found"
}

func FindLog() []string {
	logs := []string{}
	// Find the auditd log file
	if auditdLog, err := FindLogAuditD(); err == nil {
		logs = append(logs, auditdLog)
	}
	// Find the syslog file
	logs = append(logs, FindLogSyslog())
	return logs
}

func UnzipFile(filepath string, directorytostore string) {
	r, err := zip.OpenReader(filepath)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer r.Close()

	// Iterate through the files in the archive.
	for _, f := range r.File {
		fmt.Printf("Extracting %s\n", f.Name)

		// If the entry is a directory, create it.
		if f.FileInfo().IsDir() {
			err := os.MkdirAll(path.Join(directorytostore, f.Name), os.ModePerm)
			if err != nil {
				fmt.Println(err)
				return
			}
			continue
		}

		// Open the file inside the archive.
		rc, err := f.Open()
		if err != nil {
			fmt.Println(err)
			return
		}
		defer rc.Close()

		// Create the output file.
		outPath := path.Join(directorytostore, f.Name)
		outFile, err := os.Create(outPath)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer outFile.Close()

		// Copy the contents of the file to the output file.
		_, err = io.Copy(outFile, rc)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	fmt.Println("Extraction complete.")
}
