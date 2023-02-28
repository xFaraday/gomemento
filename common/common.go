package common

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
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
