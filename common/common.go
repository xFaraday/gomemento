package common

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"

	"github.com/klauspost/compress/zstd"
)

type finfo struct {
	name string
	size int64
	time string
	hash string
}

func CheckFile(name string) finfo {
	fileInfo, err := os.Stat(name)
	if err != nil {
		panic(err)
	}
	println(name)
	if fileInfo.IsDir() {

		t := fileInfo.ModTime().String()
		b := fileInfo.Size()

		i := finfo{
			name: name,
			size: b,
			time: t,
			hash: "directory",
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
			name: name,
			size: b,
			time: t,
			hash: Enc,
		}
		return i
	}
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
	case shellname == "bash" || shellname == "sh":
		shellpathfull := homedir + "/.bash_history"
		return shellpathfull
	case shellname == "ash":
		shellpathfull := homedir + "/.ash_history"
		return shellpathfull
	case shellname == "zsh":
		shellpathfull := homedir + "/.zsh_history"
		return shellpathfull
	case shellname == "fish":
		shellpathfull := homedir + "/.local/share/fish/fish_history"
		return shellpathfull
	}
	return "shell not found"
}

func OpenFile(file string) []string {
	var s []string
	stats := CheckFile(file)
	if stats.size != 0 {
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

func GetIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ipaddr := localAddr.IP
	return ipaddr.String()
}
