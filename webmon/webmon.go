package webmon

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/config"
	"go.uber.org/zap"
)

type Beat struct {
	IP string
}

var (
	ssUserAgent = config.GetSerialScripterUserAgent()
	ssIP        = config.GetSerialScripterIP()
	SigmaRules  = "https://github.com/SigmaHQ/sigma/archive/refs/tags/0.21.zip"
	yaraRules   = "/opt/memento/rules.yar"
)

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

func HeartBeat() {
	m := Beat{IP: GetIP()}
	jsonStr, err := json.Marshal(m)
	if err != nil {
		println("error")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	bodyReader := bytes.NewReader(jsonStr)

	requestURL := fmt.Sprintf(ssIP)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		println("error")
	}

	req.Header.Set("User-Agent", ssUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		println("error")
	} else {
		//data, _ := ioutil.ReadAll(resp.Body)
		//println(string(data))
	}

	defer resp.Body.Close()

}

func IncidentAlert(alert alertmon.Alert) {

	jsonStr, err := json.Marshal(alert)
	if err != nil {
		println("error")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	bodyReader := bytes.NewReader(jsonStr)

	requestURL := fmt.Sprintf(ssIP)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		println("error")
	}

	req.Header.Set("User-Agent", ssUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		println("error")
	} else {
		data, _ := ioutil.ReadAll(resp.Body)
		println(string(data))
	}

	defer resp.Body.Close()
}

func GetSigmaRules() {
	resp, err := http.Get(SigmaRules)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	out, err := os.Create("sigma.zip")
	if err != nil {
		panic(err)
	}

	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		panic(err)
	}
}

func GetYaraRules() {
	//check if rules.yar already exists
	if _, err := os.Stat(yaraRules); err == nil {
		return
	} else {
		webLocation := config.GetYaraRules()
		resp, err := http.Get(webLocation)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		out, err := os.Create(yaraRules)
		if err != nil {
			panic(err)
		}

		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			panic(err)
		}

		zap.S().Info("[+] Downloaded Yara Rules from: " + webLocation)
	}
}
