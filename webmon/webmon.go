package webmon

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/xFaraday/gomemento/alertmon"
	"github.com/xFaraday/gomemento/config"
)

type Beat struct {
	IP string
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

func HeartBeat() {
	ssUserAgent := config.GetSerialScripterUserAgent()

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

	requestURL := fmt.Sprintf("https://10.123.80.115:10000/api/v1/common/heartbeat")
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
	ssUserAgent := config.GetSerialScripterUserAgent()

	jsonStr, err := json.Marshal(alert)
	if err != nil {
		println("error")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	bodyReader := bytes.NewReader(jsonStr)

	requestURL := fmt.Sprintf("https://10.123.80.115:10000/api/v1/common/incidentalert")
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
