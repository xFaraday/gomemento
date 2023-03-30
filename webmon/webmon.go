package webmon

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

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
	SigmaRules  = "https://transfer.sh/mvgq2e/sigma-0.21.zip"
	yaraRules   = "/opt/memento/rules.yar"
)

func TestHeartBeat() (err error) {

	m := Beat{IP: GetIP()}
	jsonStr, err := json.Marshal(m)
	if err != nil {
		zap.S().Warn(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	bodyReader := bytes.NewReader(jsonStr)

	requestURL := fmt.Sprintf("%v/api/v1/common/heartbeat", ssIP)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		zap.S().Warn(err)
	}

	req.Header.Set("User-Agent", ssUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		zap.S().Error(err)
		return err
	} else {
		if resp.StatusCode != http.StatusOK {
			zap.S().Error("Unexpected status code %d\n", resp.StatusCode)
			return errors.New("Unexpected status code")
		}
	}

	defer resp.Body.Close()
	return nil

}

func CheckEndpoint() bool {
	url := ssIP

	if !strings.Contains(url, "http") {
		zap.S().Warn("No http in URL, skipping posts: ", url)
		return false
	}

	err := TestHeartBeat()
	if err != nil {
		zap.S().Error("Error checking heartbeat:", err)
		return false
	}

	return true
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

func HeartBeat() (err error) {
	runRequest := CheckEndpoint()
	if runRequest == false {
		return nil
	}
	//ssUserAgent := "nestler-code"

	m := Beat{IP: GetIP()}
	jsonStr, err := json.Marshal(m)
	if err != nil {
		zap.S().Warn(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	bodyReader := bytes.NewReader(jsonStr)

	requestURL := fmt.Sprintf("%v/api/v1/common/heartbeat", ssIP)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		zap.S().Warn(err)
	}

	req.Header.Set("User-Agent", ssUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		zap.S().Error(err)
		return err
	} else {
		// data, _ := ioutil.ReadAll(resp.Body)
		// println(string(data))
	}

	defer resp.Body.Close()
	return nil

}

func IncidentAlert(alert alertmon.Alert) (err error) {
	runRequest := CheckEndpoint()
	if !runRequest {
		return nil
	}

	jsonStr, err := json.Marshal(alert)
	if err != nil {
		zap.S().Warn(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	bodyReader := bytes.NewReader(jsonStr)

	requestURL := fmt.Sprintf("%v/api/v1/common/incidentalert", ssIP)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		zap.S().Warn(err)
	}

	req.Header.Set("User-Agent", ssUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		zap.S().Error(err)
		return err
	} else {
		// data, _ := ioutil.ReadAll(resp.Body)
		// println(string(data))
	}

	defer resp.Body.Close()
	return nil
}

func DirSanityCheckSigma() {
	//check if the homedir directory exists
	if _, err := os.Stat("/opt/memento"); os.IsNotExist(err) {
		os.Mkdir("/opt/memento", 0700)
	}
	//check if the dirforbackups directory exists
	if _, err := os.Stat("/opt/memento/sigma"); os.IsNotExist(err) {
		os.Mkdir("/opt/memento/sigma", 0700)
	}
}

func GetSigmaRules() bool {
	DirSanityCheckSigma()
	// Create a new HTTPS client with the default settings.
	client := &http.Client{}

	// Create a new HTTPS request.
	req, err := http.NewRequest("GET", SigmaRules, nil)
	if err != nil {
		return false
	}

	// Set the headers for the request if needed.
	// req.Header.Set("HeaderName", "HeaderValue")

	// Make the HTTPS request.
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Create the output file.
	out, err := os.Create("/opt/memento/sigma/sigma.zip")
	if err != nil {
		return false
	}
	defer out.Close()

	// Copy the response body to the output file.
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return false
	}

	return true
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
