package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

/*

Majority of code written by Hunter Pittman. https://github.com/Hunter-Pittman

*/

type Configuration struct {
	Apis struct {
		Kaspersky struct {
			APIKey string `json:"APIKey"`
		} `json:"Kaspersky"`
		SerialScripter struct {
			IP        string `json:"IP"`
			UserAgent string `json:"UserAgent"`
		} `json:"SerialScripter"`
		Yara struct {
			Rules string `json:"Rules"`
		} `json:"Yara"`
		Sigma struct {
			ZipLocation string `json:"ZipLocation"`
		} `json:"Sigma"`
	} `json:"Apis"`
}

const CONFIG_LOC string = "/opt/memento/config.json"

func RetrieveConfig() {

}

func GetSigmaURL() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.Apis.Sigma.ZipLocation
}

func GetKaperskyKey() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.Apis.Kaspersky.APIKey
}

func GetSerialScripterUserAgent() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.Apis.SerialScripter.UserAgent
}

func GetSerialScripterIP() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.Apis.SerialScripter.IP
}

func GetYaraRules() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.Apis.Yara.Rules
}

func MakeConfig(API string, IPofServ string, UA string, YaraRules string, sigmaurl string) {
	/*config := Configuration{
		Apis: {
			Kaspersky: {
				APIKey: API,
			},
			SerialScripter: {
				IP:        IPofServ,
				UserAgent: UA,
			},
			Yara: {
				Rules: YaraRules,
			},
		}
	}*/
	config := &Configuration{}
	config.Apis.Kaspersky.APIKey = API
	config.Apis.SerialScripter.IP = IPofServ
	config.Apis.SerialScripter.UserAgent = UA
	config.Apis.Yara.Rules = YaraRules
	config.Apis.Sigma.ZipLocation = sigmaurl
	file, _ := json.MarshalIndent(config, "", " ")
	_ = ioutil.WriteFile(CONFIG_LOC, file, 0644)
}

/*
func GetYaraExePath() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.ExePaths.Yara
}
*/
