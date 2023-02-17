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
	} `json:"Apis"`
}

const CONFIG_LOC string = "/opt/memento/config.json"

func RetrieveConfig() {

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

func MakeConfig(API string, IPofServ string, UA string) {
	/*config := Configuration{
		Apis: {
			Kaspersky: {
				APIKey: API,
			},
			SerialScripter: {
				IP:        IPofServ,
				UserAgent: UA,
		},
	}*/
	config := &Configuration{}
	config.Apis.Kaspersky.APIKey = API
	config.Apis.SerialScripter.IP = IPofServ
	config.Apis.SerialScripter.UserAgent = UA
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
