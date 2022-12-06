package config

import (
	"encoding/json"
	"fmt"
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
