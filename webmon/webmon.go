package webmon

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/xFaraday/gomemento/common"
)

type Beat struct {
	IP string
}

func PostToServ(jsonblob []uint8) {
	//post files to web server

	/*
		stuff to add to this POC

		-> Add way to poll webserver first, to check if server is up and reachable
		-> Add authentication mechanism, maybe just custom header?
		-> Add way to give json and file name to server
		--> Maybe to do it like this:
			Post filename, file path, and hostname | /api/v1/store
			Post json /api/v1/store/{filename+hostname}
	*/

	resp, err := http.Post("https://httpbin.org/post", "application/json", bytes.NewBuffer(jsonblob))

	if err != nil {
		panic(err)
	} else {
		println(resp.Status)
		println(resp.Request)
	}

	defer resp.Body.Close()
}

func HeartBeat() {
	m := Beat{IP: common.GetIP()}
	jsonStr, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	resp, err := http.Post("http://localhost:80/heartbeat", "application/json", bytes.NewBuffer(jsonStr))

	if err != nil {
		panic(err)
	} else {
		println(resp.Status)
	}

	defer resp.Body.Close()
}
