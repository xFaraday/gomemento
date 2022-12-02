package alertmon

type Incident struct {
	Name     string
	User     string
	Process  string
	RemoteIP string
	Cmd      string
}

type Alert struct {
	Host     string
	Incident Incident
}
