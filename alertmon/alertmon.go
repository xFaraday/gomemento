package alertmon

type Incident struct {
	Name        string
	CurrentTime string
	User        string
	Severity    string
	Payload     string
}

type Alert struct {
	Host     string
	Incident Incident
}
