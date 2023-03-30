package common

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/M00NLIG7/go-sigma-rule-engine"
)

// AuditEvent represents an Audit log event
type AuditEvent struct {
	Type string
	Data map[string]string
}

// Keywords returns the keywords for an AuditEvent
func (e AuditEvent) Keywords() ([]string, bool) {
	keywords := []string{e.Type}
	for k := range e.Data {
		keywords = append(keywords, k)
	}
	return keywords, true
}

// Select returns the value of the given field for an AuditEvent
func (e AuditEvent) Select(name string) (interface{}, bool) {
	if name == "type" {
		return e.Type, true
	}
	if value, ok := e.Data[name]; ok {
		return value, true
	}
	return nil, false
}

func ParseEventsAuditD(logFile string) ([]AuditEvent, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]AuditEvent, 0)
	scanner := bufio.NewScanner(file)
	event := make(map[string]string) // create a single map outside the loop
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "type=") {
			continue
		}

		parts := strings.Split(line, " ")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				event[kv[0]] = kv[1]
			}
		}

		if len(event) > 0 {
			events = append(events, AuditEvent{
				Type: event["type"],
				Data: event,
			})
			event = make(map[string]string) // clear the map for the next event
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

func ChopAuditD(rulePath string, outputType string) ([]string, error) {
	// Find the auditd file
	auditdLogPath, err := FindLogAuditD()
	if err != nil {
		return nil, fmt.Errorf("failed to find audit log: %v", err)
	}

	// Parse the auditd events
	events, err := ParseEventsAuditD(auditdLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit log: %v", err)
	}

	// Load the Sigma ruleset
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: []string{rulePath},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load ruleset: %v", err)
	}

	// Make a list of sigma.Results called results
	results := make([]sigma.Results, 0)
	eventresults := make([]string, 0)

	//TO DO AFTER BATH
	//make a var eventResults []string
	//make long custom strings with separators, reference json structure for stuff that is relevant to pull out and stuff inside string
	//use that instead of the sigma.results because its very limiting

	for _, event := range events {
		if result, match := ruleset.EvalAll(event); match {
			results = append(results, result)
			str := event.Data["AUID"] + "|-:-|" + event.Data["exe"] + "|-:-|" + event.Data["terminal"] + "|-:-|" + event.Data["pid"] + "|-:-|" + result[0].ID + "|-:-|" + result[0].Title
			eventresults = append(eventresults, str)
		}
	}

	fmt.Printf("Processed %d auditd events\n", len(events))
	return eventresults, nil

}
