package common

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/M00NLIG7/go-sigma-rule-engine"
)

// Representation of syslog event
type SyslogEvent struct {
	Facility  string
	Severity  string
	Message   string
	Timestamp string
}

/*
Keywords is a function required for a sigma.Event
to be passed to sigma.Rulset.EvalAll

Keywords returns a list of the different keys in our
SyslogEvent struct.
*/
func (e SyslogEvent) Keywords() ([]string, bool) {
	return []string{e.Facility, e.Severity, e.Message}, true
}

/*
Select is a function required for a sigma.Event
to be passed to sigma.Rulset.EvalAll

Select returns the value for a specified key
*/
func (e SyslogEvent) Select(name string) (interface{}, bool) {
	switch name {
	case "facility":
		return e.Facility, true
	case "severity":
		return e.Severity, true
	case "message":
		return e.Message, true
	default:
		return nil, false
	}
}

/*
ParseEvents interprets and parses the log file
and builds a slice of SyslogEvent structs
*/
func ParseEventsSyslog(logFile string) ([]SyslogEvent, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]SyslogEvent, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		r := regexp.MustCompile(`^([a-zA-Z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)

		matches := r.FindStringSubmatch(line)

		if matches == nil {
			fmt.Println("Failed to match timestamp")
		}

		timestamp := matches[1]

		parts := strings.SplitN(line, " ", 5)
		if len(parts) != 5 {
			continue
		}

		facility := strings.TrimSuffix(parts[0], ":")
		severity := parts[1]
		message := strings.TrimSpace(parts[4])
		events = append(events, SyslogEvent{
			Facility:  facility,
			Severity:  severity,
			Message:   message,
			Timestamp: timestamp,
		})
	}
	return events, nil
}

func ChopSyslog(rulePath string, outputType string) []string {
	// Find the syslog file
	syslogPath := FindLogSyslog()

	// Parse the syslog events
	events, err := ParseEventsSyslog(syslogPath)
	if err != nil {
		log.Fatalf("Failed to parse events: %v", err)
	}

	// Load the Sigma ruleset
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: []string{rulePath},
	})
	if err != nil {
		log.Fatalf("Failed to load ruleset: %v", err)
	}

	// Make a list of sigma.Results called results
	results := make([]sigma.Results, 0)
	eventResults := make([]string, 0)

	for _, event := range events {
		if result, match := ruleset.EvalAll(event); match {
			results = append(results, result)
			str := event.Message + "|-:-|" + result[0].ID + "|-:-|" + result[0].Title
			eventResults = append(eventResults, str)
		}
	}

	fmt.Printf("Processed %d syslog events\n", len(events))
	return eventResults
}
