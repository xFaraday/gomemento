package common

import (
	"fmt"
	"log"

	"github.com/M00NLIG7/go-sigma-rule-engine"
	"github.com/coreos/go-systemd/v22/sdjournal"
)

type JournaldEvent struct {
	Message   string
	Timestamp uint64
}

func (e JournaldEvent) Keywords() ([]string, bool) {
	return []string{e.Message}, true
}

func (e JournaldEvent) Select(name string) (interface{}, bool) {
	switch name {
	case "message":
		return e.Message, true
	default:
		return nil, false
	}
}

func ParseEventsJournalD() []JournaldEvent {
	j, err := sdjournal.NewJournal()

	if err != nil {
		log.Fatal("Failed to open journal:", err)
	}
	defer j.Close()

	err = j.SeekHead()
	if err != nil {
		log.Fatal("Failed to seek to end of journal:", err)
	}

	events := make([]JournaldEvent, 0)

	for {
		n, err := j.Next()
		if err != nil {
			log.Fatal("Failed to read journal entry:", err)
		}
		if n == 0 {
			break
		}
		message, _ := j.GetData("MESSAGE")
		timestamp, _ := j.GetRealtimeUsec()

		events = append(events, JournaldEvent{
			Message:   message,
			Timestamp: timestamp,
		})

		if err != nil {
			log.Fatal("Failed to get journal entry data:", err)
		}
		// Do something with the journal entry data...
	}

	return events
}

func ChopJournalD(rulePath string) ([]string, error) {
	events := ParseEventsJournalD()

	path := [1]string{rulePath}
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: path[:],
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to load ruleset: %v", err)
	}

	results := make([]sigma.Results, 0)
	eventResults := make([]string, 0)

	for _, event := range events {
		if result, match := ruleset.EvalAll(event); match {
			results = append(results, result)
			str := event.Message + "|-:-|" + result[0].ID + "|-:-|" + result[0].Title
			eventResults = append(eventResults, str)
		}
	}
	fmt.Printf("Processed %d journald events\n", len(events))
	return eventResults, nil
}
