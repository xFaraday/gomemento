package firewallmon

import (
	"fmt"
	"os/exec"
	"strings"
)

type FirewallRule struct {
	Chain   string
	RuleNum int
	Packets int64
	Bytes   int64
	Target  string
	Proto   string
	In      string
	Out     string
	Source  string
	Dest    string
}

func main() {
	// Run iptables command to retrieve firewall information
	cmd := exec.Command("iptables", "-L", "-n", "-v")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Parse output and store in struct
	firewallRules := parseFirewallOutput(strings.TrimSpace(string(output)))

	// Print results
	fmt.Println("Firewall information:")
	for _, rule := range firewallRules {
		fmt.Printf("%+v\n", rule)
	}
}

// Parse output of iptables command and store in struct
func parseFirewallOutput(output string) []FirewallRule {
	var firewallRules []FirewallRule
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "target") {
			// Skip header rows
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			// Skip malformed rows
			continue
		}

		ruleNum := 0
		packets := int64(0)
		bytes := int64(0)

		fmt.Sscanf(fields[0], "%d", &ruleNum)
		fmt.Sscanf(fields[1], "%d", &packets)
		fmt.Sscanf(fields[2], "%d", &bytes)

		firewallRules = append(firewallRules, FirewallRule{
			Chain:   fields[ChainIndex(fields)],
			RuleNum: ruleNum,
			Packets: packets,
			Bytes:   bytes,
			Target:  fields[TargetIndex(fields)],
			Proto:   fields[ProtoIndex(fields)],
			In:      fields[InIndex(fields)],
			Out:     fields[OutIndex(fields)],
			Source:  fields[SourceIndex(fields)],
			Dest:    fields[DestIndex(fields)],
		})
	}

	return firewallRules
}

// Index of chain field in iptables output
func ChainIndex(fields []string) int {
	for i, field := range fields {
		if field == "chain" || field == "Chain" {
			return i + 1
		}
	}
	return -1
}

// Index of target field in iptables output
func TargetIndex(fields []string) int {
	for i, field := range fields {
		if field == "target" || field == "Target" {
			return i + 1
		}
	}
	return -1
}

// Index of protocol field in iptables output
func ProtoIndex(fields []string) int {
	for i, field := range fields {
		if field == "prot" || field == "Proto" {
			return i + 1
		}
	}
	return -1
}

// Index of in interface field in iptables output
func InIndex(fields []string) int {
	for i, field := range fields {
		if field == "in" || field == "In" {
			return i + 1
		}
	}
	return -1
}

// Index of out interface field in iptables output
func OutIndex(fields []string) int {
	for i, field := range fields {
		if field == "out" || field == "Out" {
			return i + 1
		}
	}
	return -1
}

// Index of source IP address field in iptables output
func SourceIndex(fields []string) int {
	for i, field := range fields {
		if field == "source" || field == "Source" {
			return i + 1
		}
	}
	return -1
}

// Index of destination IP address field in iptables output
func DestIndex(fields []string) int {
	for i, field := range fields {
		if field == "destination" || field == "Dest" {
			return i + 1
		}
	}
	return -1
}
