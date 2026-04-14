package utils

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	minPort = uint64(1)     // port 0 is reserved and rejected
	maxPort = uint64(65535) // highest valid port number
)

// ParsePorts parses a port expression and returns the deduplicated, sorted
// list of port numbers it represents. Accepted formats:
//
//   - Single port:  "80"
//   - Range:        "1-1024"
//   - Comma list:   "80,443,8080"
//   - Mixed:        "1-1024,8080,9000"
//
// Port 0 and ports above 65535 are rejected. A reversed range (e.g. "1024-1")
// is rejected with a descriptive error. Duplicate ports are silently removed
// from the output.
func ParsePorts(input string) ([]uint16, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("ParsePorts: input is empty")
	}

	seen := make(map[uint16]struct{})

	for _, token := range strings.Split(input, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("ParsePorts: empty token in %q (trailing comma?)", input)
		}

		if strings.Contains(token, "-") {
			ports, err := parsePortRange(token)
			if err != nil {
				return nil, err
			}
			for _, p := range ports {
				seen[p] = struct{}{}
			}
		} else {
			p, err := parseSinglePort(token)
			if err != nil {
				return nil, err
			}
			seen[p] = struct{}{}
		}
	}

	result := make([]uint16, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

// parseSinglePort validates and converts a single port number string.
func parseSinglePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("ParsePorts: %q is not a valid port number", s)
	}
	if n < minPort || n > maxPort {
		return 0, fmt.Errorf("ParsePorts: port %d is out of valid range [%d, %d]", n, minPort, maxPort)
	}
	return uint16(n), nil
}

// parsePortRange expands a "start-end" token into the slice of ports it covers.
func parsePortRange(s string) ([]uint16, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("ParsePorts: invalid range token %q", s)
	}

	start, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil || start < minPort || start > maxPort {
		return nil, fmt.Errorf("ParsePorts: invalid range start %q in %q", parts[0], s)
	}

	end, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil || end < minPort || end > maxPort {
		return nil, fmt.Errorf("ParsePorts: invalid range end %q in %q", parts[1], s)
	}

	if start > end {
		return nil, fmt.Errorf("ParsePorts: range is reversed — start %d > end %d in %q", start, end, s)
	}

	ports := make([]uint16, 0, int(end-start+1))
	for i := start; i <= end; i++ {
		ports = append(ports, uint16(i))
	}
	return ports, nil
}
