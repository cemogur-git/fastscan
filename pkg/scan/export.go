package scan

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
)

// jsonRecord is the JSON wire representation of a single scan Result.
// A separate struct avoids polluting Result with json tags and lets us
// serialise State as a string rather than an integer.
type jsonRecord struct {
	IP        string  `json:"ip"`
	Port      uint16  `json:"port"`
	State     string  `json:"state"`
	Service   string  `json:"service,omitempty"`
	Banner    string  `json:"banner,omitempty"`
	LatencyMs float64 `json:"latency_ms"`
}

// csvHeader is the fixed header row written by ExportCSV.
var csvHeader = []string{"IP", "Port", "State", "Service", "Banner", "Latency"}

// ExportJSON encodes results as a JSON array and writes it to w.
// State is serialised as its string label (e.g. "open"), and Latency is
// expressed in milliseconds as a floating-point number.
// Returns a wrapped error if encoding or writing fails.
func ExportJSON(results []Result, w io.Writer) error {
	records := make([]jsonRecord, len(results))
	for i, r := range results {
		records[i] = jsonRecord{
			IP:        r.IP,
			Port:      r.Port,
			State:     r.State.String(),
			Service:   r.Service,
			Banner:    r.Banner,
			LatencyMs: float64(r.Latency.Microseconds()) / 1000.0,
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(records); err != nil {
		return fmt.Errorf("export json: encode: %w", err)
	}
	return nil
}

// ExportCSV writes results to w in RFC 4180 CSV format with a header row.
// Column order: IP, Port, State, Service, Banner, Latency.
// Latency is formatted as a Go duration string (e.g. "1.234ms").
// Returns a wrapped error if any write fails.
func ExportCSV(results []Result, w io.Writer) error {
	cw := csv.NewWriter(w)

	if err := cw.Write(csvHeader); err != nil {
		return fmt.Errorf("export csv: write header: %w", err)
	}

	for _, r := range results {
		record := []string{
			r.IP,
			fmt.Sprintf("%d", r.Port),
			r.State.String(),
			r.Service,
			r.Banner,
			r.Latency.String(),
		}
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("export csv: write record ip=%s port=%d: %w", r.IP, r.Port, err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("export csv: flush: %w", err)
	}
	return nil
}
