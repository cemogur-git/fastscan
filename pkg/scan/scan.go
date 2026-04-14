// Package scan provides TCP port-scanning algorithms for fastscan.
// Each algorithm implements the Scanner interface and is fully configurable
// through a ScanConfig value; no global state is used.
package scan

import (
	"context"
	"time"
)

// Default tuning values for ScanConfig. Chosen for a balance between speed
// and reliability on a typical LAN; tune for WAN or sensitive targets.
const (
	DefaultConcurrency = 1000
	DefaultTimeout     = 500 * time.Millisecond
	DefaultRateLimit   = 10_000 // packets per second
	DefaultRetryCount  = 0
)

// State represents the observed state of a scanned port.
type State int

const (
	// StateOpen indicates the port accepted a connection or replied to a probe.
	StateOpen State = iota
	// StateClosed indicates the port actively refused the connection (RST).
	StateClosed
	// StateFiltered indicates no response was received within the timeout.
	StateFiltered
)

// String returns the human-readable label for a port state.
// Implements fmt.Stringer so State values print as words, not integers,
// when formatted with %s, %v, or used in JSON marshalling.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// Result holds the outcome of scanning a single (IP, port) pair.
type Result struct {
	IP      string
	Port    uint16
	State   State
	Latency time.Duration
	Banner  string // populated in Faz 5; empty for connect-scan results
}

// ScanConfig carries the tuning parameters shared across all scan strategies.
// Construct one with NewScanConfig to get production-safe defaults, then
// override individual fields as needed.
type ScanConfig struct {
	// Concurrency is the maximum number of probes in flight at any time.
	// Must be > 0.
	Concurrency int
	// Timeout is the per-probe deadline. Must be > 0.
	Timeout time.Duration
	// RateLimit caps the number of probes dispatched per second.
	// 0 disables the cap (useful for localhost or controlled environments).
	RateLimit int
	// RetryCount is the number of additional attempts for a Filtered result.
	// 0 means a single attempt with no retry.
	RetryCount int
}

// NewScanConfig returns a ScanConfig populated with production-safe defaults.
// Callers may override individual fields after construction.
func NewScanConfig() ScanConfig {
	return ScanConfig{
		Concurrency: DefaultConcurrency,
		Timeout:     DefaultTimeout,
		RateLimit:   DefaultRateLimit,
		RetryCount:  DefaultRetryCount,
	}
}

// Scanner is the common interface implemented by every scan strategy.
// Config is embedded in the implementation rather than passed per-call so
// callers set tuning once at construction time.
// All implementations must be safe for concurrent use.
type Scanner interface {
	// Scan probes each (target, port) pair and streams Result values to the
	// returned channel. The channel is closed when all probes have completed
	// or ctx is cancelled. An error is returned only for fatal setup failures;
	// per-probe errors are encoded as StateFiltered Results.
	Scan(ctx context.Context, targets []string, ports []uint16) (<-chan Result, error)
}
