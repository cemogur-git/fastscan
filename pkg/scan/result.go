package scan

import (
	"fmt"
	"sync"
	"time"
)

// Aggregator collects Result values streamed through a channel and provides
// thread-safe access to the accumulated set. Construct one with NewAggregator,
// call Collect to drain a scan channel, then query Results, Summary, or
// FilterByState once collection is complete (or concurrently — both are safe).
type Aggregator struct {
	mu      sync.Mutex
	results []Result
	start   time.Time
	elapsed time.Duration
}

// NewAggregator returns an initialised, empty Aggregator ready for use.
func NewAggregator() *Aggregator {
	return &Aggregator{}
}

// Collect drains ch, appending every received Result to the internal slice.
// It blocks until ch is closed. The wall-clock duration between the first call
// and channel close is stored so Summary can report accurate elapsed time.
// Collect is not intended to be called concurrently from multiple goroutines;
// Results and FilterByState may safely be called while Collect is running.
func (a *Aggregator) Collect(ch <-chan Result) {
	a.mu.Lock()
	a.start = time.Now()
	a.mu.Unlock()

	for r := range ch {
		a.mu.Lock()
		a.results = append(a.results, r)
		a.mu.Unlock()
	}

	a.mu.Lock()
	a.elapsed = time.Since(a.start)
	a.mu.Unlock()
}

// Results returns a shallow copy of all collected results. Modifying the
// returned slice does not affect the Aggregator's internal state.
func (a *Aggregator) Results() []Result {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Result, len(a.results))
	copy(out, a.results)
	return out
}

// Summary returns a one-line human-readable description: the number of open
// ports, the total result count, and the elapsed collection time rounded to
// the nearest millisecond. If Collect has not been called yet, elapsed is 0s.
func (a *Aggregator) Summary() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	open := 0
	for _, r := range a.results {
		if r.State == StateOpen {
			open++
		}
	}

	// Use the stored elapsed time once Collect finishes; compute live elapsed
	// if Collect is still running (elapsed == 0 but start is set).
	elapsed := a.elapsed
	if elapsed == 0 && !a.start.IsZero() {
		elapsed = time.Since(a.start)
	}

	return fmt.Sprintf("open: %d / %d  elapsed: %s",
		open, len(a.results), elapsed.Round(time.Millisecond))
}

// FilterByState returns a new slice containing only the Results whose State
// matches state. The original result set is not modified.
// Returns nil when no results match (not an empty slice) to allow callers to
// distinguish "filter not applied yet" from "zero matches".
func (a *Aggregator) FilterByState(state State) []Result {
	a.mu.Lock()
	defer a.mu.Unlock()

	var out []Result
	for _, r := range a.results {
		if r.State == state {
			out = append(out, r)
		}
	}
	return out
}
