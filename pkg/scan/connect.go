package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// Option configures a ConnectScanner at construction time.
type Option func(*ConnectScanner)

// WithDialFunc overrides the TCP dial function used by ConnectScanner.
// Intended for unit testing — production code should use the default dialer.
func WithDialFunc(fn func(ctx context.Context, network, address string) (net.Conn, error)) Option {
	return func(s *ConnectScanner) { s.dialFunc = fn }
}

// ConnectScanner performs a full TCP three-way handshake (connect scan).
// It requires no elevated privileges and works on all platforms.
// Use SYNScanner (pkg/network) for stealth scanning without completing the handshake.
type ConnectScanner struct {
	cfg      ScanConfig
	dialFunc func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewConnectScanner constructs a ConnectScanner with the given configuration.
// Callers may pass Option values to override internal behaviour (e.g. for testing).
func NewConnectScanner(cfg ScanConfig, opts ...Option) *ConnectScanner {
	s := &ConnectScanner{
		cfg:      cfg,
		dialFunc: (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Scan implements Scanner. Each (target, port) pair is probed concurrently;
// the semaphore caps in-flight goroutines at cfg.Concurrency so the goroutine
// count stays bounded regardless of input size. If cfg.RateLimit > 0, probes
// are paced to at most cfg.RateLimit per second before the semaphore is acquired.
func (s *ConnectScanner) Scan(ctx context.Context, targets []string, ports []uint16) (<-chan Result, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("connect scan: target list is empty")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("connect scan: port list is empty")
	}

	results := make(chan Result, s.cfg.Concurrency)
	sem := semaphore.NewWeighted(int64(s.cfg.Concurrency))

	go func() {
		defer close(results)

		// Rate-limiting ticker: paces probe dispatch to cfg.RateLimit/s.
		// A nil channel blocks forever on receive, effectively disabling the gate.
		var ticker <-chan time.Time
		if s.cfg.RateLimit > 0 {
			t := time.NewTicker(time.Second / time.Duration(s.cfg.RateLimit))
			defer t.Stop()
			ticker = t.C
		}

		var wg sync.WaitGroup

	loop:
		for _, target := range targets {
			for _, port := range ports {
				// Rate-limit before acquiring the semaphore so we don't hold a
				// concurrency slot while waiting for the next tick.
				if ticker != nil {
					select {
					case <-ticker:
					case <-ctx.Done():
						break loop
					}
				}

				if err := sem.Acquire(ctx, 1); err != nil {
					// ctx cancelled; stop dispatching new probes.
					break loop
				}

				wg.Add(1)
				go func(ip string, p uint16) {
					defer wg.Done()
					defer sem.Release(1)

					r := s.probe(ctx, ip, p)
					select {
					case results <- r:
					case <-ctx.Done():
					}
				}(target, port)
			}
		}

		// Wait for all in-flight probes to finish before the deferred close(results)
		// runs. This guarantees no goroutine writes to a closed channel.
		wg.Wait()
	}()

	return results, nil
}

// probe dials (ip, port) up to 1+cfg.RetryCount times, retrying only on
// StateFiltered. It stops early if ctx is cancelled between attempts.
func (s *ConnectScanner) probe(ctx context.Context, ip string, port uint16) Result {
	var r Result
	for attempt := 0; attempt <= s.cfg.RetryCount; attempt++ {
		if ctx.Err() != nil {
			return Result{IP: ip, Port: port, State: StateFiltered}
		}
		r = s.dialOnce(ctx, ip, port)
		if r.State != StateFiltered {
			return r
		}
	}
	return r
}

// dialOnce performs a single TCP dial and classifies the outcome as Open,
// Closed, or Filtered based on the error type returned by the OS.
func (s *ConnectScanner) dialOnce(ctx context.Context, ip string, port uint16) Result {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	start := time.Now()
	conn, err := s.dialFunc(ctx, "tcp", addr)
	latency := time.Since(start)

	if err == nil {
		conn.Close()
		return Result{IP: ip, Port: port, State: StateOpen, Latency: latency}
	}
	// "connection refused" means the host sent RST — the port is actively closed.
	if isRefused(err) {
		return Result{IP: ip, Port: port, State: StateClosed, Latency: latency}
	}
	// Timeout, no route, or context cancellation → treat as filtered.
	return Result{IP: ip, Port: port, State: StateFiltered, Latency: latency}
}

// isRefused reports whether err is a TCP connection-refused error (RST from remote).
// We inspect the error string because net does not export a typed refused error.
func isRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "actively refused")
}
