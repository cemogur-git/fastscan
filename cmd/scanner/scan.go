package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cemogur-git/fastscan/pkg/scan"
	"github.com/cemogur-git/fastscan/pkg/utils"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

// Default values for scan flags. Named constants keep magic numbers out of
// flag registration and make the defaults easy to audit in one place.
const (
	defaultPorts       = "1-1024"
	defaultConcurrency = scan.DefaultConcurrency // 1000
	defaultTimeoutSec  = 0.5                     // 500 ms — matches scan.DefaultTimeout
	defaultRateLimit   = scan.DefaultRateLimit   // 10 000 pps
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "TCP port taraması başlatır",
	Long: `Belirtilen hedef ve port aralığında TCP connect taraması yapar.

Örnekler:
  fastscan scan -t 192.168.1.1
  fastscan scan -t 192.168.1.0/24 -p 22,80,443
  fastscan scan -t 10.0.0.1-10 -p 1-65535 -c 500 --timeout 0.5
  fastscan scan -t 10.0.0.1 --json | jq '.[] | select(.state=="open")'`,
	RunE: runScan,
}

// setupScanCmd registers flags on scanCmd and adds it to rootCmd.
// Called from execute() so no init() function is needed.
func setupScanCmd() {
	f := scanCmd.Flags()
	f.StringP("target", "t", "", "Hedef IP, CIDR veya son-oktet aralığı (örn: 192.168.1.1, 10.0.0.0/24, 192.168.1.1-20)")
	f.StringP("ports", "p", defaultPorts, "Port ifadesi (örn: 80, 1-1024, 80,443,8080)")
	f.IntP("concurrency", "c", defaultConcurrency, "Paralel bağlantı sayısı")
	f.Float64("timeout", defaultTimeoutSec, "Port başına zaman aşımı saniye cinsinden (örn: 0.5, 2.0)")
	f.Int("rate", defaultRateLimit, "Saniyede maksimum paket sayısı (0 = sınırsız)")
	f.Bool("json", false, "Sonuçları JSON formatında yaz (yalnızca açık portlar)")
	f.Bool("no-tui", false, "TUI'yi devre dışı bırak, düz metin çıktısı ver")

	_ = scanCmd.MarkFlagRequired("target")
	rootCmd.AddCommand(scanCmd)
}

// jsonEntry is the JSON representation of a single open port result.
type jsonEntry struct {
	Host    string `json:"host"`
	Port    uint16 `json:"port"`
	State   string `json:"state"`
	RTTms   int64  `json:"rtt_ms"`
}

func runScan(cmd *cobra.Command, _ []string) error {
	f := cmd.Flags()

	targetExpr, _ := f.GetString("target")
	portsExpr, _ := f.GetString("ports")
	concurrency, _ := f.GetInt("concurrency")
	timeoutSec, _ := f.GetFloat64("timeout")
	rateLimit, _ := f.GetInt("rate")
	jsonOutput, _ := f.GetBool("json")
	noTUI, _ := f.GetBool("no-tui")

	rawTargets, err := utils.ParseTargets(targetExpr)
	if err != nil {
		return fmt.Errorf("hedef ayrıştırma: %w", err)
	}

	ports, err := utils.ParsePorts(portsExpr)
	if err != nil {
		return fmt.Errorf("port ayrıştırma: %w", err)
	}

	// Filter out any entries that are not valid IP addresses, logging a warning
	// per invalid entry so the user knows which targets were skipped.
	targets := make([]string, 0, len(rawTargets))
	for _, t := range rawTargets {
		if net.ParseIP(t) == nil {
			fmt.Fprintf(os.Stderr, "uyarı: geçersiz IP atlandı: %s\n", t)
			continue
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return fmt.Errorf("geçerli hedef bulunamadı")
	}

	cfg := scan.ScanConfig{
		Concurrency: concurrency,
		Timeout:     time.Duration(float64(time.Second) * timeoutSec),
		RateLimit:   rateLimit,
		RetryCount:  scan.DefaultRetryCount,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanner := scan.NewConnectScanner(cfg)

	ch, err := scanner.Scan(ctx, targets, ports)
	if err != nil {
		return fmt.Errorf("tarama: %w", err)
	}

	total := len(targets) * len(ports)

	// Use plain text if explicitly requested, JSON is requested, or stdout is
	// not an interactive terminal (e.g. piped to a file or another tool).
	if jsonOutput || noTUI || !isatty(os.Stdout) {
		return plainOutput(ch, jsonOutput)
	}

	return tuiOutput(ch, total, targetExpr)
}

// plainOutput drains results and prints open ports to stdout.
// In JSON mode every open result is written as a JSON object on its own line.
// In text mode a human-readable table row is printed instead.
func plainOutput(results <-chan scan.Result, asJSON bool) error {
	enc := json.NewEncoder(os.Stdout)

	for r := range results {
		if r.State != scan.StateOpen {
			continue
		}
		if asJSON {
			entry := jsonEntry{
				Host:  r.IP,
				Port:  r.Port,
				State: r.State.String(),
				RTTms: r.Latency.Milliseconds(),
			}
			if err := enc.Encode(entry); err != nil {
				return fmt.Errorf("JSON kodlama: %w", err)
			}
		} else {
			fmt.Printf("%-15s  %5d/tcp  %-8s  %v\n",
				r.IP, r.Port, r.State, r.Latency.Round(time.Millisecond))
		}
	}

	return nil
}

// tuiOutput runs the Bubble Tea program that renders scan progress interactively.
func tuiOutput(results <-chan scan.Result, total int, target string) error {
	m := newTUIModel(results, total, target)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI: %w", err)
	}
	return nil
}

// isatty reports whether f is connected to an interactive terminal.
// Uses only standard library calls to avoid an extra dependency.
func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
