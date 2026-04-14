// Package main is the CLI entry point for fastscan.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cemogur-git/fastscan/pkg/network"
	"github.com/cemogur-git/fastscan/pkg/scan"
	"github.com/cemogur-git/fastscan/pkg/utils"
	"github.com/spf13/cobra"
)

// legalNotice is printed to stderr before any scanning begins.
// Displaying this notice is mandatory per the project security standards.
const legalNotice = "[!] Bu araç yalnızca sahip olduğunuz veya yazılı\n izin aldığınız sistemlerde kullanılabilir."

// Output format identifiers — kept as named constants to avoid magic strings.
const (
	outputJSON  = "json"
	outputCSV   = "csv"
	outputTable = "table"
)

// Default flag values. Named constants keep magic literals in one place.
const (
	defaultPorts       = "1-1024"
	defaultConcurrency = 1000
	defaultTimeoutMS   = 500
	defaultOutput      = outputTable
)

var rootCmd = &cobra.Command{
	Use:   "fastscan [flags]",
	Short: "Yüksek performanslı TCP port scanner",
	Long: `fastscan — cloud-native, yüksek performanslı TCP port tarayıcı.

Örnekler:
  fastscan --target 192.168.1.1
  fastscan --target 192.168.1.0/24 --ports 22,80,443 --output json
  fastscan --target 10.0.0.1 --stealth --output csv --outfile results.csv`,
	RunE: runScan,
	// SilenceUsage prevents the full usage block from printing on runtime errors,
	// which would obscure the actual error message.
	SilenceUsage: true,
}

// execute sets up flags and runs the root command.
// os.Exit is confined to this function and main; nowhere else in the codebase.
func execute() {
	setupRootFlags()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// setupRootFlags attaches all CLI flags to rootCmd.
// Called once from execute() so no init() function is needed.
func setupRootFlags() {
	f := rootCmd.Flags()
	f.String("target", "", "Hedef IP, CIDR veya son-oktet aralığı (örn: 192.168.1.1, 10.0.0.0/24, 192.168.1.1-20)")
	f.String("ports", defaultPorts, "Port ifadesi (örn: 80, 1-1024, 80,443,8080)")
	f.Bool("stealth", false, "SYN scan kullan; CAP_NET_RAW gerektirir")
	f.Int("concurrency", defaultConcurrency, "Paralel bağlantı sayısı")
	f.Int("timeout", defaultTimeoutMS, "Port başına zaman aşımı ms cinsinden")
	f.String("output", defaultOutput, "Çıktı formatı: json, csv veya table")
	f.String("outfile", "", "Çıktı dosyası yolu (belirtilmezse stdout kullanılır)")
	f.Bool("verbose", false, "Debug log aktif")

	_ = rootCmd.MarkFlagRequired("target")
}

// runScan is the RunE handler for rootCmd. It orchestrates the full scan
// pipeline: flag parse → legal warning → target/port parse → scanner construction
// → TUI or plain export.
func runScan(cmd *cobra.Command, _ []string) error {
	f := cmd.Flags()

	targetExpr, _ := f.GetString("target")
	portsExpr, _ := f.GetString("ports")
	stealth, _ := f.GetBool("stealth")
	concurrency, _ := f.GetInt("concurrency")
	timeoutMS, _ := f.GetInt("timeout")
	outputFmt, _ := f.GetString("output")
	outfile, _ := f.GetString("outfile")
	verbose, _ := f.GetBool("verbose")

	// Step 1: legal notice — always shown before any processing.
	fmt.Fprintln(os.Stderr, legalNotice)

	// Step 2: validate output format early so we fail before scanning starts.
	switch outputFmt {
	case outputJSON, outputCSV, outputTable:
		// valid
	default:
		return fmt.Errorf("geçersiz --output değeri %q; json, csv veya table olmalı", outputFmt)
	}

	// Step 3: parse targets.
	rawTargets, err := utils.ParseTargets(targetExpr)
	if err != nil {
		return fmt.Errorf("hedef ayrıştırma: %w", err)
	}
	targets := make([]string, 0, len(rawTargets))
	for _, t := range rawTargets {
		if net.ParseIP(t) == nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "uyarı: geçersiz IP atlandı: %s\n", t)
			}
			continue
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return fmt.Errorf("geçerli hedef bulunamadı")
	}

	// Step 4: parse ports.
	ports, err := utils.ParsePorts(portsExpr)
	if err != nil {
		return fmt.Errorf("port ayrıştırma: %w", err)
	}

	cfg := scan.ScanConfig{
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutMS) * time.Millisecond,
		RateLimit:   scan.DefaultRateLimit,
		RetryCount:  scan.DefaultRetryCount,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Step 5: construct scanner based on --stealth flag.
	var scanner scan.Scanner
	if stealth {
		ifaceName, localIP, ifErr := defaultOutboundInterface()
		if ifErr != nil {
			return fmt.Errorf("stealth: ağ arayüzü tespit edilemedi: %w", ifErr)
		}
		rs, rsErr := network.NewRawSocket(ifaceName)
		if rsErr != nil {
			return fmt.Errorf("stealth: raw socket açılamadı (CAP_NET_RAW gereklidir): %w", rsErr)
		}
		defer rs.Close()
		scanner = network.NewSYNScanner(rs, cfg, localIP)
	} else {
		scanner = scan.NewConnectScanner(cfg)
	}

	// Step 6: start scan — returns result channel; probing runs in background.
	ch, err := scanner.Scan(ctx, targets, ports)
	if err != nil {
		return fmt.Errorf("tarama başlatılamadı: %w", err)
	}

	total := len(targets) * len(ports)

	// Step 7: prepare output writer — file or stdout.
	var w io.Writer = os.Stdout
	if outfile != "" {
		fh, createErr := os.Create(outfile)
		if createErr != nil {
			return fmt.Errorf("çıktı dosyası açılamadı: %w", createErr)
		}
		defer fh.Close()
		w = fh
	}

	// Step 8: run TUI when output is "table", no outfile, and stdout is a tty.
	// Any other combination falls through to the non-interactive export path.
	if outputFmt == outputTable && outfile == "" && isatty(os.Stdout) {
		return tuiRun(ch, total, targetExpr)
	}

	// Non-interactive path: aggregate all results, then export in the chosen format.
	agg := scan.NewAggregator()
	agg.Collect(ch)
	results := agg.FilterByState(scan.StateOpen)

	switch outputFmt {
	case outputJSON:
		return scan.ExportJSON(results, w)
	case outputCSV:
		return scan.ExportCSV(results, w)
	default: // outputTable — outfile is set or stdout is not a tty
		return writeTable(results, w)
	}
}

// defaultOutboundInterface returns the name and IPv4 address of the first
// non-loopback, up interface that has an IPv4 unicast address.
// Used to populate the source-IP field in hand-crafted SYN packets.
//
// CAP_NET_RAW is still required by the caller to open raw sockets.
func defaultOutboundInterface() (string, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, fmt.Errorf("arayüz listesi alınamadı: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
				return iface.Name, ip4, nil
			}
		}
	}
	return "", nil, fmt.Errorf("aktif IPv4 arayüzü bulunamadı")
}

// isatty reports whether f is connected to an interactive terminal.
// Uses only standard-library stat calls to avoid adding a dependency.
func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// writeTable writes open scan results as a human-readable fixed-width table to w.
// Column order: IP | PORT | SERVİS | BANNER | LATENCY — matches the TUI summary.
func writeTable(results []scan.Result, w io.Writer) error {
	fmt.Fprintf(w, "%-15s  %5s  %-12s  %-20s  %s\n", "IP", "PORT", "SERVİS", "BANNER", "LATENCY")
	fmt.Fprintln(w, strings.Repeat("─", 68))
	for _, r := range results {
		svc := r.Service
		if svc == "" {
			svc = "—"
		}
		banner := r.Banner
		if len(banner) > 20 {
			banner = banner[:17] + "..."
		}
		fmt.Fprintf(w, "%-15s  %5d  %-12s  %-20s  %v\n",
			r.IP, r.Port, svc, banner, r.Latency.Round(time.Millisecond))
	}
	return nil
}
