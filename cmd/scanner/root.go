// Package main is the CLI entry point for fastscan.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "fastscan",
	Short: "Yüksek performanslı TCP port scanner",
	Long: `fastscan — cloud-native, yüksek performanslı TCP port tarayıcı.

YASAL UYARI: Bu araç yalnızca sahip olduğunuz veya yazılı izin aldığınız
sistemlerde kullanılabilir. İzinsiz kullanım yasalara aykırıdır.
Tüm sorumluluk kullanıcıya aittir.`,
	// RunE allows the root command to report configuration errors without panic.
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("bir alt komut seçin — örnek: fastscan scan --help")
	},
}

// execute runs the root command and terminates the process on failure.
// os.Exit is confined to this function and main; nowhere else.
func execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
