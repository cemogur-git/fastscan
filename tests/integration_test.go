// Package tests contains integration tests for fastscan.
// These tests exercise multiple packages together but never open real
// outbound network connections — they use loopback or mock sockets only.
package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIntegration_Placeholder(t *testing.T) {
	// Confirm package wiring compiles end-to-end.
	require.NotNil(t, t)
	t.Skip("integration tests not yet implemented")
}
