package network_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawSocket_Placeholder(t *testing.T) {
	// Real tests will verify packet construction without a live socket.
	assert.NotNil(t, assert.AnError)
	t.Skip("not yet implemented")
}

func TestSYNScanner_Placeholder(t *testing.T) {
	t.Skip("not yet implemented")
}
