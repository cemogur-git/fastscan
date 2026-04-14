package utils_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cemogur-git/fastscan/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── ParseTargets ────────────────────────────────────────────────────────────

func TestParseTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantLen   int    // expected number of IPs; -1 = skip length check
		wantFirst string // expected first IP; "" = skip
		wantLast  string // expected last IP; "" = skip
		wantErr   bool
	}{
		// ── valid: single IP ──────────────────────────────────────────────
		{
			name:      "single IPv4",
			input:     "192.168.1.1",
			wantLen:   1,
			wantFirst: "192.168.1.1",
		},
		{
			name:      "single IP with leading space",
			input:     "  10.0.0.1  ",
			wantLen:   1,
			wantFirst: "10.0.0.1",
		},

		// ── valid: CIDR ───────────────────────────────────────────────────
		{
			name:      "CIDR /24 has 254 hosts",
			input:     "192.168.1.0/24",
			wantLen:   254,
			wantFirst: "192.168.1.1",
			wantLast:  "192.168.1.254",
		},
		{
			name:      "CIDR /32 returns single host",
			input:     "10.0.0.5/32",
			wantLen:   1,
			wantFirst: "10.0.0.5",
		},
		{
			name:      "CIDR /31 returns both addresses (RFC 3021)",
			input:     "10.0.0.0/31",
			wantLen:   2,
			wantFirst: "10.0.0.0",
			wantLast:  "10.0.0.1",
		},
		{
			name:      "CIDR /30 has 2 hosts",
			input:     "10.0.0.0/30",
			wantLen:   2,
			wantFirst: "10.0.0.1",
			wantLast:  "10.0.0.2",
		},
		{
			name:      "CIDR /16 has 65534 hosts",
			input:     "10.0.0.0/16",
			wantLen:   65534,
			wantFirst: "10.0.0.1",
			wantLast:  "10.0.255.254",
		},

		// ── valid: octet range ────────────────────────────────────────────
		{
			name:      "range 1-20 produces 20 IPs",
			input:     "192.168.1.1-20",
			wantLen:   20,
			wantFirst: "192.168.1.1",
			wantLast:  "192.168.1.20",
		},
		{
			name:      "range with same start and end is one IP",
			input:     "10.0.0.5-5",
			wantLen:   1,
			wantFirst: "10.0.0.5",
		},
		{
			name:      "range ending at 255",
			input:     "192.168.1.200-255",
			wantLen:   56,
			wantFirst: "192.168.1.200",
			wantLast:  "192.168.1.255",
		},

		// ── errors ────────────────────────────────────────────────────────
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "invalid IP",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "invalid CIDR — bad prefix length",
			input:   "192.168.1.0/33",
			wantErr: true,
		},
		{
			name:    "invalid CIDR — non-numeric host",
			input:   "abc.def.ghi.jkl/24",
			wantErr: true,
		},
		{
			name:    "/0 exceeds maxTargets",
			input:   "0.0.0.0/0",
			wantErr: true,
		},
		{
			name:    "reversed range (end < start)",
			input:   "192.168.1.20-5",
			wantErr: true,
		},
		{
			name:    "range end octet > 255",
			input:   "192.168.1.1-300",
			wantErr: true,
		},
		{
			name:    "invalid start IP in range",
			input:   "999.999.999.999-20",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := utils.ParseTargets(tt.input)

			if tt.wantErr {
				require.Error(t, err, "expected an error for input %q", tt.input)
				return
			}

			require.NoError(t, err)

			if tt.wantLen >= 0 {
				assert.Len(t, got, tt.wantLen)
			}
			if tt.wantFirst != "" {
				require.NotEmpty(t, got)
				assert.Equal(t, tt.wantFirst, got[0])
			}
			if tt.wantLast != "" {
				require.NotEmpty(t, got)
				assert.Equal(t, tt.wantLast, got[len(got)-1])
			}
		})
	}
}

// ─── ParsePorts ──────────────────────────────────────────────────────────────

func TestParsePorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    []uint16
		wantErr bool
	}{
		// ── valid: single port ────────────────────────────────────────────
		{
			name:  "single port 80",
			input: "80",
			want:  []uint16{80},
		},
		{
			name:  "minimum valid port 1",
			input: "1",
			want:  []uint16{1},
		},
		{
			name:  "maximum valid port 65535",
			input: "65535",
			want:  []uint16{65535},
		},

		// ── valid: range ──────────────────────────────────────────────────
		{
			name:  "range 1-5",
			input: "1-5",
			want:  []uint16{1, 2, 3, 4, 5},
		},
		{
			name:  "range of one (start == end)",
			input: "443-443",
			want:  []uint16{443},
		},
		{
			name:  "range 1-1024",
			input: "1-1024",
			want:  makeRange(1, 1024),
		},

		// ── valid: comma list ─────────────────────────────────────────────
		{
			name:  "comma list",
			input: "80,443,8080",
			want:  []uint16{80, 443, 8080},
		},

		// ── valid: mixed ──────────────────────────────────────────────────
		{
			name:  "mixed range and singles",
			input: "22,80,8000-8002,9000",
			want:  []uint16{22, 80, 8000, 8001, 8002, 9000},
		},

		// ── valid: deduplication & ordering ──────────────────────────────
		{
			name:  "duplicates removed",
			input: "80,80,443",
			want:  []uint16{80, 443},
		},
		{
			name:  "result is sorted",
			input: "9000,443,80",
			want:  []uint16{80, 443, 9000},
		},
		{
			name:  "range overlap with single is deduped and sorted",
			input: "1-5,3,6",
			want:  []uint16{1, 2, 3, 4, 5, 6},
		},

		// ── errors ────────────────────────────────────────────────────────
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "port zero is rejected",
			input:   "0",
			wantErr: true,
		},
		{
			name:    "port 65536 is rejected",
			input:   "65536",
			wantErr: true,
		},
		{
			name:    "reversed range",
			input:   "1024-1",
			wantErr: true,
		},
		{
			name:    "non-numeric token",
			input:   "http",
			wantErr: true,
		},
		{
			name:    "trailing comma",
			input:   "80,",
			wantErr: true,
		},
		{
			name:    "range with zero start",
			input:   "0-1024",
			wantErr: true,
		},
		{
			name:    "range with out-of-bounds end",
			input:   "1-65536",
			wantErr: true,
		},
		{
			name:    "negative number",
			input:   "-80",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := utils.ParsePorts(tt.input)

			if tt.wantErr {
				require.Error(t, err, "expected an error for input %q", tt.input)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// makeRange returns a sorted []uint16 from start to end inclusive.
func makeRange(start, end uint16) []uint16 {
	out := make([]uint16, 0, int(end-start)+1)
	for i := start; i <= end; i++ {
		out = append(out, i)
	}
	return out
}

// ─── Logger ──────────────────────────────────────────────────────────────────

func TestLogger_LevelFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		loggerLevel utils.Level
		emit        func(l *utils.Logger)
		wantInOut   []string // substrings that MUST appear
		wantAbsent  []string // substrings that must NOT appear
	}{
		{
			name:        "LevelInfo suppresses Debug",
			loggerLevel: utils.LevelInfo,
			emit:        func(l *utils.Logger) { l.Debug("secret-dbg"); l.Info("visible-inf") },
			wantInOut:   []string{"visible-inf", "[INF]"},
			wantAbsent:  []string{"secret-dbg"},
		},
		{
			name:        "LevelDebug emits all levels",
			loggerLevel: utils.LevelDebug,
			emit: func(l *utils.Logger) {
				l.Debug("d"); l.Info("i"); l.Warn("w"); l.Error("e")
			},
			wantInOut:  []string{"[DBG]", "[INF]", "[WRN]", "[ERR]", "d", "i", "w", "e"},
			wantAbsent: []string{},
		},
		{
			name:        "LevelWarn suppresses Info and Debug",
			loggerLevel: utils.LevelWarn,
			emit: func(l *utils.Logger) {
				l.Debug("no-dbg"); l.Info("no-inf"); l.Warn("yes-wrn"); l.Error("yes-err")
			},
			wantInOut:  []string{"yes-wrn", "yes-err", "[WRN]", "[ERR]"},
			wantAbsent: []string{"no-dbg", "no-inf"},
		},
		{
			name:        "LevelError suppresses everything below Error",
			loggerLevel: utils.LevelError,
			emit: func(l *utils.Logger) {
				l.Debug("no"); l.Info("no"); l.Warn("no"); l.Error("only-this")
			},
			wantInOut:  []string{"only-this", "[ERR]"},
			wantAbsent: []string{"[DBG]", "[INF]", "[WRN]"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := utils.NewLogger(tt.loggerLevel, &buf)
			tt.emit(log)
			out := buf.String()

			for _, want := range tt.wantInOut {
				assert.True(t, strings.Contains(out, want),
					"expected output to contain %q, got:\n%s", want, out)
			}
			for _, absent := range tt.wantAbsent {
				assert.False(t, strings.Contains(out, absent),
					"output must NOT contain %q, got:\n%s", absent, out)
			}
		})
	}
}

func TestLogger_OutputFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := utils.NewLogger(utils.LevelInfo, &buf)
	log.Info("hello world")

	line := buf.String()

	// Each line ends with a newline.
	assert.True(t, strings.HasSuffix(line, "\n"))
	// Timestamp in HH:MM:SS format (10 chars) appears at the start.
	require.GreaterOrEqual(t, len(line), 10)
	assert.Equal(t, ':', rune(line[2]))
	assert.Equal(t, ':', rune(line[5]))
	// Level label present.
	assert.Contains(t, line, "[INF]")
	// Message present.
	assert.Contains(t, line, "hello world")
}

func TestLogger_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := utils.NewLogger(utils.LevelDebug, &buf)

	const goroutines = 50
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			log.Info("concurrent message")
			done <- struct{}{}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	assert.Len(t, lines, goroutines, "each goroutine should produce exactly one line")
}
