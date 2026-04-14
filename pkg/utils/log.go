package utils

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Level represents the minimum severity of log messages a Logger will emit.
// Messages below the configured level are silently discarded.
type Level int

const (
	// LevelDebug enables all messages. Use only when --verbose is active.
	LevelDebug Level = iota
	// LevelInfo is the default level for normal operation.
	LevelInfo
	// LevelWarn enables warnings and errors only.
	LevelWarn
	// LevelError enables error messages only.
	LevelError
)

// levelLabel maps a Level to the three-letter tag written to the output.
var levelLabel = map[Level]string{
	LevelDebug: "DBG",
	LevelInfo:  "INF",
	LevelWarn:  "WRN",
	LevelError: "ERR",
}

// Logger provides structured, leveled logging for fastscan.
// It is safe for concurrent use. No global state is used.
type Logger struct {
	level Level
	w     io.Writer
	mu    sync.Mutex
}

// NewLogger constructs a Logger that writes to w and suppresses messages
// below level. Pass LevelInfo for normal operation; pass LevelDebug when the
// caller activates the --verbose flag.
func NewLogger(level Level, w io.Writer) *Logger {
	return &Logger{level: level, w: w}
}

// Debug writes a diagnostic message.
// Emitted only when the Logger was created with LevelDebug.
func (l *Logger) Debug(msg string) { l.emit(LevelDebug, msg) }

// Info writes an informational message.
// Emitted at LevelDebug and LevelInfo.
func (l *Logger) Info(msg string) { l.emit(LevelInfo, msg) }

// Warn writes a warning message.
// Emitted at LevelDebug, LevelInfo, and LevelWarn.
func (l *Logger) Warn(msg string) { l.emit(LevelWarn, msg) }

// Error writes an error message.
// Emitted at all levels except when lvl > LevelError (not possible with current
// constants, but guarded for forward compatibility).
func (l *Logger) Error(msg string) { l.emit(LevelError, msg) }

// emit writes a timestamped log line if lvl is at or above the threshold.
// The output format is: "HH:MM:SS [LVL] message\n"
func (l *Logger) emit(lvl Level, msg string) {
	if lvl < l.level {
		return
	}
	label, ok := levelLabel[lvl]
	if !ok {
		label = "???"
	}
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("15:04:05"), label, msg)

	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.w, line)
}
