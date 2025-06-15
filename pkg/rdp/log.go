package rdp

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

// Logger is the package logger. By default it writes pretty console output to
// stderr at INFO level. Library users can replace it with their own
// zerolog.Logger (e.g. zerolog.New(io.Discard) to silence) or just adjust the
// level via Logger.Level().
//
// The CLI in cmd/rdp-screenshotter wires `-log-level` into this variable.
var Logger = zerolog.New(zerolog.ConsoleWriter{
	Out:        os.Stderr,
	TimeFormat: "15:04:05",
	NoColor:    !isatty(os.Stderr),
}).With().Timestamp().Logger().Level(zerolog.InfoLevel)

// SetLogger replaces the package logger. Useful for tests (zerolog.Nop()) or
// for routing output to your application's structured logging pipeline.
func SetLogger(l zerolog.Logger) {
	Logger = l
}

// SetLogOutput points the default console logger at w. Convenient when callers
// want plain output but a different sink (e.g. a file). For full control,
// build your own zerolog.Logger and pass it to SetLogger.
func SetLogOutput(w io.Writer) {
	Logger = zerolog.New(zerolog.ConsoleWriter{Out: w, TimeFormat: "15:04:05", NoColor: true}).
		With().Timestamp().Logger().Level(Logger.GetLevel())
}

// SetLogLevel adjusts the level threshold of the package logger.
func SetLogLevel(level zerolog.Level) {
	Logger = Logger.Level(level)
}

// isatty reports whether f is a character device (terminal). Used to gate
// ANSI colour in the default ConsoleWriter without pulling in go-isatty.
func isatty(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
