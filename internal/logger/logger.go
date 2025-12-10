package logger

import (
	"io"
	"log"
)

// USAGE:
// 	l := NewLogger(os.Stdout, true, "BoringMachine: ");
//  l.Println()

func NewLogger(out io.Writer, verbose bool, prefix string) *log.Logger {
	var instance *log.Logger
	if verbose {
		instance = log.New(out, prefix, log.LUTC)
	} else {
		instance = log.New(io.Discard, prefix, log.LUTC)
	}

	return instance
}
