package pkcs11

import (
	"context"
)

// LogLevel ...
type LogLevel string

const (
	LogError LogLevel = "error"
	LogWarn  LogLevel = "warn"
	LogInfo  LogLevel = "info"
)

// LogFunc ...
type LogFunc func(level LogLevel, message string)

// ContextLogFunc ...
type ContextLogFunc func(ctx context.Context, level LogLevel, message string)

// SetLogger ...
func SetLogger(logger LogFunc) {
	logFunc = logger
}

// SetContextLogger ...
func SetContextLogger(logger ContextLogFunc) {
	ctxLogFunc = logger
}

// private ---------------------------------------------------------------------

var (
	logFunc    LogFunc
	ctxLogFunc ContextLogFunc
)

func logging(ctx context.Context, level LogLevel, funcName string, err error, message string) {
	var msg string
	if err == nil {
		msg = ": success: " + message
	} else {
		msg = ": err:" + err.Error() + ": " + message
	}
	if ctx != nil {
		if ctxLogFunc != nil && message != "" {
			ctxLogFunc(ctx, level, funcName+msg)
		}
	} else {
		if logFunc != nil && message != "" {
			logFunc(level, funcName+msg)
		}
	}
}
