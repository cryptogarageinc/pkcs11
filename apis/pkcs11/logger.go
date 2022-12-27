package pkcs11

import (
	"context"
	"fmt"
)

// LogLevel ...
type LogLevel string

const (
	LogError LogLevel = "error"
	LogWarn  LogLevel = "warn"
	LogInfo  LogLevel = "info"
)

// LogFunc ...
type LogFunc func(level LogLevel, message string, err error)

// ContextLogFunc ...
type ContextLogFunc func(ctx context.Context, level LogLevel, message string, err error)

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

func logError(ctx context.Context, message string, err error) {
	if ctx != nil {
		if ctxLogFunc != nil {
			ctxLogFunc(ctx, LogError, message, err)
		}
	} else {
		if logFunc != nil {
			logFunc(LogError, message, err)
		}
	}
}

func logWarn(ctx context.Context, message string, err error) {
	if ctx != nil {
		if ctxLogFunc != nil {
			ctxLogFunc(ctx, LogWarn, message, err)
		}
	} else {
		if logFunc != nil {
			logFunc(LogWarn, message, err)
		}
	}
}

func logInfo(ctx context.Context, message string) {
	if ctx != nil {
		if ctxLogFunc != nil {
			ctxLogFunc(ctx, LogInfo, message, nil)
		}
	} else {
		if logFunc != nil {
			logFunc(LogInfo, message, nil)
		}
	}
}

func logInfof(ctx context.Context, message string, params ...any) {
	var msg string
	if len(params) > 0 {
		msg = fmt.Sprintf(message, params...)
	} else {
		msg = message
	}
	if ctx != nil {
		if ctxLogFunc != nil {
			ctxLogFunc(ctx, LogInfo, msg, nil)
		}
	} else {
		if logFunc != nil {
			logFunc(LogInfo, msg, nil)
		}
	}
}
