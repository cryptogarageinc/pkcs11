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

func logError(ctx context.Context, message string, err error) {
	var errMsg string
	if err != nil {
		errMsg = " err:" + err.Error()
	}
	if ctx != nil {
		if ctxLogFunc != nil {
			ctxLogFunc(ctx, LogError, message+errMsg)
		}
	} else {
		if logFunc != nil {
			logFunc(LogError, message+errMsg)
		}
	}
}

func logWarn(ctx context.Context, message string, err error) {
	var errMsg string
	if err != nil {
		errMsg = " err:" + err.Error()
	}
	if ctx != nil {
		if ctxLogFunc != nil {
			ctxLogFunc(ctx, LogWarn, message+errMsg)
		}
	} else {
		if logFunc != nil {
			logFunc(LogWarn, message+errMsg)
		}
	}
}

func logInfo(ctx context.Context, message string) {
	if ctx != nil {
		if ctxLogFunc != nil {
			ctxLogFunc(ctx, LogInfo, message)
		}
	} else {
		if logFunc != nil {
			logFunc(LogInfo, message)
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
			ctxLogFunc(ctx, LogInfo, msg)
		}
	} else {
		if logFunc != nil {
			logFunc(LogInfo, msg)
		}
	}
}
