package log

import (
	"context"

	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/pkg/zapcontext"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Must ... new logger
func Must(logger *zap.Logger, err error) *zap.Logger {
	if err != nil {
		panic(err)
	}
	return logger
}

// New ... new logger
func New(env string) (*zap.Logger, error) {
	switch env {
	case "console":
		return newConsoleConfig().Build(
			zap.AddStacktrace(zapcore.WarnLevel))
	case "dev", "develop", "development":
		return newDevelopmentConfig().Build(
			zap.AddStacktrace(zapcore.DebugLevel))
	default:
		return newProductionConfig().Build(
			zap.AddStacktrace(zapcore.WarnLevel))
	}
}

// Logger ... get context from context
func logger(ctx context.Context) *zap.Logger {
	return zapcontext.Extract(ctx)
}

// Debug ... output debug log
func Debug(ctx context.Context, msg string, fields ...zap.Field) {
	withTracing(
		ctx,
		msg,
		func(ctx context.Context, msg string, fields ...zap.Field) {
			logger(ctx).WithOptions(zap.AddCallerSkip(3)).Debug(msg, fields...)
		},
		fields...)
}

// Info ... output info log
func Info(ctx context.Context, msg string, fields ...zap.Field) {
	withTracing(
		ctx,
		msg,
		func(ctx context.Context, msg string, fields ...zap.Field) {
			logger(ctx).WithOptions(zap.AddCallerSkip(3)).Info(msg, fields...)
		},
		fields...)
}

// Warning ... output warning log
func Warning(ctx context.Context, msg string, fields ...zap.Field) {
	withTracing(
		ctx,
		msg,
		func(ctx context.Context, msg string, fields ...zap.Field) {
			logger(ctx).WithOptions(zap.AddCallerSkip(3)).Warn(msg, fields...)
		},
		fields...)
}

// WarningWithError ... output warning log
func WarningWithError(ctx context.Context, msg string, err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	withTracing(
		ctx,
		msg,
		func(ctx context.Context, msg string, fields ...zap.Field) {
			logger(ctx).WithOptions(zap.AddCallerSkip(3)).Warn(msg, fields...)
		},
		fields...)
}

// Error ... output error log
func Error(ctx context.Context, msg string, err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	withTracing(
		ctx,
		msg,
		func(ctx context.Context, msg string, fields ...zap.Field) {
			logger(ctx).WithOptions(zap.AddCallerSkip(3)).Error(msg, fields...)
		},
		fields...)
}

// ErrorIfExists ... calls Errorf only when the error exists
func ErrorIfExists(ctx context.Context, err error, msg string, fields ...zap.Field) {
	if err == nil {
		return
	}
	withTracing(
		ctx,
		msg,
		func(ctx context.Context, msg string, fields ...zap.Field) {
			logger(ctx).WithOptions(zap.AddCallerSkip(3)).Error(msg, fields...)
		},
		fields...)
}

// LogWithLevel ... output by log level
func LogWithLevel(ctx context.Context, level zapcore.Level, msg string, fields ...zap.Field) {
	withTracing(
		ctx,
		msg,
		func(ctx context.Context, msg string, fields ...zap.Field) {
			logger(ctx).WithOptions(zap.AddCallerSkip(3)).Check(level, msg).Write(fields...)
		},
		fields...)
}

type LogFunc func(ctx context.Context, msg string, fields ...zap.Field)

func withTracing(
	ctx context.Context,
	msg string,
	f LogFunc,
	fields ...zap.Field,
) {
	f(ctx, msg, fields...)
}
