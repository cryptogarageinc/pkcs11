package zapcontext

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxLoggerKeyStruct struct{}

var (
	ctxLoggerKey = ctxLoggerKeyStruct{}
)

type zapCtxLogger struct {
	logger *zap.Logger
	fields []zapcore.Field
}

func ToContext(ctx context.Context, logger *zap.Logger) context.Context {
	l := &zapCtxLogger{
		logger: logger,
	}
	return context.WithValue(ctx, &ctxLoggerKey, l)
}

func AddFields(ctx context.Context, fields ...zapcore.Field) error {
	l, ok := ctx.Value(&ctxLoggerKey).(*zapCtxLogger)
	if !ok || l == nil {
		return fmt.Errorf("this context is not contains zapcontext")
	}
	l.fields = append(l.fields, fields...)
	return nil
}

func Extract(ctx context.Context) *zap.Logger {
	l, ok := ctx.Value(&ctxLoggerKey).(*zapCtxLogger)
	if !ok || l == nil {
		return zap.NewNop()
	}
	return l.logger.With(l.fields...)
}
