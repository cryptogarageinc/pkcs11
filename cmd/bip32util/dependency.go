package main

import (
	"context"

	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/application/handler"
	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/domain/service"
	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/pkg/log"
	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/pkg/zapcontext"
	"go.uber.org/zap"

	"github.com/cryptogarageinc/pkcs11"
	pkcs11api "github.com/cryptogarageinc/pkcs11/apis/pkcs11"
)

func newCmdHandler(ctx context.Context, env *environment) handler.CmdHandler {
	p := pkcs11.New(env.LibPath)
	if p == nil {
		panic("failed to create pkcs11")
	}

	pkcs11api.SetContextLogger(func(ctx context.Context, level pkcs11api.LogLevel, message string, err error) {
		logObj := zapcontext.Extract(ctx)
		switch level {
		case pkcs11api.LogError:
			logObj.Error(message, zap.Error(err))
		case pkcs11api.LogWarn:
			logObj.Warn(message, zap.Error(err))
		case pkcs11api.LogInfo:
			logObj.Info(message)
		}
	})

	api := pkcs11api.NewPkcs11(p, pkcs11api.CurveSecp256k1).WithSlot(env.SlotID).WithSOLogin(env.LoginBySO)
	closeFn := func(ctx context.Context) {
		if env.SlotID >= 0 {
			api.CloseSessionAll(ctx, uint(env.SlotID))
		}
		api.Finalize(ctx)
		p.Destroy()
	}

	if err := api.Initialize(ctx); err != nil {
		closeFn(ctx)
		panic(err)
	}
	pkcs11Service, err := service.NewPkcs11(ctx, api, env.PinCode, env.SlotID, env.PartitionID)
	if err != nil {
		log.Error(ctx, "failed to create the pkcs11 service.", err)
		// To display help, do not execute a panic here.
	}
	return handler.NewBip32CmdHandler(pkcs11Service, closeFn)
}
