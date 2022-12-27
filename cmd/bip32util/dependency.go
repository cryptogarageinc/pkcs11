package main

import (
	"context"

	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/application/handler"
	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/domain/service"

	"github.com/cryptogarageinc/pkcs11"
	pkcs11api "github.com/cryptogarageinc/pkcs11/apis/pkcs11"
)

func newCmdHandler(ctx context.Context, env *environment) handler.CmdHandler {
	p := pkcs11.New(env.LibPath)
	if p == nil {
		panic("failed to create pkcs11")
	}

	api := pkcs11api.NewPkcs11(p, pkcs11api.CurveSecp256k1).WithSlot(env.SlotID)
	closeFn := func(ctx context.Context) error {
		if env.SlotID >= 0 {
			api.CloseSessionAll(ctx, uint(env.SlotID))
		}
		api.Finalize(ctx)
		p.Destroy()
		return nil
	}

	if err := api.Initialize(ctx); err != nil {
		_ = closeFn(ctx)
		panic(err)
	}
	pkcs11Service, err := service.NewPkcs11(ctx, api, env.PinCode, env.SlotID, env.PartitionID)
	if err != nil {
		_ = closeFn(ctx)
		panic(err)
	}
	return handler.NewBip32CmdHandler(pkcs11Service, closeFn)
}
