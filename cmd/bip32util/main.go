// Copyright 2022 Crypto Garage. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"os"

	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/pkg/log"
	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/pkg/zapcontext"

	env "github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

type environment struct {
	PinCode string `env:"PIN_CODE,required"`

	// optional
	LibPath     string `env:"CRYPTOKI_LIB_PATH" envDefault:"/usr/safenet/lunaclient/lib/libCryptoki2_64.so"`
	SlotID      int    `env:"SLOT_ID" envDefault:"-1"`
	PartitionID int64  `env:"PARTITION_ID" envDefault:"-1"`
	LoginBySO   bool   `env:"SO_LOGIN" envDefault:"false"`
	LogEnv      string `env:"LOG_ENV" envDefault:"product"`
}

func main() {
	if _, statErr := os.Stat(".env"); statErr == nil {
		// If exist dotenv, load dotenv.
		if err := godotenv.Load(); err != nil {
			panic(err)
		}
	}
	envObj := &environment{}
	if err := env.Parse(envObj); err != nil {
		panic(err)
	}

	logger := log.Must(log.New(envObj.LogEnv))
	defer func() {
		_ = logger.Sync()
	}()

	ctx := zapcontext.ToContext(context.Background(), logger)

	cmdHandler := newCmdHandler(ctx, envObj)
	defer cmdHandler.Close(ctx)
	if err := cmdHandler.ExecCommand(ctx); err != nil {
		logger.Error("command failed.", zap.Error(err))
	}
	logger.Debug("command finish")
}
