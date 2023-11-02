module github.com/cryptogarageinc/pkcs11/cmd/bip32util

go 1.21

require (
	github.com/caarlos0/env/v10 v10.0.0
	github.com/cryptogarageinc/pkcs11 v0.0.0-00010101000000-000000000000
	github.com/joho/godotenv v1.5.1
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.7.0
	go.uber.org/zap v1.26.0
)

replace github.com/cryptogarageinc/pkcs11 => ../..

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)
