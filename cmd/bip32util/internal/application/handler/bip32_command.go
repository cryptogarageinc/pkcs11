package handler

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/domain/service"
	"github.com/cryptogarageinc/pkcs11/cmd/bip32util/internal/pkg/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type CmdHandler interface {
	ExecCommand(ctx context.Context) error
	Close(ctx context.Context)
}

type CloseFunc func(ctx context.Context)

type bip32CmdHandler struct {
	closeFn       CloseFunc
	pkcs11Service service.Pkcs11
}

func NewBip32CmdHandler(pkcs11Service service.Pkcs11, closeFn CloseFunc) *bip32CmdHandler {
	return &bip32CmdHandler{
		pkcs11Service: pkcs11Service,
		closeFn:       closeFn,
	}
}

func (h *bip32CmdHandler) ExecCommand(ctx context.Context) error {
	rootCmd := &cobra.Command{
		Use:   "bip32util",
		Short: "bip32 client utility tool",
		Long:  "bip32 client utility tool",
	}

	rootCmd.AddCommand(h.genXprivCmd(ctx))
	rootCmd.AddCommand(h.importXprivCmd(ctx))
	rootCmd.AddCommand(h.exportXprivCmd(ctx))
	rootCmd.AddCommand(h.findKeyCmd(ctx))
	rootCmd.AddCommand(h.signCmd(ctx))
	rootCmd.AddCommand(h.sleepCmd(ctx))
	rootCmd.AddCommand(h.manyDeriveCmd(ctx))

	return rootCmd.Execute()
}

func (h *bip32CmdHandler) Close(ctx context.Context) {
	h.closeFn(ctx)
}

func (h *bip32CmdHandler) genXprivCmd(ctx context.Context) *cobra.Command {
	var seedLabel, xprivlabel string
	var seedByteLen uint32
	var canExport bool
	// TODO: AES KEY encrypt状態でのimportも検討
	addCmd := &cobra.Command{
		Use:   "genXpriv",
		Short: "generate seed and xpriv",
		Long:  "generate seed and xpriv",
		RunE: func(cmd *cobra.Command, args []string) error {
			if seedLabel == "" {
				log.Warning(ctx, "label is empty. seed is not save.")
			}
			if xprivlabel == "" {
				log.Warning(ctx, "label is empty. xpriv is not save.")
			}
			if err := h.pkcs11Service.GenerateXpriv(ctx, uint(seedByteLen), seedLabel, xprivlabel, canExport); err != nil {
				return err
			}
			return nil
		},
	}

	addCmd.Flags().Uint32VarP(&seedByteLen, "seedByteLen", "s", 64, "seed byte length. default is 64 (512 bit)")
	addCmd.Flags().StringVarP(&seedLabel, "seedLabel", "sl", "", "seed label. if empty, xpriv has not save.")
	addCmd.Flags().StringVarP(&xprivlabel, "xprivlabel", "xl", "", "xpriv label. if empty, xpriv has not save.")
	addCmd.Flags().BoolVarP(&canExport, "canExport", "ce", false, "export flag. if false, importing xpriv can not export.")
	return addCmd
}

func (h *bip32CmdHandler) importXprivCmd(ctx context.Context) *cobra.Command {
	var seed, xpriv string
	var label string
	var canExport bool
	// TODO: AES KEY encrypt状態でのimportも検討
	addCmd := &cobra.Command{
		Use:   "importxpriv",
		Short: "import xpriv",
		Long:  "import xpriv. required seed or xpriv.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if label == "" {
				log.Warning(ctx, "label is empty. xpriv is not save.")
			}
			switch {
			case xpriv != "":
				if err := h.pkcs11Service.ImportXpriv(ctx, xpriv, label, canExport); err != nil {
					return err
				}
			case seed != "":
				seedBytes, err := hex.DecodeString(seed)
				if err != nil {
					return err
				}
				if err := h.pkcs11Service.ImportXprivFromSeed(ctx, seedBytes, label, canExport); err != nil {
					return err
				}
			default:
				return errors.New("required seed or xpriv")
			}
			return nil
		},
	}

	addCmd.Flags().StringVarP(&seed, "seed", "s", "", "seed")
	addCmd.Flags().StringVarP(&xpriv, "xpriv", "x", "", "master xpriv key")
	addCmd.Flags().StringVarP(&label, "label", "l", "", "xpriv label. if empty, xpriv has not save.")
	addCmd.Flags().BoolVarP(&canExport, "canExport", "ce", false, "export flag. if false, importing xpriv can not export.")
	return addCmd
}

func (h *bip32CmdHandler) exportXprivCmd(ctx context.Context) *cobra.Command {
	var label, outputPath string
	// TODO: AES KEY encrypt状態でのexportも検討
	addCmd := &cobra.Command{
		Use:   "exportxpriv",
		Short: "export xpriv",
		Long:  "export xpriv",
		RunE: func(cmd *cobra.Command, args []string) error {
			if label == "" {
				return errors.New("label is required")
			}
			xpriv, err := h.pkcs11Service.ExportXpriv(ctx, label)
			if err != nil {
				return err
			}
			if outputPath == "" {
				fmt.Printf("[xpriv] %s\n", xpriv)
				return nil
			}

			file, err := os.Create(outputPath)
			if err != nil {
				return err
			}
			defer func() {
				if tmpErr := file.Close(); tmpErr != nil {
					log.Warning(ctx, "file.Close failed", zap.Error(tmpErr))
				}
			}()
			if _, err := file.WriteString(xpriv); err != nil {
				return err
			}
			fmt.Printf("[xpriv] output=%s\n", outputPath)
			return nil
		},
	}

	addCmd.Flags().StringVarP(&label, "label", "l", "", "xpriv label.")
	addCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file path.")
	return addCmd
}

func (h *bip32CmdHandler) findKeyCmd(ctx context.Context) *cobra.Command {
	var label, path string
	addCmd := &cobra.Command{
		Use:   "findkey",
		Short: "find key",
		Long:  "find key. if set bip32 path, get the derive key.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if label == "" {
				return errors.New("label is required")
			}

			if path == "" {
				if err := h.pkcs11Service.FindKeyByLabel(ctx, label); err != nil {
					return err
				}
				fmt.Println("label is found.")
			} else {
				pkBytes, err := h.pkcs11Service.GetPublicKeyByDeriveKey(ctx, label, path)
				if err != nil {
					return err
				}
				fmt.Printf("[publicKey] %s\n", hex.EncodeToString(pkBytes))
			}
			return nil
		},
	}

	addCmd.Flags().StringVarP(&label, "label", "l", "", "xpriv label.")
	addCmd.Flags().StringVarP(&path, "path", "p", "", "bip32 path.")
	return addCmd
}

func (h *bip32CmdHandler) signCmd(ctx context.Context) *cobra.Command {
	var label, path, message string
	addCmd := &cobra.Command{
		Use:   "exportxpriv",
		Short: "export xpriv",
		Long:  "export xpriv",
		RunE: func(cmd *cobra.Command, args []string) error {
			if label == "" {
				return errors.New("label is required")
			}
			if message == "" {
				return errors.New("message is required")
			}
			msgBytes, err := hex.DecodeString(message)
			if err != nil {
				return err
			}
			sig, err := h.pkcs11Service.SignByDeriveKey(ctx, label, path, msgBytes)
			if err != nil {
				return err
			}
			fmt.Printf("[signature] %s\n", hex.EncodeToString(sig))
			return nil
		},
	}

	addCmd.Flags().StringVarP(&label, "label", "l", "", "xpriv label.")
	addCmd.Flags().StringVarP(&path, "path", "p", "", "bip32 path.")
	addCmd.Flags().StringVarP(&message, "message", "m", "", "message hash.")
	return addCmd
}

func (h *bip32CmdHandler) manyDeriveCmd(ctx context.Context) *cobra.Command {
	var label, basePath string
	var count uint32
	var sleepDuration time.Duration
	addCmd := &cobra.Command{
		Use:   "manyderive",
		Short: "many derive keys",
		Long:  "many derive keys.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if label == "" {
				return errors.New("label is required")
			}

			if err := h.pkcs11Service.DeriveKeysByLabel(ctx, label, basePath, count); err != nil {
				return err
			}
			fmt.Printf("sleep start. duration[%d]\n", sleepDuration)
			time.Sleep(sleepDuration)
			fmt.Println("sleep end.")
			return nil
		},
	}

	addCmd.Flags().StringVarP(&label, "label", "l", "", "xpriv label.")
	addCmd.Flags().StringVarP(&basePath, "basepath", "p", "", "bip32 base path.")
	addCmd.Flags().Uint32VarP(&count, "count", "c", 1, "bip32 derive count.")
	addCmd.Flags().DurationVarP(&sleepDuration, "duration", "d", time.Second, "sleep duration. default=1s.")
	return addCmd
}

func (h *bip32CmdHandler) sleepCmd(ctx context.Context) *cobra.Command {
	var sleepDuration time.Duration
	addCmd := &cobra.Command{
		Use:   "sleep",
		Short: "sleep after logon session.",
		Long:  "sleep after logon session.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("sleep start. duration[%d]\n", sleepDuration)
			time.Sleep(sleepDuration)
			fmt.Println("sleep end.")
			return nil
		},
	}

	addCmd.Flags().DurationVarP(&sleepDuration, "duration", "d", time.Second, "sleep duration. default=1s.")
	return addCmd
}
