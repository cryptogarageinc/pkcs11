package service

import (
	"context"

	"github.com/cryptogarageinc/pkcs11"
	pkcs11api "github.com/cryptogarageinc/pkcs11/apis/pkcs11"
)

type Pkcs11 interface {
	GenerateXpriv(
		ctx context.Context,
		seedByteLength uint,
		seedLabel,
		xprivLabel string,
		canExport bool,
	) error

	ImportXprivFromSeed(
		ctx context.Context,
		seed []byte,
		xprivLabel string,
		canExport bool,
	) error

	ImportXpriv(
		ctx context.Context,
		xpriv string,
		xprivLabel string,
		canExport bool,
	) error

	ExportXpriv(
		ctx context.Context,
		xprivLabel string,
	) (xpriv string, err error)
	// find by label
	// sign with derive & findLabel
	// get pubkey with derive & findLabel

	FindKeyByLabel(
		ctx context.Context,
		xprivLabel string,
	) error
	SignByDeriveKey(
		ctx context.Context,
		xprivLabel string,
		path string,
		message []byte,
	) (signature []byte, err error)
	GetPublicKeyByDeriveKey(
		ctx context.Context,
		xprivLabel string,
		path string,
	) (publicKey []byte, err error)
}

type pkcs11Service struct {
	pkcs11Api   pkcs11api.Pkcs11
	session     pkcs11.SessionHandle
	pin         string
	partitionID int64
}

var _ Pkcs11 = (*pkcs11Service)(nil)

func NewPkcs11(
	ctx context.Context,
	pkcs11Api pkcs11api.Pkcs11,
	pin string,
	partitionID int64,
) (service *pkcs11Service, err error) {
	var session pkcs11.SessionHandle
	if partitionID >= 0 {
		session, err = pkcs11Api.OpenSessionWithPartition(ctx, uint(partitionID), pin)
		if err != nil {
			return nil, err
		}
	} else {
		session, err = pkcs11Api.OpenSession(ctx, pin)
		if err != nil {
			return nil, err
		}
	}
	return &pkcs11Service{
		pkcs11Api:   pkcs11Api,
		session:     session,
		pin:         pin,
		partitionID: partitionID,
	}, nil
}

func (s *pkcs11Service) GenerateXpriv(
	ctx context.Context,
	seedByteLength uint,
	seedLabel,
	xprivLabel string,
	canExport bool,
) error {
	seedHdl, err := s.pkcs11Api.GenerateSeed(ctx, s.session, seedLabel, seedByteLength)
	if err != nil {
		return err
	}
	_, _, err = s.pkcs11Api.CreateXprivFromSeed(ctx, s.session, seedHdl, "", xprivLabel, canExport)
	if err != nil {
		return err
	}
	return nil
}

func (s *pkcs11Service) ImportXprivFromSeed(
	ctx context.Context,
	seed []byte,
	xprivLabel string,
	canExport bool,
) error {
	seedHdl, err := s.pkcs11Api.ImportSeed(ctx, s.session, seed, "")
	if err != nil {
		return err
	}
	_, _, err = s.pkcs11Api.CreateXprivFromSeed(ctx, s.session, seedHdl, "", xprivLabel, canExport)
	if err != nil {
		return err
	}
	return nil
}

func (s *pkcs11Service) ImportXpriv(
	ctx context.Context,
	xpriv string,
	xprivLabel string,
	canExport bool,
) error {
	_, err := s.pkcs11Api.ImportXpriv(ctx, s.session, xpriv, xprivLabel, canExport)
	if err != nil {
		return err
	}
	return nil
}

func (s *pkcs11Service) ExportXpriv(
	ctx context.Context,
	xprivLabel string,
) (xpriv string, err error) {
	xprivHdl, err := s.pkcs11Api.FindKeyByLabel(ctx, s.session, xprivLabel)
	if err != nil {
		return "", err
	}
	xpriv, err = s.pkcs11Api.ExportXpriv(ctx, s.session, xprivHdl)
	if err != nil {
		return "", err
	}
	return xpriv, nil
}

func (s *pkcs11Service) FindKeyByLabel(
	ctx context.Context,
	xprivLabel string,
) error {
	_, err := s.pkcs11Api.FindKeyByLabel(ctx, s.session, xprivLabel)
	if err != nil {
		return err
	}
	return nil
}

func (s *pkcs11Service) SignByDeriveKey(
	ctx context.Context,
	xprivLabel string,
	path string,
	message []byte,
) (signature []byte, err error) {
	xprivHdl, err := s.pkcs11Api.FindKeyByLabel(ctx, s.session, xprivLabel)
	if err != nil {
		return nil, err
	}
	skHdl := xprivHdl
	if path != "" {
		_, sk, err := s.DeriveKeyPair(ctx, s.session, xprivHdl, path)
		if err != nil {
			return nil, err
		}
		skHdl = sk
	}
	sig, err := s.pkcs11Api.GenerateSignature(ctx, s.session, skHdl, pkcs11api.MechanismTypeEcdsa, message)
	if err != nil {
		return nil, err
	}
	return sig.ToSlice(), nil
}

func (s *pkcs11Service) DeriveKeyPair(
	ctx context.Context,
	session pkcs11.SessionHandle,
	masterXprivHandle pkcs11.ObjectHandle,
	path string,
) (pubkeyHandle pkcs11.ObjectHandle, privkeyHandle pkcs11.ObjectHandle, err error) {
	bip32Path, err := pkcs11api.ConvertBip32PathFromString(path)
	if err != nil {
		return 0, 0, err
	}
	pk, sk, err := s.pkcs11Api.DeriveKeyPair(ctx, s.session, masterXprivHandle, bip32Path)
	if err != nil {
		return 0, 0, err
	}
	return pk, sk, nil
}

func (s *pkcs11Service) GetPublicKeyByDeriveKey(
	ctx context.Context,
	xprivLabel string,
	path string,
) (publicKey []byte, err error) {
	xprivHdl, err := s.pkcs11Api.FindKeyByLabel(ctx, s.session, xprivLabel)
	if err != nil {
		return nil, err
	}
	pkHdl, _, err := s.DeriveKeyPair(ctx, s.session, xprivHdl, path)
	if err != nil {
		return nil, err
	}
	pk, err := s.pkcs11Api.GetPublicKey(ctx, s.session, pkHdl)
	if err != nil {
		return nil, err
	}
	return pk.ToSlice(), nil
}
