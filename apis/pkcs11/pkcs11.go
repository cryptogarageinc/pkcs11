package pkcs11

import (
	"context"

	"github.com/cryptogarageinc/pkcs11"
	"github.com/pkg/errors"
)

// Type: ECDSA
const MechanismTypeEcdsa uint = pkcs11.CKM_ECDSA

var CurveSecp256k1 = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a}

// go generate comment
//go:generate -command mkdir mock
//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -source pkcs11.go -destination mock/pkcs11.go -package mock
//go:generate go run golang.org/x/tools/cmd/goimports@v0.4.0 -w mock/pkcs11.go

type Pkcs11 interface {
	GetPkcs11Context() *pkcs11.Ctx
	Initialize(ctx context.Context) error
	Finalize(ctx context.Context)

	// OpenSession creates a session and login an user.
	OpenSession(
		ctx context.Context,
		pin string,
	) (session pkcs11.SessionHandle, err error)
	// OpenSessionWithPartition creates a session for a partition, and login an user.
	OpenSessionWithPartition(
		ctx context.Context,
		partitionID uint,
		pin string,
	) (session pkcs11.SessionHandle, err error)
	// CloseSession deletes a session and logout an user.
	CloseSession(ctx context.Context, session pkcs11.SessionHandle)
	// ReLogin does logout and re-login.
	ReLogin(ctx context.Context, session pkcs11.SessionHandle, pin string) error

	FindKeyByLabel(
		ctx context.Context,
		session pkcs11.SessionHandle,
		label string,
	) (key pkcs11.ObjectHandle, err error)
	CreateXprivFromSeed(
		ctx context.Context,
		session pkcs11.SessionHandle,
		seedHandle pkcs11.ObjectHandle,
		xpubLabel, // if not empty, set to token=true.
		xprivLabel string, // if not empty, set to token=true.
		canExport bool,
	) (pubkeyHandle pkcs11.ObjectHandle, privkeyHandle pkcs11.ObjectHandle, err error)
	DeriveKeyPair(
		ctx context.Context,
		session pkcs11.SessionHandle,
		masterXprivHandle pkcs11.ObjectHandle,
		path []uint32,
	) (pubkeyHandle pkcs11.ObjectHandle, privkeyHandle pkcs11.ObjectHandle, err error)

	GenerateSignature(
		ctx context.Context,
		session pkcs11.SessionHandle,
		privkeyHandle pkcs11.ObjectHandle,
		mechanismType uint,
		message []byte,
	) (signature SignatureBytes, err error)

	GetPublicKey(
		ctx context.Context,
		session pkcs11.SessionHandle,
		pubkeyHandle pkcs11.ObjectHandle,
	) (pubkey PublicKeyBytes, err error)

	ImportSeed(
		ctx context.Context,
		session pkcs11.SessionHandle,
		seedBytes []byte,
		label string, // if not empty, set to token=true.
	) (seedHandle pkcs11.ObjectHandle, err error)
	ImportXpriv(
		ctx context.Context,
		session pkcs11.SessionHandle,
		xpriv,
		label string, // if not empty, set to token=true.
		canExport bool,
	) (xprivHandle pkcs11.ObjectHandle, err error)
	ExportXpriv(
		ctx context.Context,
		session pkcs11.SessionHandle,
		xprivHandle pkcs11.ObjectHandle,
	) (xpriv string, err error)
}

func NewPkcs11(pkcs11Ctx *pkcs11.Ctx, namedCurveOid []byte) *pkcs11Api {
	return &pkcs11Api{
		pkcs11Obj:            pkcs11Ctx,
		namedCurveOid:        namedCurveOid,
		targetSlot:           -1,
	}
}

var _ Pkcs11 = (*pkcs11Api)(nil)

// TODO: Exclusive control should be performed by the caller.
type pkcs11Api struct {
	pkcs11Obj            *pkcs11.Ctx
	namedCurveOid        []byte
	initialized          bool
	targetSlot           int
	currentSlot          uint
}

func (p *pkcs11Api) WithSlot(slot int) *pkcs11Api {
	if slot >= 0 {
		p.targetSlot = slot
	}
	return p
}

func (p *pkcs11Api) GetPkcs11Context() *pkcs11.Ctx {
	return p.pkcs11Obj
}

func (p *pkcs11Api) Initialize(ctx context.Context) error {
	if p.initialized {
		return nil
	}

	err := p.pkcs11Obj.Initialize()
	if err != nil {
		logError(ctx, "Initialize", err)
		return err
	}
	logInfo(ctx, "Initialize success")
	p.initialized = true
	return nil
}

func (p *pkcs11Api) Finalize(ctx context.Context) {
	if !p.initialized {
		logError(ctx, "Finalize", errors.New("already finalized"))
		return
	}

	if err := p.pkcs11Obj.CloseAllSessions(p.currentSlot); err != nil {
		logWarn(ctx, "Finalize.CloseAllSessions", err)
	}

	if err := p.pkcs11Obj.Finalize(); err != nil {
		logError(ctx, "Finalize.Finalize", err)
		return
	}
	logInfo(ctx, "Finalize success")
	p.initialized = false
}

func (p *pkcs11Api) OpenSession(
	ctx context.Context,
	pin string,
) (session pkcs11.SessionHandle, err error) {
	return p.openSession(ctx, nil, pin)
}

func (p *pkcs11Api) OpenSessionWithPartition(
	ctx context.Context,
	partitionID uint,
	pin string,
) (session pkcs11.SessionHandle, err error) {
	return p.openSession(ctx, &partitionID, pin)
}

func (p *pkcs11Api) CloseSession(ctx context.Context, session pkcs11.SessionHandle) {
	err := p.pkcs11Obj.Logout(session)
	if err != nil {
		logWarn(ctx, "CloseSession.Logout", err)
		// fall-through
	}

	err = p.pkcs11Obj.CloseSession(session)
	if err != nil {
		logError(ctx, "CloseSession.CloseSession", err)
		return
	}
	logInfo(ctx, "CloseSession success")
}

func (p *pkcs11Api) ReLogin(ctx context.Context, session pkcs11.SessionHandle, pin string) error {
	if err := p.pkcs11Obj.Logout(session); err != nil {
		logWarn(ctx, "ReLogin.Logout", err)
	}

	if err := p.pkcs11Obj.Login(session, pkcs11.CKU_USER, pin); err != nil {
		logError(ctx, "ReLogin.Login", err)
		err = errors.Wrap(err, "ReLogin failed")
		return err
	}
	return nil
}

func (p *pkcs11Api) FindKeyByLabel(
	ctx context.Context,
	session pkcs11.SessionHandle,
	label string,
) (key pkcs11.ObjectHandle, err error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	handles, err := p.findAttr(ctx, session, template, 2)
	if err != nil {
		logError(ctx, "FindKeyByLabel.findAttr", err)
		return 0, err
	}
	switch len(handles) {
	case 1:
		// success
	case 0:
		err = errors.New("target is empty")
		logError(ctx, "FindKeyByLabel", err)
		return 0, err
	default:
		err = errors.Errorf("target is many, %d", len(handles))
		logError(ctx, "FindKeyByLabel", err)
		return 0, err
	}
	key = handles[0]
	logInfo(ctx, "FindKeyByLabel success")
	return key, nil
}

func (p *pkcs11Api) CreateXprivFromSeed(
	ctx context.Context,
	session pkcs11.SessionHandle,
	seedHandle pkcs11.ObjectHandle,
	xpubLabel,
	xprivLabel string,
	canExport bool,
) (pubkeyHandle pkcs11.ObjectHandle, privkeyHandle pkcs11.ObjectHandle, err error) {
	var xpubToken, xprivToken bool
	if xpubLabel != "" {
		xpubToken = true
	}
	if xprivLabel != "" {
		xprivToken = true
	}
	pubKeyAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, xpubToken),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_BIP32),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, xpubLabel),
	}
	privKeyAttr := p.getMasterXprivTemplate(xprivLabel, xprivToken, canExport)
	pubkeyHandle, privkeyHandle, err = p.pkcs11Obj.DeriveBIP32MasterKeys(
		session, seedHandle, pubKeyAttr, privKeyAttr)
	if err != nil {
		err = errors.WithStack(err)
		logError(ctx, "CreateXprivFromSeed", err)
		return 0, 0, err
	}
	logInfo(ctx, "CreateXprivFromSeed success")
	return pubkeyHandle, privkeyHandle, nil
}

func (p *pkcs11Api) DeriveKeyPair(
	ctx context.Context,
	session pkcs11.SessionHandle,
	masterXprivHandle pkcs11.ObjectHandle,
	path []uint32,
) (pubkeyHandle pkcs11.ObjectHandle, privkeyHandle pkcs11.ObjectHandle, err error) {
	pubKeyAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_BIP32),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
	}
	privKeyAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_BIP32),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	pubkeyHandle, privkeyHandle, pathErrIdx, err := p.pkcs11Obj.DeriveBIP32ChildKeys(
		session, masterXprivHandle, pubKeyAttr, privKeyAttr, path)
	if err != nil {
		err = errors.Wrapf(err, "pathErrIdx: %d", pathErrIdx)
		logError(ctx, "DeriveKeyPair", err)
		return 0, 0, err
	}
	logInfo(ctx, "DeriveKeyPair success")
	return pubkeyHandle, privkeyHandle, nil
}

func (p *pkcs11Api) GenerateSignature(
	ctx context.Context,
	session pkcs11.SessionHandle,
	privkeyHandle pkcs11.ObjectHandle,
	mechanismType uint,
	message []byte,
) (signature SignatureBytes, err error) {
	mechanisms := GetMechanismSimple(mechanismType)
	err = p.pkcs11Obj.SignInit(session, mechanisms, privkeyHandle)
	if err != nil {
		logError(ctx, "GenerateSignature.SignInit", err)
		return signature, err
	}
	data, err := p.pkcs11Obj.Sign(session, message)
	if err != nil {
		logError(ctx, "GenerateSignature.Sign", err)
		return signature, err
	}

	signature = SignatureBytes{}
	copy(signature[:], data)
	logInfo(ctx, "GenerateSignature success")
	return signature, nil
}

func (p *pkcs11Api) GetPublicKey(
	ctx context.Context,
	session pkcs11.SessionHandle,
	pubkeyHandle pkcs11.ObjectHandle,
) (pubkey PublicKeyBytes, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	attr, err := p.pkcs11Obj.GetAttributeValue(session, pubkeyHandle, template)
	if err != nil {
		logError(ctx, "GetPublicKey.GetAttributeValue", err)
		return pubkey, err
	}
	pubkey = PublicKeyBytes{}
	switch len(attr[0].Value) {
	case 65:
		copy(pubkey[:], attr[0].Value)
	case 67: // asn1 encoding
		copy(pubkey[:], attr[0].Value[2:])
	default:
		err = errors.Errorf("invalid length, %d", len(attr[0].Value))
		logError(ctx, "GetPublicKey", err)
		return pubkey, err
	}
	logInfo(ctx, "GetPublicKey success")
	return pubkey, err
}

func (p *pkcs11Api) ImportSeed(
	ctx context.Context,
	session pkcs11.SessionHandle,
	seedBytes []byte,
	label string,
) (seedHandle pkcs11.ObjectHandle, err error) {
	aesTemplate, aesMech := p.getAesTemplate()
	wrappingKey, err := p.pkcs11Obj.GenerateKey(session, aesMech, aesTemplate)
	if err != nil {
		logError(ctx, "ImportSeed.GenerateKey", err)
		return 0, errors.Wrap(err, "ImportSeed failed")
	}

	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv)}
	err = p.pkcs11Obj.EncryptInit(session, mech, wrappingKey)
	if err != nil {
		logError(ctx, "ImportSeed.EncryptInit", err)
		return 0, errors.Wrap(err, "ImportSeed failed")
	}
	encrypted, err := p.pkcs11Obj.Encrypt(session, seedBytes)
	if err != nil {
		logError(ctx, "ImportSeed.Encrypt", err)
		return 0, errors.Wrap(err, "ImportSeed failed")
	}

	token := false
	if label != "" {
		token = true
	}
	seedTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, token),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, len(seedBytes)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	seedHandle, err = p.pkcs11Obj.UnwrapKey(
		session, mech, wrappingKey, encrypted, seedTemplate)
	if err != nil {
		logError(ctx, "ImportSeed.UnwrapKey", err)
		return 0, errors.Wrap(err, "ImportSeed failed")
	}
	return seedHandle, nil
}

func (p *pkcs11Api) ImportXpriv(
	ctx context.Context,
	session pkcs11.SessionHandle,
	xpriv,
	label string,
	canExport bool,
) (xprivHandle pkcs11.ObjectHandle, err error) {
	aesTemplate, aesMech := p.getAesTemplate()
	wrappingKey, err := p.pkcs11Obj.GenerateKey(session, aesMech, aesTemplate)
	if err != nil {
		logError(ctx, "ImportXpriv.GenerateKey", err)
		return 0, errors.Wrap(err, "ImportXpriv failed")
	}

	mechanisms := GetMechanismSimple(pkcs11.CKM_AES_KEY_WRAP)
	if err := p.pkcs11Obj.EncryptInit(session, mechanisms, wrappingKey); err != nil {
		logError(ctx, "ImportXpriv.EncryptInit", err)
		return 0, errors.Wrap(err, "ImportXpriv failed")
	}
	encrypted, err := p.pkcs11Obj.Encrypt(session, []byte(xpriv))
	if err != nil {
		logError(ctx, "ImportXpriv.Encrypt", err)
		return 0, errors.Wrap(err, "ImportXpriv failed")
	}
	xprivToken := false
	if label != "" {
		xprivToken = true
	}
	keyTemplate := p.getMasterXprivTemplate(label, xprivToken, canExport)
	xprivHandle, err = p.pkcs11Obj.UnwrapKey(
		session, mechanisms, wrappingKey, encrypted, keyTemplate)
	if err != nil {
		logError(ctx, "ImportXpriv.UnwrapKey", err)
		return 0, errors.Wrap(err, "ImportXpriv failed")
	}
	logInfo(ctx, "ImportXpriv success")
	return xprivHandle, nil
}

func (p *pkcs11Api) ExportXpriv(
	ctx context.Context,
	session pkcs11.SessionHandle,
	xprivHandle pkcs11.ObjectHandle,
) (xpriv string, err error) {
	aesTemplate, aesMech := p.getAesTemplate()
	wrappingKey, err := p.pkcs11Obj.GenerateKey(session, aesMech, aesTemplate)
	if err != nil {
		logError(ctx, "ExportXpriv.GenerateKey", err)
		return "", errors.Wrap(err, "ExportXpriv failed")
	}

	mechanisms := GetMechanismSimple(pkcs11.CKM_AES_KEY_WRAP)
	wrappedKeyBytes, err := p.pkcs11Obj.WrapKey(
		session, mechanisms, wrappingKey, xprivHandle)
	if err != nil {
		logError(ctx, "ExportXpriv.WrapKey", err)
		return "", errors.Wrap(err, "ExportXpriv failed")
	}
	if err := p.pkcs11Obj.DecryptInit(session, mechanisms, wrappingKey); err != nil {
		logError(ctx, "ExportXpriv.DecryptInit", err)
		return "", errors.Wrap(err, "ExportXpriv failed")
	}
	keyBytes, err := p.pkcs11Obj.Decrypt(session, wrappedKeyBytes)
	if err != nil {
		logError(ctx, "ExportXpriv.Decrypt", err)
		return "", errors.Wrap(err, "ExportXpriv failed")
	} else if len(keyBytes) == 0 {
		err = errors.New("failed to export key")
		logError(ctx, "ExportXpriv empty key length", err)
		return "", err
	}
	xpriv = string(keyBytes)
	logInfof(ctx, "ExportXpriv success. keyLen=%d", len(keyBytes))
	return xpriv, nil
}

func (p *pkcs11Api) openSession(
	ctx context.Context,
	partitionID *uint,
	pin string,
) (session pkcs11.SessionHandle, err error) {
	slotID, err := p.getSlotID(ctx)
	if err != nil {
		logError(ctx, "openSession.getSlotID", err)
		return 0, err
	}

	if partitionID == nil {
		session, err = p.pkcs11Obj.OpenSession(
			slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			logError(ctx, "openSession.OpenSession", err)
			return 0, errors.Wrap(err, "openSession failed")
		}
	} else {
		session, err = p.pkcs11Obj.OpenSessionWithPartition(
			slotID, *partitionID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			logError(ctx, "openSession.OpenSessionWithPartition", err)
			return 0, errors.Wrap(err, "openSession failed")
		}
	}
	if err = p.pkcs11Obj.Login(session, pkcs11.CKU_USER, pin); err != nil {
		logError(ctx, "openSession.Login", err)
		tmpErr := p.pkcs11Obj.CloseSession(session)
		if tmpErr != nil {
			logError(ctx, "openSession.CloseSession", tmpErr)
		}
		return 0, errors.Wrap(err, "openSession failed")
	}

	logInfo(ctx, "openSession success")
	p.currentSlot = slotID
	return session, nil
}

func (p *pkcs11Api) getSlotID(ctx context.Context) (uint, error) {
	slots, err := p.pkcs11Obj.GetSlotList(true)
	if err != nil {
		return 0, err
	} else if len(slots) == 0 {
		return 0, errors.New("slot is empty")
	}
	logInfof(ctx, "getSlotID %v", slots)
	if p.targetSlot >= 0 {
		for _, slot := range slots {
			if slot == uint(p.targetSlot) {
				return slot, nil
			}
		}
		return 0, errors.New("target slot is not found")
	}
	// use a first slot
	return slots[0], nil
}

func (p *pkcs11Api) findAttr(
	ctx context.Context,
	session pkcs11.SessionHandle,
	template []*pkcs11.Attribute,
	maxNum int,
) ([]pkcs11.ObjectHandle, error) {
	if err := p.pkcs11Obj.FindObjectsInit(session, template); err != nil {
		err = errors.Wrapf(err, "FindObjectsInit failed")
		return nil, err
	}
	obj, _, err := p.pkcs11Obj.FindObjects(session, maxNum)
	if err != nil {
		err = errors.Wrapf(err, "FindObjects failed")
		tmpErr := p.pkcs11Obj.FindObjectsFinal(session)
		if tmpErr != nil {
			logError(ctx, "findAttr.FindObjectsFinal", tmpErr)
		}
		return nil, err
	}
	if err := p.pkcs11Obj.FindObjectsFinal(session); err != nil {
		err = errors.Wrapf(err, "FindObjectsFinal failed")
		return nil, err
	}
	return obj, nil
}

func (p *pkcs11Api) getAesTemplate() ([]*pkcs11.Attribute, []*pkcs11.Mechanism) {
	aesTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	}
	aesMech := GetMechanismSimple(pkcs11.CKM_AES_KEY_GEN)
	return aesTemplate, aesMech
}

func (p *pkcs11Api) getMasterXprivTemplate(label string, token, extractable bool) []*pkcs11.Attribute {
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, token),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_BIP32),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	return keyTemplate
}
