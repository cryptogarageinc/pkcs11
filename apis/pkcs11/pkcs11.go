package pkcs11

import (
	"context"
	"time"

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
	Initialize(ctx context.Context) error
	Finalize(ctx context.Context)

	// OpenSession creates a session and login an user.
	OpenSession(ctx context.Context, pin string) (session pkcs11.SessionHandle, err error)
	OpenSessionWithPartition(ctx context.Context, partitionID uint, pin string) (session pkcs11.SessionHandle, err error)
	CloseSession(ctx context.Context, session pkcs11.SessionHandle)

	FindKeyByLabel(
		ctx context.Context,
		session pkcs11.SessionHandle,
		label string,
	) (key pkcs11.ObjectHandle, err error)

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
	) (signature [64]byte, err error)

	GetPublicKey(
		ctx context.Context,
		session pkcs11.SessionHandle,
		pubkeyHandle pkcs11.ObjectHandle,
	) (pubkey [65]byte, err error)
}

func NewPkcs11(ctx *pkcs11.Ctx, namedCurveOid []byte) *pkcs11Api {
	return &pkcs11Api{
		pkcs11Obj:            ctx,
		namedCurveOid:        namedCurveOid,
		sessionCheckChMap:    make(map[pkcs11.SessionHandle]chan struct{}),
		sessionCheckDuration: time.Hour,
	}
}

var _ Pkcs11 = (*pkcs11Api)(nil)

type pkcs11Api struct {
	pkcs11Obj            *pkcs11.Ctx
	namedCurveOid        []byte
	sessionCheckChMap    map[pkcs11.SessionHandle]chan struct{}
	sessionCheckDuration time.Duration
}

func (p *pkcs11Api) WithSessionCheckDuration(duration time.Duration) *pkcs11Api {
	p.sessionCheckDuration = duration
	return p
}

func (p *pkcs11Api) Initialize(ctx context.Context) error {
	err := p.pkcs11Obj.Initialize()
	if err != nil {
		logging(ctx, LogError, "Initialize", err, "")
		return err
	}
	logging(ctx, LogInfo, "Initialize", nil, "")
	return nil
}

func (p *pkcs11Api) Finalize(ctx context.Context) {
	if len(p.sessionCheckChMap) != 0 {
		for session := range p.sessionCheckChMap {
			p.CloseSession(ctx, session)
		}
	}

	err := p.pkcs11Obj.Finalize()
	if err != nil {
		logging(ctx, LogError, "Finalize.Finalize", err, "")
		return
	}
	logging(ctx, LogInfo, "Finalize", nil, "")
}

func (p *pkcs11Api) OpenSession(ctx context.Context, pin string) (session pkcs11.SessionHandle, err error) {
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
		logging(ctx, LogError, "CloseSession.Logout", err, "")
		// fall-through
	}
	if ch, ok := p.sessionCheckChMap[session]; ok {
		close(ch)
		delete(p.sessionCheckChMap, session)
	}

	err = p.pkcs11Obj.CloseSession(session)
	if err != nil {
		logging(ctx, LogError, "CloseSession.CloseSession", err, "")
		return
	}
	logging(ctx, LogInfo, "CloseSession", nil, "")
}

func (p *pkcs11Api) FindKeyByLabel(
	ctx context.Context,
	session pkcs11.SessionHandle,
	label string,
) (key pkcs11.ObjectHandle, err error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	handles, err := p.findAttr(ctx, session, template, 2)
	if err != nil {
		logging(ctx, LogError, "FindKeyByLabel.findAttr", err, "")
		return 0, err
	}
	switch len(handles) {
	case 1:
		// success
	case 0:
		err = errors.New("target is empty")
		logging(ctx, LogError, "FindKeyByLabel", err, "")
		return 0, err
	default:
		err = errors.Errorf("target is many, %d", len(handles))
		logging(ctx, LogError, "FindKeyByLabel", err, "")
		return 0, err
	}
	key = handles[0]
	return key, nil
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
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
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
		logging(ctx, LogError, "DeriveKeyPair", err, "")
		return 0, 0, err
	}
	logging(ctx, LogError, "DeriveKeyPair", nil, "")
	return pubkeyHandle, privkeyHandle, nil
}

func (p *pkcs11Api) GenerateSignature(
	ctx context.Context,
	session pkcs11.SessionHandle,
	privkeyHandle pkcs11.ObjectHandle,
	mechanismType uint,
	message []byte,
) (signature [64]byte, err error) {
	mechanisms := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismType, nil)}
	err = p.pkcs11Obj.SignInit(session, mechanisms, privkeyHandle)
	if err != nil {
		logging(ctx, LogError, "GenerateSignature.SignInit", err, "")
		return signature, err
	}
	data, err := p.pkcs11Obj.Sign(session, message)
	if err != nil {
		logging(ctx, LogError, "GenerateSignature.Sign", err, "")
		return signature, err
	}

	signature = [64]byte{}
	copy(signature[:], data)
	logging(ctx, LogInfo, "GenerateSignature", nil, "")
	return signature, nil
}

func (p *pkcs11Api) GetPublicKey(
	ctx context.Context,
	session pkcs11.SessionHandle,
	pubkeyHandle pkcs11.ObjectHandle,
) (pubkey [65]byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	attr, err := p.pkcs11Obj.GetAttributeValue(session, pubkeyHandle, template)
	if err != nil {
		logging(ctx, LogError, "GetPublicKey.GetAttributeValue", err, "")
		return pubkey, err
	}
	pubkey = [65]byte{}
	switch len(attr[0].Value) {
	case 65:
		copy(pubkey[:], attr[0].Value)
	case 67: // asn1 encoding
		copy(pubkey[:], attr[0].Value[2:])
	default:
		err = errors.Errorf("invalid length: %d", len(attr[0].Value))
		logging(ctx, LogError, "GetPublicKey", err, "")
		return pubkey, err
	}
	logging(ctx, LogInfo, "GetPublicKey", nil, "")
	return pubkey, err
}

func (p *pkcs11Api) getSlotID() (uint, error) {
	slots, err := p.pkcs11Obj.GetSlotList(true)
	if err != nil {
		return 0, err
	} else if len(slots) == 0 {
		return 0, errors.New("slot is empty")
	}
	return slots[0], nil
}

func (p *pkcs11Api) openSession(
	ctx context.Context,
	partitionID *uint,
	pin string,
) (session pkcs11.SessionHandle, err error) {
	slotID, err := p.getSlotID()
	if err != nil {
		logging(ctx, LogError, "openSession.getSlotID", err, "")
		return 0, err
	}

	if partitionID == nil {
		session, err = p.pkcs11Obj.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			logging(ctx, LogError, "openSession.OpenSession", err, "")
			return 0, errors.Wrap(err, "openSession failed")
		}
	} else {
		session, err = p.pkcs11Obj.OpenSessionWithPartition(slotID, *partitionID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			logging(ctx, LogError, "openSession.OpenSession", err, "")
			return 0, errors.Wrap(err, "openSession failed")
		}
	}
	if err = p.pkcs11Obj.Login(session, pkcs11.CKU_USER, pin); err != nil {
		logging(ctx, LogError, "openSession.Login", err, "")
		tmpErr := p.pkcs11Obj.CloseSession(session)
		if tmpErr != nil {
			logging(ctx, LogError, "openSession.CloseSession", tmpErr, "")
		}
		return 0, errors.Wrap(err, "openSession failed")
	}

	ch := make(chan struct{}, 1)
	if p.sessionCheckDuration > 0 {
		go func() {
			ticker := time.NewTicker(p.sessionCheckDuration)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					_, chkErr := p.pkcs11Obj.GetInfo()
					if chkErr != nil {
						logging(ctx, LogWarn, "GetInfo", chkErr, "")
					}
				case <-ch:
					return
				}
			}
		}()
	}
	p.sessionCheckChMap[session] = ch
	return session, nil
}

func (p *pkcs11Api) findAttr(
	ctx context.Context,
	session pkcs11.SessionHandle,
	template []*pkcs11.Attribute,
	maxNum int,
) ([]pkcs11.ObjectHandle, error) {
	if err := p.pkcs11Obj.FindObjectsInit(session, template); err != nil {
		return nil, err
	}
	obj, _, err := p.pkcs11Obj.FindObjects(session, maxNum)
	if err != nil {
		tmpErr := p.pkcs11Obj.FindObjectsFinal(session)
		if tmpErr != nil {
			logging(ctx, LogError, "openSession.CloseSession", tmpErr, "")
		}
		return nil, err
	}
	if err := p.pkcs11Obj.FindObjectsFinal(session); err != nil {
		return nil, err
	}
	return obj, nil
}
