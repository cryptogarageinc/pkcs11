// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

// These tests depend on SoftHSM and the library being in
// in /usr/lib/softhsm/libsofthsm.so

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/cryptogarageinc/pkcs11"
	"github.com/stretchr/testify/assert"
)

/*
This test supports the following environment variables:

* SOFTHSM_LIB: complete path to libsofthsm.so
* SOFTHSM_TOKENLABEL
* SOFTHSM_PRIVKEYLABEL
* SOFTHSM_PIN
*/
var (
	libPath = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	pin     = "1234"
)

const (
	pkLabel  = "test-pk"
	skLabel  = "test-sk"
	testHash = "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"
)

func init() {
	if x := os.Getenv("SOFTHSM_LIB"); x != "" {
		libPath = x
	}
	if x := os.Getenv("SOFTHSM_PIN"); x != "" {
		pin = x
	}
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")
	os.Setenv("SOFTHSM2_CONF", wd+"/softhsm2.conf")

	SetContextLogger(func(_ context.Context, level LogLevel, message string, err error) {
		if err == nil {
			fmt.Printf("[%s] %s\n", level, message)
		} else {
			fmt.Printf("[%s] %s, err=%+v\n", level, message, err)
		}
	})
}

func getPkcs11() *pkcs11.Ctx {
	lib := libPath
	if x := os.Getenv("SOFTHSM_LIB"); x != "" {
		lib = x
	}
	return pkcs11.New(lib)
}

func TestPkcs11Api(t *testing.T) {
	p := getPkcs11()
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	defer p.Destroy()

	api := NewPkcs11(p, CurveSecp256k1)
	ctx := context.Background()
	err := api.Initialize(ctx)
	assert.NoError(t, err)
	defer api.Finalize(ctx)

	session, err := api.OpenSession(ctx, pin)
	assert.NoError(t, err)
	defer api.CloseSession(ctx, session)

	// create key
	var skHdl, pkHdl pkcs11.ObjectHandle
	if !testing.Short() {
		// BIP32
		// TODO: need implement
		t.Skip("not implement")
	}

	// (not bip32 case)
	pkHdl, skHdl, err = generateKeyPair(p, session, pkLabel, skLabel)
	assert.NoError(t, err)
	assert.NotEqual(t, pkHdl, 0)
	assert.NotEqual(t, skHdl, 0)
	if err == nil {
		defer func() {
			err := api.DestroyKey(ctx, session, skHdl)
			assert.NoError(t, err)
			err = api.DestroyKey(ctx, session, pkHdl)
			assert.NoError(t, err)
		}()
	}

	skHdl2, err := api.FindKeyByLabel(ctx, session, skLabel)
	assert.NoError(t, err)
	assert.Equal(t, skHdl, skHdl2)

	// sign key
	testHashByte, err := hex.DecodeString(testHash)
	assert.NoError(t, err)
	sig, err := api.GenerateSignature(ctx, session, skHdl, MechanismTypeEcdsa, testHashByte)
	assert.NoError(t, err)
	sigStr := sig.ToHex()
	fmt.Printf("sig: %s\n", sigStr)
	assert.NotEqual(t, sigStr,
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, len(sig), 64)

	// get pubkey
	pk, err := api.GetPublicKey(ctx, session, pkHdl)
	assert.NoError(t, err)
	pkStr := pk.ToHex()
	fmt.Printf("pk: %s\n", pkStr)
	assert.NotEqual(t, pkStr,
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, len(pk), 65)
}

func TestPkcs11ApiWithCurvePrime256v1(t *testing.T) {
	p := getPkcs11()
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	defer p.Destroy()

	api := NewPkcs11(p, CurveSecp256k1)
	ctx := context.Background()
	err := api.Initialize(ctx)
	assert.NoError(t, err)
	defer api.Finalize(ctx)

	session, err := api.OpenSession(ctx, pin)
	assert.NoError(t, err)
	defer api.CloseSession(ctx, session)

	// create key
	var skHdl, pkHdl pkcs11.ObjectHandle
	mech := pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)
	pkHdl, skHdl, err = api.GenerateKeyPairWithCurve(ctx, session, mech, CurvePrime256v1, pkcs11.CKK_ECDSA, pkLabel, skLabel, false)
	assert.NoError(t, err)
	assert.NotEqual(t, pkHdl, 0)
	assert.NotEqual(t, skHdl, 0)
	if err == nil {
		defer func() {
			err := api.DestroyKey(ctx, session, skHdl)
			assert.NoError(t, err)
			err = api.DestroyKey(ctx, session, pkHdl)
			assert.NoError(t, err)
		}()
	}

	skHdl2, err := api.FindKeyByLabel(ctx, session, skLabel)
	assert.NoError(t, err)
	assert.Equal(t, skHdl, skHdl2)

	// sign key
	testHashByte, err := hex.DecodeString(testHash)
	assert.NoError(t, err)
	sig, err := api.GenerateSignature(ctx, session, skHdl, MechanismTypeEcdsa, testHashByte)
	assert.NoError(t, err)
	sigStr := sig.ToHex()
	fmt.Printf("sig: %s\n", sigStr)
	assert.NotEqual(t, sigStr,
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, len(sig), 64)

	// get pubkey
	pk, err := api.GetPublicKey(ctx, session, pkHdl)
	assert.NoError(t, err)
	pkStr := pk.ToHex()
	fmt.Printf("pk: %s\n", pkStr)
	assert.NotEqual(t, pkStr,
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, len(pk), 65)
}

/*
func TestPkcs11ApiWithCurveEd25519(t *testing.T) {
	p := getPkcs11()
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	defer p.Destroy()

	api := NewPkcs11(p, CurveSecp256k1)
	ctx := context.Background()
	err := api.Initialize(ctx)
	assert.NoError(t, err)
	defer api.Finalize(ctx)

	session, err := api.OpenSession(ctx, pin)
	assert.NoError(t, err)
	defer api.CloseSession(ctx, session)

	// create key
	var skHdl, pkHdl pkcs11.ObjectHandle
	mech := pkcs11.NewMechanism(pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)
	pkHdl, skHdl, err = api.GenerateKeyPairWithCurve(ctx, session, mech, nil, pkcs11.CKK_EC_EDWARDS, pkLabel, skLabel, false)
	assert.NoError(t, err)
	assert.NotEqual(t, pkHdl, 0)
	assert.NotEqual(t, skHdl, 0)
	if err == nil {
		defer func() {
			err := api.DestroyKey(ctx, session, skHdl)
			assert.NoError(t, err)
			err = api.DestroyKey(ctx, session, pkHdl)
			assert.NoError(t, err)
		}()
	}

	skHdl2, err := api.FindKeyByLabel(ctx, session, skLabel)
	assert.NoError(t, err)
	assert.Equal(t, skHdl, skHdl2)

	// sign key
	testHashByte, err := hex.DecodeString(testHash)
	assert.NoError(t, err)
	sig, err := api.GenerateSignature(ctx, session, skHdl, MechanismTypeEddsa, testHashByte)
	assert.NoError(t, err)
	sigStr := sig.ToHex()
	fmt.Printf("sig: %s\n", sigStr)
	assert.NotEqual(t, sigStr,
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, len(sig), 64)

	// get pubkey
	pk, err := api.GetPublicKey(ctx, session, pkHdl)
	assert.NoError(t, err)
	pkStr := pk.ToHex()
	fmt.Printf("pk: %s\n", pkStr)
	assert.NotEqual(t, pkStr,
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	assert.Equal(t, len(pk), 65)
}
*/

func TestPkcs11Sessions(t *testing.T) {
	p := getPkcs11()
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	defer p.Destroy()

	api := NewPkcs11(p, CurveSecp256k1)
	ctx := context.Background()
	err := api.Initialize(ctx)
	assert.NoError(t, err)
	defer api.Finalize(ctx)

	session1, err := api.OpenSession(ctx, pin)
	assert.NoError(t, err)

	info1, err := p.GetSessionInfo(session1)
	assert.NoError(t, err)
	fmt.Printf("sessionInfo1, %v\n", info1)

	// close with finalize
}

func TestPkcs11ReLogin(t *testing.T) {
	p := getPkcs11()
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	defer p.Destroy()

	api := NewPkcs11(p, CurveSecp256k1)
	ctx := context.Background()
	err := api.Initialize(ctx)
	assert.NoError(t, err)
	defer api.Finalize(ctx)

	session1, err := api.OpenSession(ctx, pin)
	assert.NoError(t, err)

	info1, err := p.GetSessionInfo(session1)
	assert.NoError(t, err)
	fmt.Printf("sessionInfo1, %v\n", info1)

	err = api.ReLogin(ctx, session1, pin)
	assert.NoError(t, err)

	info2, err := p.GetSessionInfo(session1)
	assert.NoError(t, err)
	fmt.Printf("sessionInfo2, %v\n", info2)
	assert.Equal(t, info2, info1)

	// close with finalize
}

func TestPkcs11GenerateSeed(t *testing.T) {
	p := getPkcs11()
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	defer p.Destroy()

	api := NewPkcs11(p, CurveSecp256k1)
	ctx := context.Background()
	err := api.Initialize(ctx)
	assert.NoError(t, err)
	defer api.Finalize(ctx)

	session, err := api.OpenSession(ctx, pin)
	assert.NoError(t, err)
	defer api.CloseSession(ctx, session)

	hdl, err := api.GenerateSeed(ctx, session, "", 512/8)
	assert.NoError(t, err)
	assert.NotEqual(t, pkcs11.ObjectHandle(0), hdl)
}

func generateKeyPair(
	p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	pkLabel,
	skLabel string,
) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, CurveSecp256k1),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, pkLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, skLabel),
	}
	pk, sk, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	return pk, sk, err
}
