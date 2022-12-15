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
	"time"

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

func TestPkcs11Api(t *testing.T) {
	lib := libPath
	if x := os.Getenv("SOFTHSM_LIB"); x != "" {
		lib = x
	}
	p := pkcs11.New(lib)
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	defer p.Destroy()

	api := NewPkcs11(p, CurveSecp256k1).WithSessionCheckDuration(time.Second)
	ctx := context.Background()
	err := api.Initialize(ctx)
	assert.NoError(t, err)
	dumpError(err)
	defer api.Finalize(ctx)

	session, err := api.OpenSession(ctx, pin)
	assert.NoError(t, err)
	dumpError(err)
	defer api.CloseSession(ctx, session)

	// create key
	var skHdl, pkHdl pkcs11.ObjectHandle
	if testing.Short() {
		// (not bip32 case)
		pkHdl, skHdl, err = generateKeyPair(p, session, "test-pk", "test-sk")
		assert.NoError(t, err)
		dumpError(err)
		assert.NotEqual(t, pkHdl, 0)
		assert.NotEqual(t, skHdl, 0)

		skHdl2, err := api.FindKeyByLabel(ctx, session, skLabel)
		assert.NoError(t, err)
		dumpError(err)
		assert.Equal(t, skHdl, skHdl2)
	} else {
		// BIP32
		// TODO: need implement
	}

	// sign key
	testHashByte, err := hex.DecodeString(testHash)
	assert.NoError(t, err)
	sig, err := api.GenerateSignature(ctx, session, skHdl, MechanismTypeEcdsa, testHashByte)
	assert.NoError(t, err)
	dumpError(err)
	sigStr := hex.EncodeToString(sig[:])
	assert.NotEqual(t, sigStr,
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	fmt.Printf("sig: %s\n", sigStr)

	// get pubkey
	pk, err := api.GetPublicKey(ctx, session, pkHdl)
	assert.NoError(t, err)
	dumpError(err)
	pkStr := hex.EncodeToString(pk[:])
	fmt.Printf("pk: %s\n", pkStr)
	assert.NotEqual(t, pkStr,
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
}

func dumpError(err error) {
	if err != nil {
		fmt.Printf("error: %+v\n", err)
	}
}

func generateKeyPair(
	p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	pkLabel,
	skLabel string,
) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, CurveSecp256k1),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, pkLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, skLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	pk, sk, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	return pk, sk, err
}
