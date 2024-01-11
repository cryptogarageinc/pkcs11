// Copyright 2013 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

/*
#cgo windows CFLAGS: -DREPACK_STRUCTURES

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "pkcs11go.h"

struct ctx {
#ifdef _WIN32
	HINSTANCE handle;
#else
	void *handle;
#endif
	CK_FUNCTION_LIST_PTR sym;
};

#define CKM_BIP32_MASTER_DERIVE (CKM_VENDOR_DEFINED + 0xE00)
#define CKM_BIP32_CHILD_DERIVE (CKM_VENDOR_DEFINED + 0xE01)

typedef struct CK_BIP32_MASTER_DERIVE_PARAMS {
  CK_ATTRIBUTE_PTR pPublicKeyTemplate;
  CK_ULONG         ulPublicKeyAttributeCount;
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
  CK_ULONG         ulPrivateKeyAttributeCount;
  CK_OBJECT_HANDLE hPublicKey; // output parameter
  CK_OBJECT_HANDLE hPrivateKey; // output parameter
} CK_BIP32_MASTER_DERIVE_PARAMS;

typedef struct CK_BIP32_CHILD_DERIVE_PARAMS {
  CK_ATTRIBUTE_PTR pPublicKeyTemplate;
  CK_ULONG         ulPublicKeyAttributeCount;
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
  CK_ULONG         ulPrivateKeyAttributeCount;
  CK_ULONG_PTR     pulPath;
  CK_ULONG         ulPathLen;
  CK_OBJECT_HANDLE hPublicKey; // output parameter
  CK_OBJECT_HANDLE hPrivateKey; // output parameter
  CK_ULONG         ulPathErrorIndex; // output parameter
} CK_BIP32_CHILD_DERIVE_PARAMS;

CK_RV DeriveBIP32Master(struct ctx * c, CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE basekey,
    CK_ATTRIBUTE_PTR aPub, CK_ULONG alenPub,
    CK_ATTRIBUTE_PTR aPriv, CK_ULONG alenPriv,
    CK_OBJECT_HANDLE_PTR publicKey, CK_OBJECT_HANDLE_PTR privateKey)
{
  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_BIP32_MASTER_DERIVE;

  CK_BIP32_MASTER_DERIVE_PARAMS params;
  params.pPublicKeyTemplate = aPub;
  params.ulPublicKeyAttributeCount = alenPub;
  params.pPrivateKeyTemplate = aPriv;
  params.ulPrivateKeyAttributeCount = alenPriv;
  params.hPublicKey = 0;
  params.hPrivateKey = 0;

  mechanism.pParameter = &params;
  mechanism.ulParameterLen = sizeof(params);

  CK_RV e = c->sym->C_DeriveKey(session, &mechanism, basekey, NULL, 0, NULL);
  *publicKey = params.hPublicKey;
  *privateKey = params.hPrivateKey;
  return e;
}

CK_RV DeriveBIP32Child(struct ctx * c, CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE basekey,
    CK_ATTRIBUTE_PTR aPub, CK_ULONG alenPub,
    CK_ATTRIBUTE_PTR aPriv, CK_ULONG alenPriv, CK_ULONG_PTR path, CK_ULONG pathLen,
    CK_OBJECT_HANDLE_PTR publicKey, CK_OBJECT_HANDLE_PTR privateKey, CK_ULONG_PTR pathErrorIndex)
{
  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_BIP32_CHILD_DERIVE;

  CK_BIP32_CHILD_DERIVE_PARAMS params;
  params.pPublicKeyTemplate = aPub;
  params.ulPublicKeyAttributeCount = alenPub;
  params.pPrivateKeyTemplate = aPriv;
  params.ulPrivateKeyAttributeCount = alenPriv;
  params.pulPath = path;
  params.ulPathLen = pathLen;
  params.hPublicKey = 0;
  params.hPrivateKey = 0;
  params.ulPathErrorIndex = 0;

  mechanism.pParameter = &params;
  mechanism.ulParameterLen = sizeof(params);

  CK_RV e = c->sym->C_DeriveKey(session, &mechanism, basekey, NULL, 0, NULL);
  *publicKey = params.hPublicKey;
  *privateKey = params.hPrivateKey;
  *pathErrorIndex = params.ulPathErrorIndex;
  return e;
}

CK_RV OpenSessionWithPartition(struct ctx * c, CK_ULONG slotID, CK_ULONG partitionID,
      CK_ULONG flags, CK_SESSION_HANDLE_PTR session)
{
	CK_RV e =
	    c->sym->CA_OpenSession((CK_SLOT_ID) slotID, partitionID, (CK_FLAGS) flags,
          NULL, NULL, session);
	return e;
}

*/
import "C"

// CKK_BIP32 should be assigned to the CKA_KEY_TYPE attribute of templates for derived keys
const CKK_BIP32 = CKK_VENDOR_DEFINED + 0x14
const CKA_DERIVE_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000213)
const CKA_BIP32_VERSION_BYTES = (CKA_VENDOR_DEFINED | 0x1101)
const CKA_BIP32_CHILD_INDEX = (CKA_VENDOR_DEFINED | 0x1102)
const CKA_BIP32_CHILD_DEPTH = (CKA_VENDOR_DEFINED | 0x1103)
const CKA_BIP32_ID = (CKA_VENDOR_DEFINED | 0x1104)
const CKA_BIP32_FINGERPRINT = (CKA_VENDOR_DEFINED | 0x1105)
const CKA_BIP32_PARENT_FINGERPRINT = (CKA_VENDOR_DEFINED | 0x1106)

// for Ed25519
const CKK_EC_EDWARDS = (CKK_VENDOR_DEFINED | 0x00008003)
const CKM_EC_EDWARDS_KEY_PAIR_GEN = (CKM_VENDOR_DEFINED | 0x00009040)
const CKM_EDDSA = (CKM_VENDOR_DEFINED | 0x00009041)

func (c *Ctx) DeriveBIP32MasterKeys(sh SessionHandle, basekey ObjectHandle, publicAttr []*Attribute, privateAttr []*Attribute) (ObjectHandle, ObjectHandle, error) {
	var publicKey C.CK_OBJECT_HANDLE
	var privateKey C.CK_OBJECT_HANDLE
	publicAttrArena, publicAttrC, publicAttrLen := cAttributeList(publicAttr)
	defer publicAttrArena.Free()
	privateAttrArena, privateAttrC, privateAttrLen := cAttributeList(privateAttr)
	defer privateAttrArena.Free()
	e := C.DeriveBIP32Master(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(basekey), publicAttrC, publicAttrLen, privateAttrC, privateAttrLen, &publicKey, &privateKey)
	return ObjectHandle(publicKey), ObjectHandle(privateKey), toError(e)
}

func (c *Ctx) DeriveBIP32ChildKeys(sh SessionHandle, basekey ObjectHandle, publicAttr []*Attribute, privateAttr []*Attribute, path []uint32) (ObjectHandle, ObjectHandle, uint, error) {
	var publicKey C.CK_OBJECT_HANDLE
	var privateKey C.CK_OBJECT_HANDLE
	var pathErrorIndex C.CK_ULONG
	publicAttrArena, publicAttrC, publicAttrLen := cAttributeList(publicAttr)
	defer publicAttrArena.Free()
	privateAttrArena, privateAttrC, privateAttrLen := cAttributeList(privateAttr)
	defer privateAttrArena.Free()
	cPath := make([]C.CK_ULONG, len(path))
	for i, pathVal := range path {
		cPath[i] = C.CK_ULONG(pathVal)
	}
	e := C.DeriveBIP32Child(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(basekey), publicAttrC, publicAttrLen, privateAttrC, privateAttrLen, &cPath[0], C.CK_ULONG(len(path)), &publicKey, &privateKey, &pathErrorIndex)
	return ObjectHandle(publicKey), ObjectHandle(privateKey), uint(pathErrorIndex), toError(e)
}

// OpenSessionWithPartition opens a session between an application and a token and a partition.
func (c *Ctx) OpenSessionWithPartition(slotID uint, partitionID uint, flags uint) (SessionHandle, error) {
	var s C.CK_SESSION_HANDLE
	e := C.OpenSessionWithPartition(c.ctx, C.CK_ULONG(slotID), C.CK_ULONG(partitionID), C.CK_ULONG(flags), C.CK_SESSION_HANDLE_PTR(&s))
	return SessionHandle(s), toError(e)
}
