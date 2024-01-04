// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"
)

func TestDuplicate(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	trial := util.ComputeAuthPolicy(HashAlgorithmSHA256)
	trial.PolicyCommandCode(CommandDuplicate)

	template := &Public{
		Type:       ObjectTypeRSA,
		NameAlg:    HashAlgorithmSHA256,
		Attrs:      AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrSign,
		AuthPolicy: trial.GetDigest(),
		Params: MakePublicParamsUnion(
			RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme:    RSAScheme{Scheme: RSASchemeNull},
				KeyBits:   2048,
				Exponent:  0,
			},
		),
	}
	sensitive := &SensitiveCreate{UserAuth: []byte("foo")}
	priv, pub, _, _, _, err := tpm.Create(primary, sensitive, template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	object, err := tpm.Load(primary, priv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, object)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	parentPub := &Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrRestricted | AttrDecrypt,
		Params: MakePublicParamsUnion(
			RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   MakeSymKeyBitsUnion[uint16](128),
					Mode:      MakeSymModeUnion(SymModeCFB)},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: uint32(key.PublicKey.E),
			},
		),
		Unique: MakePublicIDUnion(PublicKeyRSA(key.PublicKey.N.Bytes())),
	}
	parent, err := tpm.LoadExternal(nil, parentPub, HandleOwner)
	if err != nil {
		t.Fatalf("LoadExternal failed: %v", err)
	}
	defer flushContext(t, tpm, parent)

	run := func(t *testing.T, newParentContext ResourceContext, encryptionKeyIn Data, symmetricAlg *SymDefObject) (Data, Private, EncryptedSecret) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		if err := tpm.PolicyCommandCode(sessionContext, CommandDuplicate); err != nil {
			t.Fatalf("PolicyCommandCode failed: %v", err)
		}

		encryptionKeyOut, duplicate, outSymSeed, err := tpm.Duplicate(object, newParentContext, encryptionKeyIn, symmetricAlg, sessionContext)
		if err != nil {
			t.Fatalf("Duplicate failed: %v", err)
		}

		return encryptionKeyOut, duplicate, outSymSeed
	}

	verifyDuplicate := func(t *testing.T, duplicate Private, outer bool, encryptionKey Data, inSymSeed EncryptedSecret, symmetricAlg *SymDefObject) {
		var privKey crypto.PrivateKey
		parentNameAlg := HashAlgorithmNull
		var parentSymmetricAlg *SymDefObject
		if outer {
			privKey = key
			parentNameAlg = parentPub.NameAlg
			parentSymmetricAlg = &parentPub.Params.AsymDetail().Symmetric
		}

		sensitiveDup, err := objectutil.UnwrapDuplicated(duplicate, pub, privKey, parentNameAlg, parentSymmetricAlg, inSymSeed, encryptionKey, symmetricAlg)
		if err != nil {
			t.Fatalf("Unwrap failed: %v", err)
		}

		if sensitiveDup.Type != template.Type {
			t.Errorf("Unexpected duplicate type")
		}
		if len(sensitiveDup.AuthValue) != template.NameAlg.Size() {
			t.Errorf("Unexpected duplicate auth value size (%d)", len(sensitiveDup.AuthValue))
		}
		if !bytes.Equal(sensitiveDup.AuthValue[0:len(sensitive.UserAuth)], sensitive.UserAuth) {
			t.Errorf("Unexpected duplicate auth value")
		}
		if len(sensitiveDup.Sensitive.RSA()) != int(template.Params.RSADetail().KeyBits)/16 {
			t.Errorf("Unexpected duplicate sensitive size")
		}
	}

	t.Run("NoWrappers", func(t *testing.T) {
		encryptionKeyOut, duplicate, outSymSeed := run(t, nil, nil, nil)
		if len(encryptionKeyOut) > 0 {
			t.Errorf("Unexpected encryption key")
		}
		if len(outSymSeed) > 0 {
			t.Errorf("Unexpected outSymSeed")
		}
		verifyDuplicate(t, duplicate, false, nil, nil, nil)
	})

	t.Run("InnerWrapper", func(t *testing.T) {
		symmetricAlg := &SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   MakeSymKeyBitsUnion[uint16](128),
			Mode:      MakeSymModeUnion(SymModeCFB),
		}
		encryptionKeyOut, duplicate, outSymSeed := run(t, nil, nil, symmetricAlg)
		if len(encryptionKeyOut) != int(symmetricAlg.KeyBits.Sym())/8 {
			t.Errorf("Unexpected encryption key size")
		}
		if len(outSymSeed) > 0 {
			t.Errorf("Unexpected outSymSeed")
		}

		verifyDuplicate(t, duplicate, false, encryptionKeyOut, nil, symmetricAlg)
	})

	t.Run("InnerWrapperWithKey", func(t *testing.T) {
		symmetricAlg := &SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   MakeSymKeyBitsUnion[uint16](128),
			Mode:      MakeSymModeUnion(SymModeCFB),
		}
		encryptionKeyIn := make(Data, 16)
		rand.Read(encryptionKeyIn)
		encryptionKeyOut, duplicate, outSymSeed := run(t, nil, encryptionKeyIn, symmetricAlg)
		if len(encryptionKeyOut) > 0 {
			t.Errorf("Unexpected encryption key")
		}
		if len(outSymSeed) > 0 {
			t.Errorf("Unexpected outSymSeed")
		}

		verifyDuplicate(t, duplicate, false, encryptionKeyIn, nil, symmetricAlg)
	})

	t.Run("OuterWrapper", func(t *testing.T) {
		encryptionKeyOut, duplicate, outSymSeed := run(t, parent, nil, nil)
		if len(encryptionKeyOut) > 0 {
			t.Errorf("Unexpected encryption key")
		}
		if len(outSymSeed) != int(parentPub.Params.RSADetail().KeyBits)/8 {
			t.Errorf("Unexpected outSymSeed size")
		}

		verifyDuplicate(t, duplicate, true, nil, outSymSeed, nil)
	})

	t.Run("OuterAndInnerWrapper", func(t *testing.T) {
		symmetricAlg := &SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   MakeSymKeyBitsUnion[uint16](128),
			Mode:      MakeSymModeUnion(SymModeCFB),
		}
		encryptionKeyOut, duplicate, outSymSeed := run(t, parent, nil, symmetricAlg)
		if len(encryptionKeyOut) != int(symmetricAlg.KeyBits.Sym())/8 {
			t.Errorf("Unexpected encryption key size")
		}
		if len(outSymSeed) != int(parentPub.Params.RSADetail().KeyBits)/8 {
			t.Errorf("Unexpected outSymSeed size")
		}

		verifyDuplicate(t, duplicate, true, encryptionKeyOut, outSymSeed, symmetricAlg)
	})
}

func TestImport(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	objectPublic := &Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrSign,
		Params: MakePublicParamsUnion(
			RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme:    RSAScheme{Scheme: RSASchemeNull},
				KeyBits:   2048,
				Exponent:  uint32(key.PublicKey.E),
			},
		),
		Unique: MakePublicIDUnion(PublicKeyRSA(key.PublicKey.N.Bytes())),
	}
	objectSensitive := &Sensitive{
		Type:      ObjectTypeRSA,
		AuthValue: []byte("foo"),
		Sensitive: MakeSensitiveCompositeUnion(PrivateKeyRSA(key.Primes[0].Bytes())),
	}

	run := func(t *testing.T, encryptionKey Data, duplicate Private, inSymSeed EncryptedSecret, symmetricAlg *SymDefObject, parentContextAuthSession SessionContext) {
		priv, err := tpm.Import(primary, encryptionKey, objectPublic, duplicate, inSymSeed, symmetricAlg, parentContextAuthSession)
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}
		object, err := tpm.Load(primary, priv, objectPublic, parentContextAuthSession)
		if err != nil {
			t.Errorf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, object)
	}

	t.Run("NoWrappers", func(t *testing.T) {
		_, duplicate, _, err := objectutil.CreateImportable(rand.Reader, objectSensitive, objectPublic, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreateDuplicationObject failed: %v", err)
		}
		run(t, nil, duplicate, nil, nil, nil)
	})

	t.Run("InnerWrapper", func(t *testing.T) {
		symmetricAlg := &SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   MakeSymKeyBitsUnion[uint16](128),
			Mode:      MakeSymModeUnion(SymModeCFB),
		}
		encryptionKey, duplicate, _, err := objectutil.CreateImportable(rand.Reader, objectSensitive, objectPublic, nil, nil, symmetricAlg)
		if err != nil {
			t.Fatalf("CreateDuplicationObject failed: %v", err)
		}
		run(t, encryptionKey, duplicate, nil, symmetricAlg, nil)
	})

	t.Run("OuterWrapper", func(t *testing.T) {
		primaryPublic, _, _, err := tpm.ReadPublic(primary)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}

		_, duplicate, outSymSeed, err := objectutil.CreateImportable(rand.Reader, objectSensitive, objectPublic, primaryPublic, nil, nil)
		if err != nil {
			t.Fatalf("CreateDuplicationObject failed: %v", err)
		}
		run(t, nil, duplicate, outSymSeed, nil, nil)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		_, duplicate, _, err := objectutil.CreateImportable(rand.Reader, objectSensitive, objectPublic, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreateDuplicationObject failed: %v", err)
		}

		sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		run(t, nil, duplicate, nil, nil, sessionContext.WithAttrs(AttrContinueSession))
	})
}
