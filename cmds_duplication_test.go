// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"math/big"
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/go-tpm2/internal/crypto"
)

func TestDuplicate(t *testing.T) {
	tpm := openTPMForTesting(t, testCapabilityOwnerHierarchy)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	trial, _ := ComputeAuthPolicy(HashAlgorithmSHA256)
	trial.PolicyCommandCode(CommandDuplicate)

	template := Public{
		Type:       ObjectTypeRSA,
		NameAlg:    HashAlgorithmSHA256,
		Attrs:      AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrSign,
		AuthPolicy: trial.GetDigest(),
		Params: PublicParamsU{
			Data: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme:    RSAScheme{Scheme: RSASchemeNull},
				KeyBits:   2048,
				Exponent:  0}}}
	sensitive := SensitiveCreate{UserAuth: []byte("foo")}
	priv, pub, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
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

	parentTemplate := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			Data: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   SymKeyBitsU{Data: uint16(128)},
					Mode:      SymModeU{Data: SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: uint32(key.PublicKey.E)}},
		Unique: PublicIDU{Data: Digest(key.PublicKey.N.Bytes())}}
	parent, err := tpm.LoadExternal(nil, &parentTemplate, HandleOwner)
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

	verifyUnwrapped := func(t *testing.T, duplicate Private) {
		var sensitiveDup *Sensitive
		if _, err := UnmarshalFromBytes(duplicate, &sensitiveDup); err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
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

	verifyInnerWrapper := func(t *testing.T, key Data, encSensitive Private) {
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("NewCipher failed: %v", err)
		}
		stream := cipher.NewCFBDecrypter(block, make([]byte, aes.BlockSize))
		plainSensitive := make(Private, len(encSensitive))
		stream.XORKeyStream(plainSensitive, encSensitive)

		var innerIntegrity Digest
		n, err := UnmarshalFromBytes(plainSensitive, &innerIntegrity)
		if err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}
		plainSensitive = plainSensitive[n:]

		h := template.NameAlg.NewHash()
		h.Write(plainSensitive)
		h.Write(object.Name())
		if !bytes.Equal(h.Sum(nil), innerIntegrity) {
			t.Errorf("Unexpected inner integrity")
		}
		var d Private
		if _, err := UnmarshalFromBytes(plainSensitive, &d); err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}
		verifyUnwrapped(t, d)
	}

	verifyOuterWrapper := func(t *testing.T, seed []byte, duplicate Private, innerKey []byte) {
		var outerHMAC Digest
		n, err := UnmarshalFromBytes(duplicate, &outerHMAC)
		if err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}
		dupSensitive := duplicate[n:]

		hmacKey := crypto.KDFa(parentTemplate.NameAlg.GetHash(), seed, []byte("INTEGRITY"), nil, nil, parentTemplate.NameAlg.Size()*8)
		h := hmac.New(func() hash.Hash { return parentTemplate.NameAlg.NewHash() }, hmacKey)
		h.Write(dupSensitive)
		h.Write(object.Name())
		if !bytes.Equal(h.Sum(nil), outerHMAC) {
			t.Errorf("Unexpected outer HMAC")
		}

		symKey := crypto.KDFa(parentTemplate.NameAlg.GetHash(), seed, []byte("STORAGE"), object.Name(), nil,
			int(parentTemplate.Params.AsymDetail().Symmetric.KeyBits.Sym()))
		block, err := aes.NewCipher(symKey)
		if err != nil {
			t.Fatalf("NewCipher failed: %v", err)
		}
		stream := cipher.NewCFBDecrypter(block, make([]byte, aes.BlockSize))
		plainSensitive := make([]byte, len(dupSensitive))
		stream.XORKeyStream(plainSensitive, dupSensitive)
		if len(innerKey) == 0 {
			var d Private
			if _, err := UnmarshalFromBytes(plainSensitive, &d); err != nil {
				t.Fatalf("UnmarshalFromBytes failed: %v", err)
			}
			verifyUnwrapped(t, d)
		} else {
			verifyInnerWrapper(t, innerKey, plainSensitive)
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
		var d Private
		if _, err := UnmarshalFromBytes(duplicate, &d); err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}
		verifyUnwrapped(t, d)
	})

	t.Run("InnerWrapper", func(t *testing.T) {
		symmetricAlg := SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   SymKeyBitsU{Data: uint16(128)},
			Mode:      SymModeU{Data: SymModeCFB}}
		encryptionKeyOut, duplicate, outSymSeed := run(t, nil, nil, &symmetricAlg)
		if len(encryptionKeyOut) != int(symmetricAlg.KeyBits.Sym())/8 {
			t.Errorf("Unexpected encryption key size")
		}
		if len(outSymSeed) > 0 {
			t.Errorf("Unexpected outSymSeed")
		}

		verifyInnerWrapper(t, encryptionKeyOut, duplicate)
	})

	t.Run("InnerWrapperWithKey", func(t *testing.T) {
		symmetricAlg := SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   SymKeyBitsU{Data: uint16(128)},
			Mode:      SymModeU{Data: SymModeCFB}}
		encryptionKeyIn := make(Data, 16)
		rand.Read(encryptionKeyIn)
		encryptionKeyOut, duplicate, outSymSeed := run(t, nil, encryptionKeyIn, &symmetricAlg)
		if len(encryptionKeyOut) > 0 {
			t.Errorf("Unexpected encryption key")
		}
		if len(outSymSeed) > 0 {
			t.Errorf("Unexpected outSymSeed")
		}

		verifyInnerWrapper(t, encryptionKeyIn, duplicate)
	})

	t.Run("OuterWrapper", func(t *testing.T) {
		encryptionKeyOut, duplicate, outSymSeed := run(t, parent, nil, nil)
		if len(encryptionKeyOut) > 0 {
			t.Errorf("Unexpected encryption key")
		}
		if len(outSymSeed) != int(parentTemplate.Params.RSADetail().KeyBits)/8 {
			t.Errorf("Unexpected outSymSeed size")
		}
		label := []byte("DUPLICATE")
		label = append(label, 0)
		seed, err := rsa.DecryptOAEP(parentTemplate.NameAlg.NewHash(), rand.Reader, key, outSymSeed, label)
		if err != nil {
			t.Fatalf("DecryptOAEP failed: %v", err)
		}
		if len(seed) != parentTemplate.NameAlg.Size() {
			t.Errorf("Unexpected seed size")
		}

		verifyOuterWrapper(t, seed, duplicate, nil)
	})

	t.Run("OuterAndInnerWrapper", func(t *testing.T) {
		symmetricAlg := SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   SymKeyBitsU{Data: uint16(128)},
			Mode:      SymModeU{Data: SymModeCFB}}
		encryptionKeyOut, duplicate, outSymSeed := run(t, parent, nil, &symmetricAlg)
		if len(encryptionKeyOut) != int(symmetricAlg.KeyBits.Sym())/8 {
			t.Errorf("Unexpected encryption key size")
		}
		if len(outSymSeed) != int(parentTemplate.Params.RSADetail().KeyBits)/8 {
			t.Errorf("Unexpected outSymSeed size")
		}
		label := []byte("DUPLICATE")
		label = append(label, 0)
		seed, err := rsa.DecryptOAEP(parentTemplate.NameAlg.NewHash(), rand.Reader, key, outSymSeed, label)
		if err != nil {
			t.Fatalf("DecryptOAEP failed: %v", err)
		}
		if len(seed) != parentTemplate.NameAlg.Size() {
			t.Errorf("Unexpected seed size")
		}

		verifyOuterWrapper(t, seed, duplicate, encryptionKeyOut)
	})
}

type sensitiveSized struct {
	Ptr *Sensitive `tpm2:"sized"`
}

func TestImport(t *testing.T) {
	tpm := openTPMForTesting(t, testCapabilityOwnerHierarchy)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	objectPublic := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrSign,
		Params: PublicParamsU{
			Data: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme:    RSAScheme{Scheme: RSASchemeNull},
				KeyBits:   2048,
				Exponent:  uint32(key.PublicKey.E)}},
		Unique: PublicIDU{Data: Digest(key.PublicKey.N.Bytes())}}
	objectSensitive := Sensitive{
		Type:      ObjectTypeRSA,
		AuthValue: make(Auth, objectPublic.NameAlg.Size()),
		Sensitive: SensitiveCompositeU{Data: PrivateKeyRSA(key.Primes[0].Bytes())}}
	copy(objectSensitive.AuthValue, []byte("foo"))

	run := func(t *testing.T, encryptionKey Data, duplicate Private, inSymSeed EncryptedSecret, symmetricAlg *SymDefObject, parentContextAuthSession SessionContext) {
		priv, err := tpm.Import(primary, encryptionKey, &objectPublic, duplicate, inSymSeed, symmetricAlg, parentContextAuthSession)
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}
		object, err := tpm.Load(primary, priv, &objectPublic, parentContextAuthSession)
		if err != nil {
			t.Errorf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, object)
	}

	t.Run("NoWrappers", func(t *testing.T) {
		duplicate, _ := MarshalToBytes(sensitiveSized{&objectSensitive})
		run(t, nil, duplicate, nil, nil, nil)
	})

	t.Run("InnerWrapper", func(t *testing.T) {
		sensitive, _ := MarshalToBytes(sensitiveSized{&objectSensitive})
		name, _ := objectPublic.Name()

		h := objectPublic.NameAlg.NewHash()
		h.Write(sensitive)
		h.Write(name)

		b, _ := MarshalToBytes(h.Sum(nil), RawBytes(sensitive))

		encryptionKey := make([]byte, 16)
		rand.Read(encryptionKey)

		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			t.Fatalf("NewCipher failed: %v", err)
		}
		stream := cipher.NewCFBEncrypter(block, make([]byte, aes.BlockSize))
		encSensitive := make(Private, len(b))
		stream.XORKeyStream(encSensitive, b)

		symmetricAlg := SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   SymKeyBitsU{Data: uint16(128)},
			Mode:      SymModeU{Data: SymModeCFB}}
		run(t, encryptionKey, encSensitive, nil, &symmetricAlg, nil)
	})

	t.Run("OuterWrapper", func(t *testing.T) {
		sensitive, _ := MarshalToBytes(sensitiveSized{&objectSensitive})
		name, _ := objectPublic.Name()

		primaryPublic, _, _, err := tpm.ReadPublic(primary)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}

		seed := make([]byte, primary.Name().Algorithm().Size())
		rand.Read(seed)

		symKey := crypto.KDFa(primary.Name().Algorithm().GetHash(), seed, []byte("STORAGE"), name, nil,
			int(primaryPublic.Params.AsymDetail().Symmetric.KeyBits.Sym()))

		block, err := aes.NewCipher(symKey)
		if err != nil {
			t.Fatalf("NewCipher failed: %v", err)
		}
		stream := cipher.NewCFBEncrypter(block, make([]byte, aes.BlockSize))
		dupSensitive := make(Private, len(sensitive))
		stream.XORKeyStream(dupSensitive, sensitive)

		hmacKey := crypto.KDFa(primary.Name().Algorithm().GetHash(), seed, []byte("INTEGRITY"), nil, nil, primary.Name().Algorithm().Size()*8)
		h := hmac.New(func() hash.Hash { return primary.Name().Algorithm().NewHash() }, hmacKey)
		h.Write(dupSensitive)
		h.Write(name)

		duplicate, _ := MarshalToBytes(h.Sum(nil), RawBytes(dupSensitive))

		keyPublic := rsa.PublicKey{
			N: new(big.Int).SetBytes(primaryPublic.Unique.RSA()),
			E: 65537}
		label := []byte("DUPLICATE")
		label = append(label, 0)
		encSeed, err := rsa.EncryptOAEP(primary.Name().Algorithm().NewHash(), rand.Reader, &keyPublic, seed, label)
		if err != nil {
			t.Fatalf("EncryptOAEP failed: %v", err)
		}

		run(t, nil, duplicate, encSeed, nil, nil)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		duplicate, _ := MarshalToBytes(sensitiveSized{&objectSensitive})

		sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		run(t, nil, duplicate, nil, nil, sessionContext.WithAttrs(AttrContinueSession))
	})
}
