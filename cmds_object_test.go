// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
)

func TestCreate(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, parent, hierarchy ResourceContext, sensitive *SensitiveCreate, template *Public, outsideInfo Data, creationPCR PCRSelectionList, session *Session) (*Public, Private) {
		outPrivate, outPublic, creationData, creationHash, creationTicket, err := tpm.Create(parent, sensitive, template, outsideInfo, creationPCR, session)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		if len(outPrivate) == 0 {
			t.Errorf("Create returned a zero sized private part")
		}

		verifyPublicAgainstTemplate(t, outPublic, template)
		verifyCreationData(t, tpm, creationData, creationHash, template, outsideInfo, creationPCR, parent)
		verifyCreationTicket(t, creationTicket, hierarchy)

		return outPublic, outPrivate
	}

	t.Run("RSA", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}
		creationPCR := PCRSelectionList{
			PCRSelection{Hash: HashAlgorithmSHA1, Select: PCRSelectionData{0, 1}},
			PCRSelection{Hash: HashAlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

		pub, _ := run(t, primary, tpm.OwnerHandleContext(), nil, &template, Data{}, creationPCR, nil)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("ECC", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA1,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &ECCParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    ECCScheme{Scheme: ECCSchemeNull},
					CurveID:   ECCCurveNIST_P256,
					KDF:       KDFScheme{Scheme: KDFAlgorithmNull}}}}

		pub, _ := run(t, primary, tpm.OwnerHandleContext(), nil, &template, Data{}, PCRSelectionList{}, nil)
		if len(pub.Unique.ECC().X) != 32 || len(pub.Unique.ECC().Y) != 32 {
			t.Errorf("CreatePrimary returned object with invalid ECC coords")
		}
	})

	t.Run("CreateWithAuthValue", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		sensitive := SensitiveCreate{UserAuth: Auth(testAuth)}
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{Data: uint16(128)},
						Mode:      SymModeU{Data: SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		pub, priv := run(t, primary, tpm.OwnerHandleContext(), &sensitive, &template, Data{}, PCRSelectionList{}, nil)
		verifyRSAAgainstTemplate(t, pub, &template)

		handle, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, handle)
		handle.SetAuthValue(testAuth)

		run(t, handle, tpm.OwnerHandleContext(), nil, &template, Data{}, PCRSelectionList{}, nil)
	})

	t.Run("WithOutsideInfo", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}
		outsideInfo := Data("foo")

		pub, _ := run(t, primary, tpm.OwnerHandleContext(), nil, &template, outsideInfo, PCRSelectionList{}, nil)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, testAuth)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}

		pub, _ := run(t, primary, tpm.OwnerHandleContext(), nil, &template, Data{}, PCRSelectionList{}, nil)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, testAuth)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}

		sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		session := Session{Context: sessionContext}

		pub, _ := run(t, primary, tpm.OwnerHandleContext(), nil, &template, Data{}, PCRSelectionList{}, &session)
		verifyRSAAgainstTemplate(t, pub, &template)
	})
}

func TestLoad(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, parent ResourceContext, session *Session) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}

		outPrivate, outPublic, _, _, _, err := tpm.Create(parent, nil, &template, nil, nil, session)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectContext, err := tpm.Load(parent, outPrivate, outPublic, session)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectContext)

		if objectContext.Handle().Type() != HandleTypeTransient {
			t.Errorf("Create returned an invalid handle 0x%08x", objectContext.Handle())
		}
		if objectContext.Name().Algorithm() != HashAlgorithmSHA256 {
			t.Errorf("Create returned a name with the wrong algorithm %v", objectContext.Name().Algorithm())
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		run(t, primary, nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, testAuth)
		defer flushContext(t, tpm, primary)

		run(t, primary, nil)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, testAuth)
		defer flushContext(t, tpm, primary)

		sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession}

		run(t, primary, &session)
	})
}

func TestReadPublic(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
		Params: PublicParamsU{
			Data: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme:    RSAScheme{Scheme: RSASchemeNull},
				KeyBits:   2048,
				Exponent:  0}}}
	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectContext, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	run := func(t *testing.T, session *Session) {
		public, name, qualifiedName, err := tpm.ReadPublic(objectContext, session)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}

		verifyPublicAgainstTemplate(t, &template, public)

		if !bytes.Equal(objectContext.Name(), name) {
			t.Errorf("ReadPublic returned an unexpected name")
		}
		if qualifiedName.Algorithm() != HashAlgorithmSHA256 {
			t.Errorf("ReadPublic returned a qualifiedName of the wrong algorithm")
		}
	}

	t.Run("NoSession", func(t *testing.T) {
		run(t, nil)
	})

	t.Run("ResponseEncrypt", func(t *testing.T) {
		symmetric := SymDef{
			Algorithm: SymAlgorithmAES,
			KeyBits:   SymKeyBitsU{Data: uint16(128)},
			Mode:      SymModeU{Data: SymModeCFB}}
		sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &symmetric, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, &Session{Context: sessionContext, Attrs: AttrResponseEncrypt})
	})
}

func TestLoadExternal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, sensitive *Sensitive, template *Public, hierarchy Handle) {
		objectContext, err := tpm.LoadExternal(sensitive, template, hierarchy)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}
		defer flushContext(t, tpm, objectContext)

		if objectContext.Handle().Type() != HandleTypeTransient {
			t.Errorf("LoadExternal returned an invalid handle 0x%08x", objectContext.Handle())
		}

		templateName, err := template.Name()
		if err != nil {
			t.Fatalf("Cannot compute name: %v", err)
		}

		if !bytes.Equal(objectContext.Name(), templateName) {
			t.Errorf("Unexpected name")
		}
	}

	t.Run("RSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Generating an RSA key failed: %v", err)
		}
		sensitive := Sensitive{
			Type:      ObjectTypeRSA,
			Sensitive: SensitiveCompositeU{Data: PrivateKeyRSA(key.Primes[0].Bytes())}}
		public := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  uint32(key.PublicKey.E)}},
			Unique: PublicIDU{Data: Digest(key.PublicKey.N.Bytes())}}

		run(t, &sensitive, &public, HandleNull)
	})

	t.Run("ECC", func(t *testing.T) {
		priv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Generating an ECC key failed: %v", err)
		}
		sensitive := Sensitive{
			Type:      ObjectTypeECC,
			Sensitive: SensitiveCompositeU{Data: ECCParameter(priv)}}
		public := Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA1,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &ECCParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    ECCScheme{Scheme: ECCSchemeNull},
					CurveID:   ECCCurveNIST_P256,
					KDF:       KDFScheme{Scheme: KDFAlgorithmNull}}},
			Unique: PublicIDU{Data: &ECCPoint{X: x.Bytes(), Y: y.Bytes()}}}

		run(t, &sensitive, &public, HandleNull)
	})

	t.Run("HMAC", func(t *testing.T) {
		key := make([]byte, 32)
		rand.Read(key)

		seed := make([]byte, 32)

		h := sha256.New()
		h.Write(seed)
		h.Write(key)
		unique := h.Sum(nil)

		sensitive := Sensitive{
			Type:      ObjectTypeKeyedHash,
			SeedValue: seed,
			Sensitive: SensitiveCompositeU{Data: key}}
		public := Public{
			Type:    ObjectTypeKeyedHash,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
			Params: PublicParamsU{
				Data: &KeyedHashParams{
					Scheme: KeyedHashScheme{
						Scheme: KeyedHashSchemeHMAC,
						Details: SchemeKeyedHashU{
							Data: &SchemeHMAC{HashAlg: HashAlgorithmSHA256}}}}},
			Unique: PublicIDU{Data: unique}}

		run(t, &sensitive, &public, HandleNull)
	})

	t.Run("PublicOnly", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Generating an RSA key failed: %v", err)
		}

		public := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  uint32(key.PublicKey.E)}},
			Unique: PublicIDU{Data: Digest(key.PublicKey.N.Bytes())}}

		run(t, nil, &public, HandleOwner)
	})
}

func TestUnseal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	secret := []byte("sensitive data")

	create := func(t *testing.T, authPolicy Digest, authValue Auth, extraAttrs ObjectAttributes) ResourceContext {
		template := Public{
			Type:       ObjectTypeKeyedHash,
			NameAlg:    HashAlgorithmSHA256,
			Attrs:      AttrFixedTPM | AttrFixedParent | extraAttrs,
			AuthPolicy: authPolicy,
			Params:     PublicParamsU{Data: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}

		sensitive := SensitiveCreate{Data: secret, UserAuth: authValue}

		outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectContext, err := tpm.Load(primary, outPrivate, outPublic, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		objectContext.SetAuthValue(authValue)
		return objectContext
	}

	run := func(t *testing.T, handle ResourceContext, session *Session) {
		sensitiveData, err := tpm.Unseal(handle, session)
		if err != nil {
			t.Fatalf("Unseal failed: %v", err)
		}
		if !bytes.Equal(sensitiveData, secret) {
			t.Errorf("Unseal didn't return the expected data (got %x)", sensitiveData)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		handle := create(t, nil, nil, AttrUserWithAuth)
		defer flushContext(t, tpm, handle)
		run(t, handle, nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		handle := create(t, nil, Auth(testAuth), AttrUserWithAuth)
		defer flushContext(t, tpm, handle)
		run(t, handle, nil)
	})

	t.Run("UseHMACSessionAuth", func(t *testing.T) {
		handle := create(t, nil, Auth(testAuth), AttrUserWithAuth)
		defer flushContext(t, tpm, handle)
		sessionContext, err := tpm.StartAuthSession(nil, handle, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, handle, &Session{Context: sessionContext})
	})

	t.Run("UsePolicySessionAuth", func(t *testing.T) {
		handle := create(t, make([]byte, 32), nil, 0)
		defer flushContext(t, tpm, handle)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, handle, &Session{Context: sessionContext})
	})
}

func TestObjectChangeAuth(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	create := func(t *testing.T, userAuth Auth) (ResourceContext, *Public) {
		sensitive := SensitiveCreate{Data: []byte("sensitive data"), UserAuth: userAuth}
		template := Public{
			Type:    ObjectTypeKeyedHash,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
			Params:  PublicParamsU{Data: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}

		outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectContext, err := tpm.Load(primary, outPrivate, outPublic, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		objectContext.SetAuthValue(userAuth)

		return objectContext, outPublic
	}

	run := func(t *testing.T, context ResourceContext, pub *Public, authValue Auth, session *Session) {
		priv, err := tpm.ObjectChangeAuth(context, primary, authValue, session)
		if err != nil {
			t.Fatalf("ObjectChangeAuth failed: %v", err)
		}

		newContext, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, newContext)
		newContext.SetAuthValue(authValue)

		_, err = tpm.Unseal(newContext, nil)
		if err != nil {
			t.Errorf("Unseal failed: %v", err)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		context, pub := create(t, nil)
		defer flushContext(t, tpm, context)
		run(t, context, pub, Auth("foo"), nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		context, pub := create(t, Auth(testAuth))
		defer flushContext(t, tpm, context)
		run(t, context, pub, Auth("1234"), nil)
	})

	t.Run("UseUnboundSessionAuth", func(t *testing.T) {
		context, pub := create(t, Auth(testAuth))
		defer flushContext(t, tpm, context)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		session := Session{Context: sessionContext}
		run(t, context, pub, Auth("foo"), &session)
	})

	t.Run("UseBoundSessionAuth", func(t *testing.T) {
		context, pub := create(t, Auth(testAuth))
		defer flushContext(t, tpm, context)
		sessionContext, err := tpm.StartAuthSession(nil, context, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, context, pub, Auth("foo"), &Session{Context: sessionContext})
	})
}

func TestMakeCredential(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	ek := createRSAEkForTesting(t, tpm)
	defer flushContext(t, tpm, ek)
	ak := createAndLoadRSAAkForTesting(t, tpm, ek, nil)
	defer flushContext(t, tpm, ak)

	// Perform test with an object contianing only the public part of the EK
	ekPub, _, _, err := tpm.ReadPublic(ek)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	ekPubCtx, err := tpm.LoadExternal(nil, ekPub, HandleEndorsement)
	if err != nil {
		t.Fatalf("LoadExternal failed: %v", err)
	}
	defer flushContext(t, tpm, ekPubCtx)

	credentialBlob, secret, err := tpm.MakeCredential(ekPubCtx, []byte("secret credential"), ak.Name())
	if err != nil {
		t.Fatalf("MakeCredential failed: %v", err)
	}

	if credentialBlob == nil {
		t.Fatalf("Returned credential blob is nil")
	}

	if binary.BigEndian.Uint16(credentialBlob) != 32 {
		t.Errorf("Invalid integrityHMAC length")
	}
	if len(credentialBlob) != 53 {
		t.Errorf("Invalid credentialBlob length")
	}

	if secret == nil {
		t.Errorf("Returned secret is nil")
	}
}

func TestActivateCredential(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	ek := createRSAEkForTesting(t, tpm)
	defer flushContext(t, tpm, ek)

	credentialIn := []byte("secret credential")

	run := func(t *testing.T, ak ResourceContext, authSession *Session) {
		credentialBlob, secret, err := tpm.MakeCredential(ek, credentialIn, ak.Name())
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		if _, _, err := tpm.PolicySecret(tpm.EndorsementHandleContext(), sessionContext, nil, nil, 0, nil); err != nil {
			t.Fatalf("PolicySecret failed: %v", err)
		}

		credentialOut, err := tpm.ActivateCredential(ak, ek, credentialBlob, secret, authSession, &Session{Context: sessionContext})
		if err != nil {
			t.Fatalf("ActivateCredential failed: %v", err)
		}

		if !bytes.Equal(credentialOut, credentialIn) {
			t.Errorf("ActivateCredential returned the wrong credential")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		ak := createAndLoadRSAAkForTesting(t, tpm, ek, nil)
		defer flushContext(t, tpm, ak)
		run(t, ak, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		ak := createAndLoadRSAAkForTesting(t, tpm, ek, testAuth)
		defer flushContext(t, tpm, ak)
		run(t, ak, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		ak := createAndLoadRSAAkForTesting(t, tpm, ek, testAuth)
		defer flushContext(t, tpm, ak)
		sessionContext, err := tpm.StartAuthSession(nil, ak, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, ak, &Session{Context: sessionContext})
	})
}
