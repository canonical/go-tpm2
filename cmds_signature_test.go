// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func TestSign(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	msg := []byte("this is a message to sign")

	t.Run("RSA", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		create := func(t *testing.T, scheme *RSAScheme, authValue []byte) (ResourceContext, *Public) {
			template := Public{
				Type:    ObjectTypeRSA,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign | AttrNoDA,
				Params: MakePublicParamsUnion(
					RSAParams{
						Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
						Scheme:    *scheme,
						KeyBits:   2048,
						Exponent:  0,
					},
				),
			}
			sensitive := SensitiveCreate{UserAuth: authValue}
			priv, pub, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			context, err := tpm.Load(primary, priv, pub, nil)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			context.SetAuthValue(authValue)

			return context, pub
		}

		sign := func(t *testing.T, key ResourceContext, digest Digest, inScheme *SigScheme, authSession SessionContext) *Signature {
			signature, err := tpm.Sign(key, digest, inScheme, nil, authSession)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if signature == nil {
				t.Fatalf("nil signature")
			}

			return signature
		}

		verify := func(t *testing.T, pub *Public, digest []byte, signature *Signature, scheme SigSchemeId, hashAlg HashAlgorithmId) {
			if signature.SigAlg != scheme {
				t.Errorf("Signature has the wrong scheme")
			}
			if signature.HashAlg() != hashAlg {
				t.Errorf("Signature has the wrong hash algorithm")
			}

			verifySignature(t, pub, digest, signature)

		}

		t.Run("UseKeyScheme", func(t *testing.T) {
			scheme := RSAScheme{
				Scheme:  RSASchemeRSASSA,
				Details: MakeAsymSchemeUnion(SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}),
			}
			key, pub := create(t, &scheme, nil)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, nil, nil)
			verify(t, pub, digest, signature, SigSchemeAlgRSASSA, HashAlgorithmSHA256)
		})

		t.Run("SpecifyInSchemeWithKeyScheme", func(t *testing.T) {
			keyScheme := RSAScheme{
				Scheme:  RSASchemeRSASSA,
				Details: MakeAsymSchemeUnion(SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}),
			}
			inScheme := SigScheme{
				Scheme:  SigSchemeAlgRSASSA,
				Details: MakeSigSchemeUnion(SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}),
			}

			key, pub := create(t, &keyScheme, nil)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, &inScheme, nil)
			verify(t, pub, digest, signature, SigSchemeAlgRSASSA, HashAlgorithmSHA256)
		})

		t.Run("UseInScheme", func(t *testing.T) {
			keyScheme := RSAScheme{Scheme: RSASchemeNull}
			inScheme := SigScheme{
				Scheme:  SigSchemeAlgRSAPSS,
				Details: MakeSigSchemeUnion(SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA1}),
			}

			key, pub := create(t, &keyScheme, nil)
			defer flushContext(t, tpm, key)

			h := crypto.SHA1.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, &inScheme, nil)
			verify(t, pub, digest, signature, SigSchemeAlgRSAPSS, HashAlgorithmSHA1)
		})

		t.Run("UsePasswordAuth", func(t *testing.T) {
			scheme := RSAScheme{
				Scheme:  RSASchemeRSASSA,
				Details: MakeAsymSchemeUnion(SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}),
			}
			key, pub := create(t, &scheme, testAuth)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, nil, nil)
			verify(t, pub, digest, signature, SigSchemeAlgRSASSA, HashAlgorithmSHA256)
		})

		t.Run("UseSessionAuth", func(t *testing.T) {
			scheme := RSAScheme{
				Scheme:  RSASchemeRSASSA,
				Details: MakeAsymSchemeUnion(SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}),
			}
			key, pub := create(t, &scheme, testAuth)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, key, SessionTypeHMAC, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer verifyContextFlushed(t, tpm, sessionContext)

			signature := sign(t, key, digest, nil, sessionContext)
			verify(t, pub, digest, signature, SigSchemeAlgRSASSA, HashAlgorithmSHA256)
		})
	})

	t.Run("ECC", func(t *testing.T) {
		primary := createECCSrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign | AttrNoDA,
			Params: MakePublicParamsUnion(
				ECCParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme: ECCScheme{
						Scheme:  ECCSchemeECDSA,
						Details: MakeAsymSchemeUnion(SigSchemeECDSA{HashAlg: HashAlgorithmSHA256}),
					},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: KDFAlgorithmNull},
				},
			),
		}
		priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		key, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, key)

		h := crypto.SHA256.New()
		h.Write(msg)
		digest := h.Sum(nil)

		signature, err := tpm.Sign(key, digest, nil, nil, nil)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if SigSchemeAlgECDSA != signature.SigAlg {
			t.Fatalf("Signature has the wrong scheme")
		}
		sig := signature.Signature.ECDSA()
		if HashAlgorithmSHA256 != sig.Hash {
			t.Errorf("Signature has the wrong hash")
		}

		verifySignature(t, pub, digest, signature)
	})
}

func TestVerifySignature(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, 0)
	defer closeTPM()

	msg := []byte("this is a message for signing")

	t.Run("RSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Generating an RSA key failed: %v", err)
		}

		public := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
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

		context, err := tpm.LoadExternal(nil, &public, HandleOwner)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}
		defer flushContext(t, tpm, context)

		run := func(t *testing.T, valid bool, digest Digest, signature *Signature) {
			verified, err := tpm.VerifySignature(context, digest, signature)
			if valid {
				if err != nil {
					t.Fatalf("VerifySignature failed: %v", err)
				}
				if verified == nil {
					t.Fatalf("nil verified")
				}
				if verified.Tag != TagVerified {
					t.Errorf("Invalid tag %v", verified.Tag)
				}
				if verified.Hierarchy != HandleOwner {
					t.Errorf("Invalid hierarchy 0x%08x", verified.Hierarchy)
				}
			} else {
				if !IsTPMParameterError(err, ErrorSignature, CommandVerifySignature, 2) {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		}

		t.Run("SSA", func(t *testing.T) {
			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			s, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			signature := Signature{
				SigAlg:    SigSchemeAlgRSASSA,
				Signature: MakeSignatureUnion(SignatureRSASSA{Hash: HashAlgorithmSHA256, Sig: s}),
			}
			run(t, true, digest, &signature)
		})

		t.Run("PSS", func(t *testing.T) {
			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			s, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			signature := Signature{
				SigAlg:    SigSchemeAlgRSAPSS,
				Signature: MakeSignatureUnion(SignatureRSAPSS{Hash: HashAlgorithmSHA256, Sig: s}),
			}
			run(t, true, digest, &signature)
		})

		t.Run("Invalid", func(t *testing.T) {
			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			s, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			signature := Signature{
				SigAlg:    SigSchemeAlgRSASSA,
				Signature: MakeSignatureUnion(SignatureRSASSA{Hash: HashAlgorithmSHA256, Sig: s}),
			}
			run(t, false, digest, &signature)
		})

		t.Run("SHA1", func(t *testing.T) {
			h := crypto.SHA1.New()
			h.Write(msg)
			digest := h.Sum(nil)

			s, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			signature := Signature{
				SigAlg:    SigSchemeAlgRSASSA,
				Signature: MakeSignatureUnion(SignatureRSASSA{Hash: HashAlgorithmSHA1, Sig: s}),
			}
			run(t, true, digest, &signature)
		})
	})
}
