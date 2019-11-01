// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestSign(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	msg := []byte("this is a message to sign")

	t.Run("RSA", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		create := func(t *testing.T, scheme *RSAScheme, authValue []byte) (ResourceContext, *Public) {
			template := Public{
				Type:    AlgorithmRSA,
				NameAlg: AlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
				Params: PublicParamsU{
					Data: &RSAParams{
						Symmetric: SymDefObject{Algorithm: AlgorithmNull},
						Scheme:    *scheme,
						KeyBits:   2048,
						Exponent:  0}}}
			sensitive := SensitiveCreate{UserAuth: authValue}
			priv, pub, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			context, _, err := tpm.Load(primary, priv, pub, nil)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			return context, pub
		}

		sign := func(t *testing.T, key ResourceContext, digest Digest, inScheme *SigScheme, auth interface{}) *Signature {
			signature, err := tpm.Sign(key, digest, inScheme, nil, auth)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			return signature
		}

		verify := func(t *testing.T, pub *Public, digest []byte, signature *Signature, scheme, hashAlg AlgorithmId) {
			if scheme != signature.SigAlg {
				t.Fatalf("Signature has the wrong scheme")
			}

			exp := int(pub.Params.RSADetail().Exponent)
			if exp == 0 {
				exp = defaultRSAExponent
			}
			pubKey := rsa.PublicKey{N: new(big.Int).SetBytes(pub.Unique.RSA()), E: exp}

			switch scheme {
			case AlgorithmRSASSA:
				sig := (*SignatureRSA)(signature.Signature.RSASSA())
				if hashAlg != sig.Hash {
					t.Errorf("Signature has the wrong hash")
				}
				if err := rsa.VerifyPKCS1v15(&pubKey, cryptGetHash(sig.Hash), digest, sig.Sig); err != nil {
					t.Errorf("Signature is invalid")
				}
			case AlgorithmRSAPSS:
				sig := (*SignatureRSA)(signature.Signature.RSAPSS())
				if hashAlg != sig.Hash {
					t.Errorf("Signature has the wrong hash")
				}
				if err := rsa.VerifyPSS(&pubKey, cryptGetHash(sig.Hash), digest, sig.Sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
					t.Errorf("Signature is invalid")
				}
			}
		}

		t.Run("UseKeyScheme", func(t *testing.T) {
			scheme := RSAScheme{
				Scheme:  AlgorithmRSASSA,
				Details: AsymSchemeU{Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}}
			key, pub := create(t, &scheme, nil)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, nil, nil)
			verify(t, pub, digest, signature, AlgorithmRSASSA, AlgorithmSHA256)
		})

		t.Run("SpecifyInSchemeWithKeyScheme", func(t *testing.T) {
			keyScheme := RSAScheme{
				Scheme:  AlgorithmRSASSA,
				Details: AsymSchemeU{Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}}
			inScheme := SigScheme{
				Scheme:  AlgorithmRSASSA,
				Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}}

			key, pub := create(t, &keyScheme, nil)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, &inScheme, nil)
			verify(t, pub, digest, signature, AlgorithmRSASSA, AlgorithmSHA256)
		})

		t.Run("UseInScheme", func(t *testing.T) {
			keyScheme := RSAScheme{Scheme: AlgorithmNull}
			inScheme := SigScheme{
				Scheme:  AlgorithmRSAPSS,
				Details: SigSchemeU{Data: &SigSchemeRSAPSS{HashAlg: AlgorithmSHA1}}}

			key, pub := create(t, &keyScheme, nil)
			defer flushContext(t, tpm, key)

			h := crypto.SHA1.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, &inScheme, nil)
			verify(t, pub, digest, signature, AlgorithmRSAPSS, AlgorithmSHA1)
		})

		t.Run("UsePasswordAuth", func(t *testing.T) {
			scheme := RSAScheme{
				Scheme:  AlgorithmRSASSA,
				Details: AsymSchemeU{Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}}
			key, pub := create(t, &scheme, testAuth)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			signature := sign(t, key, digest, nil, testAuth)
			verify(t, pub, digest, signature, AlgorithmRSASSA, AlgorithmSHA256)
		})

		t.Run("UseSessionAuth", func(t *testing.T) {
			scheme := RSAScheme{
				Scheme:  AlgorithmRSASSA,
				Details: AsymSchemeU{Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}}
			key, pub := create(t, &scheme, testAuth)
			defer flushContext(t, tpm, key)

			h := crypto.SHA256.New()
			h.Write(msg)
			digest := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, key, SessionTypeHMAC, nil, AlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer verifyContextFlushed(t, tpm, sessionContext)

			signature := sign(t, key, digest, nil, &Session{Context: sessionContext})
			verify(t, pub, digest, signature, AlgorithmRSASSA, AlgorithmSHA256)
		})
	})

	t.Run("ECC", func(t *testing.T) {
		primary := createECCSrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    AlgorithmECC,
			NameAlg: AlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
			Params: PublicParamsU{
				Data: &ECCParams{
					Symmetric: SymDefObject{Algorithm: AlgorithmNull},
					Scheme: ECCScheme{
						Scheme:  AlgorithmECDSA,
						Details: AsymSchemeU{Data: &SigSchemeECDSA{HashAlg: AlgorithmSHA256}}},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: AlgorithmNull}}}}
		priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		key, _, err := tpm.Load(primary, priv, pub, nil)
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

		if AlgorithmECDSA != signature.SigAlg {
			t.Fatalf("Signature has the wrong scheme")
		}

		pubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pub.Unique.ECC().X), Y: new(big.Int).SetBytes(pub.Unique.ECC().Y)}

		sig := signature.Signature.ECDSA()
		if AlgorithmSHA256 != sig.Hash {
			t.Errorf("Signature has the wrong hash")
		}
		if !ecdsa.Verify(&pubKey, digest, new(big.Int).SetBytes(sig.SignatureR), new(big.Int).SetBytes(sig.SignatureS)) {
			t.Errorf("Signature is invalid")
		}
	})
}

func TestVerifySignature(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	msg := []byte("this is a message for signing")

	t.Run("RSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Generating an RSA key failed: %v", err)
		}

		public := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{Algorithm: AlgorithmNull},
					Scheme:    RSAScheme{Scheme: AlgorithmNull},
					KeyBits:   2048,
					Exponent:  uint32(key.PublicKey.E)}},
			Unique: PublicIDU{Digest(key.PublicKey.N.Bytes())}}

		context, _, err := tpm.LoadExternal(nil, &public, HandleOwner)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}

		run := func(t *testing.T, valid bool, digest Digest, signature *Signature) {
			verified, err := tpm.VerifySignature(context, digest, signature)
			if valid {
				if err != nil {
					t.Fatalf("VerifySignature failed: %v", err)
				}
				if verified.Tag != TagVerified {
					t.Errorf("Invalid tag %v", verified.Tag)
				}
				if verified.Hierarchy != HandleOwner {
					t.Errorf("Invalid hierarchy 0x%08x", verified.Hierarchy)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected an error for an invalid signature")
				}
				if e, ok := err.(*TPMParameterError); !ok || e.Code() != ErrorSignature || e.Index != 2 {
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
				SigAlg:    AlgorithmRSASSA,
				Signature: SignatureU{Data: &SignatureRSASSA{Hash: AlgorithmSHA256, Sig: PublicKeyRSA(s)}}}
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
				SigAlg:    AlgorithmRSAPSS,
				Signature: SignatureU{Data: &SignatureRSAPSS{Hash: AlgorithmSHA256, Sig: PublicKeyRSA(s)}}}
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
				SigAlg:    AlgorithmRSASSA,
				Signature: SignatureU{Data: &SignatureRSASSA{Hash: AlgorithmSHA256, Sig: PublicKeyRSA(s)}}}
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
				SigAlg:    AlgorithmRSASSA,
				Signature: SignatureU{Data: &SignatureRSASSA{Hash: AlgorithmSHA1, Sig: PublicKeyRSA(s)}}}
			run(t, true, digest, &signature)
		})
	})
}
