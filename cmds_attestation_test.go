// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func verifyAttest(t *testing.T, tpm *TPMContext, attestRaw AttestRaw, tag StructTag, signContext ResourceContext, signHierarchy Handle, qualifyingData Data) *Attest {
	if attestRaw == nil {
		t.Fatalf("attestation is empty")
	}
	attest, err := attestRaw.Decode()
	if err != nil {
		t.Fatalf("attestation failed to unmarshal: %v", err)
	}
	if attest.Magic != TPMGeneratedValue {
		t.Errorf("attestation has the wrong magic value")
	}
	if attest.Type != tag {
		t.Errorf("attestation has the wrong type")
	}
	if signContext == nil {
		if !attest.QualifiedSigner.IsHandle() || attest.QualifiedSigner.Handle() != HandleNull {
			t.Errorf("certifyInfo has the wrong qualifiedSigner")
		}
	} else {
		_, _, qn, err := tpm.ReadPublic(signContext)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}
		if !bytes.Equal(qn, attest.QualifiedSigner) {
			t.Errorf("attestation has the wrong qualifiedSigner")
		}
	}
	if !bytes.Equal(attest.ExtraData, qualifyingData) {
		t.Errorf("attestation has the wrong extraData")
	}
	if signContext != nil && signHierarchy == HandleEndorsement {
		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}
		if attest.ClockInfo.ResetCount != time.ClockInfo.ResetCount {
			t.Errorf("attestation has the wrong clockInfo.resetCount")
		}
		if attest.ClockInfo.RestartCount != time.ClockInfo.RestartCount {
			t.Errorf("attestation has the wrong clockInfo.restartCount")
		}
		if attest.ClockInfo.Safe != time.ClockInfo.Safe {
			t.Errorf("attestation has the wrong clockInfo.safe")
		}
	}
	return attest
}

func verifyAttestSignature(t *testing.T, tpm *TPMContext, signContext ResourceContext, attest AttestRaw, signature *Signature, scheme SigSchemeId, hash HashAlgorithmId) {
	if signature == nil {
		t.Fatalf("nil signature")
	}
	if signContext == nil {
		if signature.SigAlg != SigSchemeAlgNull {
			t.Errorf("Unexpected signature algorithm")
		}
	} else {
		h := hash.NewHash()
		h.Write(attest)
		digest := h.Sum(nil)

		if signature.SigAlg != scheme {
			t.Errorf("Signature has the wrong scheme")
		}
		if signature.Signature.Any().HashAlg != hash {
			t.Errorf("Signature has the wrong hash algorithm")
		}

		pub, _, _, err := tpm.ReadPublic(signContext)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}

		verifySignature(t, pub, digest, signature)
	}
}

func TestCertify(t *testing.T) {
	tpm := openTPMForTesting(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy)
	defer closeTPM(t, tpm)

	prepare := func(t *testing.T, auth Auth) ResourceContext {
		ek := createRSAEkForTesting(t, tpm)
		defer flushContext(t, tpm, ek)
		return createAndLoadRSAAkForTesting(t, tpm, ek, auth)
	}

	run := func(t *testing.T, objectContext, signContext ResourceContext, signHierarchy Handle, qualifyingData Data, inScheme *SigScheme, objectContextAuthSession, signContextAuthSession SessionContext) {
		certifyInfo, signature, err := tpm.Certify(objectContext, signContext, qualifyingData, inScheme, objectContextAuthSession, signContextAuthSession)
		if err != nil {
			t.Fatalf("Certify failed: %v", err)
		}

		attest := verifyAttest(t, tpm, certifyInfo, TagAttestCertify, signContext, signHierarchy, qualifyingData)

		_, name, qn, err := tpm.ReadPublic(objectContext)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}
		if !bytes.Equal(attest.Attested.Certify.Name, name) {
			t.Errorf("certifyInfo has the wrong name")
		}
		if !bytes.Equal(attest.Attested.Certify.QualifiedName, qn) {
			t.Errorf("certifyInfo has the wrong qualifiedName")
		}

		verifyAttestSignature(t, tpm, signContext, certifyInfo, signature, SigSchemeAlgRSASSA, HashAlgorithmSHA256)
	}

	t.Run("NoSignature", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		run(t, primary, nil, HandleNull, nil, nil, nil, nil)
	})

	t.Run("WithSignature", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		run(t, primary, ak, HandleEndorsement, nil, nil, nil, nil)
	})

	t.Run("SpecifyInSchemeWithKeyScheme", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}
		run(t, primary, ak, HandleEndorsement, nil, &scheme, nil, nil)
	})

	t.Run("UseInScheme", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}
		priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		key, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, key)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}
		run(t, primary, key, HandleOwner, nil, &scheme, nil, nil)
	})

	t.Run("WithExtraData", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		run(t, primary, ak, HandleEndorsement, []byte("foo"), nil, nil, nil)
	})

	t.Run("UsePasswordAuthForKey", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		run(t, primary, ak, HandleEndorsement, nil, nil, nil, nil)
	})

	t.Run("UseSessionAuthForKey", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		sessionContext, err := tpm.StartAuthSession(nil, ak, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, primary, ak, HandleEndorsement, nil, nil, nil, sessionContext)
	})

	t.Run("UsePasswordAuthForObject", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		primary := createRSASrkForTesting(t, tpm, testAuth)
		defer flushContext(t, tpm, primary)
		run(t, primary, ak, HandleEndorsement, nil, nil, nil, nil)
	})

	t.Run("UseSessionAuthForObject", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		primary := createRSASrkForTesting(t, tpm, testAuth)
		defer flushContext(t, tpm, primary)

		sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, primary, ak, HandleEndorsement, nil, nil, sessionContext, nil)
	})
}

func TestCertifyCreation(t *testing.T) {
	tpm := openTPMForTesting(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy)
	defer closeTPM(t, tpm)

	prepare := func(t *testing.T, auth Auth) ResourceContext {
		ek := createRSAEkForTesting(t, tpm)
		defer flushContext(t, tpm, ek)
		return createAndLoadRSAAkForTesting(t, tpm, ek, auth)
	}

	run := func(t *testing.T, signContext ResourceContext, signHierarchy Handle, qualifyingData Data, inScheme *SigScheme, signContextAuthSession SessionContext) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 128},
						Mode:      SymModeU{Data: SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		objectHandle, _, _, creationHash, creationTicket, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		defer flushContext(t, tpm, objectHandle)

		certifyInfo, signature, err :=
			tpm.CertifyCreation(signContext, objectHandle, qualifyingData, creationHash, inScheme, creationTicket, signContextAuthSession)
		if err != nil {
			t.Fatalf("CertifyCreation failed: %v", err)
		}

		attest := verifyAttest(t, tpm, certifyInfo, TagAttestCreation, signContext, signHierarchy, qualifyingData)

		if !bytes.Equal(attest.Attested.Creation.ObjectName, objectHandle.Name()) {
			t.Errorf("certifyInfo has the wrong objectName")
		}
		if !bytes.Equal(attest.Attested.Creation.CreationHash, creationHash) {
			t.Errorf("certifyInfo has the wrong creationHash")
		}

		verifyAttestSignature(t, tpm, signContext, certifyInfo, signature, SigSchemeAlgRSASSA, HashAlgorithmSHA256)
	}

	t.Run("NoSignature", func(t *testing.T) {
		run(t, nil, HandleNull, nil, nil, nil)
	})

	t.Run("WithSignature", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		run(t, ak, HandleEndorsement, nil, nil, nil)
	})

	t.Run("SpecifyInSchemeWithKeyScheme", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}
		run(t, ak, HandleEndorsement, nil, &scheme, nil)
	})

	t.Run("UseInScheme", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}
		priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		key, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, key)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}
		run(t, key, HandleOwner, nil, &scheme, nil)
	})

	t.Run("WithExtraData", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		run(t, ak, HandleEndorsement, []byte("foo"), nil, nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)
		run(t, ak, HandleEndorsement, nil, nil, nil)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)

		sessionContext, err := tpm.StartAuthSession(nil, ak, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, ak, HandleEndorsement, nil, nil, sessionContext)
	})

	t.Run("InvalidTicket", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 128},
						Mode:      SymModeU{Data: SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		objectHandle, _, _, creationHash, creationTicket, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		defer flushContext(t, tpm, objectHandle)

		creationTicket.Hierarchy = HandleEndorsement

		_, _, err = tpm.CertifyCreation(nil, objectHandle, nil, creationHash, nil, creationTicket, nil)
		if !IsTPMParameterError(err, ErrorTicket, CommandCertifyCreation, 4) {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestQuote(t *testing.T) {
	tpm := openTPMForTesting(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy|testutil.TPMFeaturePCR)
	defer closeTPM(t, tpm)

	for i := 0; i < 8; i++ {
		if _, err := tpm.PCREvent(tpm.PCRHandleContext(i), Event(fmt.Sprintf("event%d", i)), nil); err != nil {
			t.Fatalf("PCREvent failed: %v", err)
		}
	}

	prepare := func(t *testing.T, auth Auth) ResourceContext {
		ek := createRSAEkForTesting(t, tpm)
		defer flushContext(t, tpm, ek)
		return createAndLoadRSAAkForTesting(t, tpm, ek, auth)
	}

	run := func(t *testing.T, signContext ResourceContext, signHierarchy Handle, qualifyingData Data, inScheme *SigScheme, pcrs PCRSelectionList, alg HashAlgorithmId, signContextAuthSession SessionContext) {
		quoted, signature, err := tpm.Quote(signContext, qualifyingData, inScheme, pcrs, signContextAuthSession)
		if err != nil {
			t.Fatalf("Quote failed: %v", err)
		}

		attest := verifyAttest(t, tpm, quoted, TagAttestQuote, signContext, signHierarchy, qualifyingData)

		pcrDigest := computePCRDigestFromTPM(t, tpm, alg, pcrs)
		if !reflect.DeepEqual(attest.Attested.Quote.PCRSelect, pcrs) {
			t.Errorf("quoted has the wrong pcrSelect")
		}
		if !bytes.Equal(attest.Attested.Quote.PCRDigest, pcrDigest) {
			t.Errorf("quoted has the wrong pcrDigest")
		}

		verifyAttestSignature(t, tpm, signContext, quoted, signature, SigSchemeAlgRSASSA, alg)
	}

	t.Run("WithSignature", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)

		pcrs := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}}
		run(t, ak, HandleEndorsement, nil, nil, pcrs, HashAlgorithmSHA256, nil)
	})

	t.Run("SpecifyInSchemeWithKeyScheme", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}
		pcrs := PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{2, 4, 7}}}
		run(t, ak, HandleEndorsement, nil, &scheme, pcrs, HashAlgorithmSHA256, nil)
	})

	t.Run("UseInScheme", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}
		priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		key, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, key)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA1}}}
		pcrs := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{4, 7}}}
		run(t, key, HandleOwner, nil, &scheme, pcrs, HashAlgorithmSHA1, nil)
	})

	t.Run("WithExtraData", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)

		pcrs := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}}
		run(t, ak, HandleEndorsement, []byte("bar"), nil, pcrs, HashAlgorithmSHA256, nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)

		pcrs := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{1, 7}}}
		run(t, ak, HandleEndorsement, nil, nil, pcrs, HashAlgorithmSHA256, nil)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)

		sessionContext, err := tpm.StartAuthSession(nil, ak, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		pcrs := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{1, 7}}}
		run(t, ak, HandleEndorsement, nil, nil, pcrs, HashAlgorithmSHA256, sessionContext)
	})
}

func TestGetTime(t *testing.T) {
	tpm := openTPMForTesting(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy|testutil.TPMFeatureHierarchyChangeAuth)
	defer closeTPM(t, tpm)

	prepare := func(t *testing.T, auth Auth) ResourceContext {
		ek := createRSAEkForTesting(t, tpm)
		defer flushContext(t, tpm, ek)
		return createAndLoadRSAAkForTesting(t, tpm, ek, auth)
	}

	run := func(t *testing.T, signContext ResourceContext, signHierarchy Handle, qualifyingData Data, inScheme *SigScheme, privacyAdminHandleAuthSession, signContextAuthSession SessionContext) {
		timeInfo, signature, err := tpm.GetTime(tpm.EndorsementHandleContext(), signContext, qualifyingData, inScheme, privacyAdminHandleAuthSession, signContextAuthSession)
		if err != nil {
			t.Fatalf("GetTime failed: %v", err)
		}

		attest := verifyAttest(t, tpm, timeInfo, TagAttestTime, signContext, signHierarchy, qualifyingData)

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}
		if attest.Attested.Time.Time.ClockInfo.ResetCount != time.ClockInfo.ResetCount {
			t.Errorf("timeInfo.attested.time.time.clockInfo.resetCount is unexpected")
		}
		if attest.Attested.Time.Time.ClockInfo.RestartCount != time.ClockInfo.RestartCount {
			t.Errorf("timeInfo.attested.time.time.clockInfo.restartCount is unexpected")
		}
		if attest.Attested.Time.Time.ClockInfo.Safe != time.ClockInfo.Safe {
			t.Errorf("timeInfo.attested.time.time.clockInfo.safe is unexpected")
		}

		if attest.Attested.Time.Time.ClockInfo.Clock != attest.ClockInfo.Clock {
			t.Errorf("timeInfo.attested.time.time.clockInfo.clock is unexpected")
		}
		if attest.Attested.Time.Time.ClockInfo.Safe != attest.ClockInfo.Safe {
			t.Errorf("timeInfo.attested.time.time.clockInfo.safe is unexpected")
		}

		verifyAttestSignature(t, tpm, signContext, timeInfo, signature, SigSchemeAlgRSASSA, HashAlgorithmSHA256)
	}

	t.Run("NoSignature", func(t *testing.T) {
		run(t, nil, HandleNull, nil, nil, nil, nil)
	})

	t.Run("WithSignature", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		run(t, ak, HandleEndorsement, nil, nil, nil, nil)
	})

	t.Run("SpecifyInSchemeWithKeyScheme", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}
		run(t, ak, HandleEndorsement, nil, &scheme, nil, nil)
	})

	t.Run("UseInScheme", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
			Params: PublicParamsU{
				Data: &RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}
		priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		key, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, key)

		scheme := SigScheme{
			Scheme:  SigSchemeAlgRSASSA,
			Details: SigSchemeU{Data: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}
		run(t, key, HandleOwner, nil, &scheme, nil, nil)
	})

	t.Run("WithExtraData", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)
		run(t, ak, HandleEndorsement, []byte("foo"), nil, nil, nil)
	})

	t.Run("UsePasswordAuthForKey", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)
		run(t, ak, HandleEndorsement, nil, nil, nil, nil)
	})

	t.Run("UseSessionAuthForKey", func(t *testing.T) {
		ak := prepare(t, testAuth)
		defer flushContext(t, tpm, ak)

		sessionContext, err := tpm.StartAuthSession(nil, ak, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, ak, HandleEndorsement, nil, nil, nil, sessionContext)
	})

	t.Run("UsePasswordAuthForPrivacyAdmin", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)

		setHierarchyAuthForTest(t, tpm, tpm.EndorsementHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.EndorsementHandleContext())

		run(t, ak, HandleEndorsement, nil, nil, nil, nil)
	})

	t.Run("UseSessionAuthForPrivacyAdmin", func(t *testing.T) {
		ak := prepare(t, nil)
		defer flushContext(t, tpm, ak)

		setHierarchyAuthForTest(t, tpm, tpm.EndorsementHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.EndorsementHandleContext())

		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, ak, HandleEndorsement, nil, nil, sessionContext, nil)
	})
}
