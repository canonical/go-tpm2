// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"testing"
)

func TestCertifyCreation(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			&RSAParams{
				Symmetric: SymDefObject{
					Algorithm: AlgorithmAES,
					KeyBits:   SymKeyBitsU{uint16(128)},
					Mode:      SymModeU{AlgorithmCFB}},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	objectHandle, _, _, creationHash, creationTicket, name, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	certifyInfo, signature, err := tpm.CertifyCreation(nil, objectHandle, nil, creationHash, nil, creationTicket, nil)
	if err != nil {
		t.Fatalf("CertifyCreation failed: %v", err)
	}
	if certifyInfo == nil {
		t.Fatalf("CertifyCreation returned a nil certifyInfo")
	}

	attest, err := certifyInfo.Decode()
	if err != nil {
		t.Fatalf("certifyInfo failed to unmarshal: %v", err)
	}

	if attest.Magic != TPMGeneratedValue {
		t.Errorf("certifyInfo has the wrong magic value")
	}
	if attest.Type != TagAttestCreation {
		t.Errorf("certifyInfo has the wrong type")
	}
	if !bytes.Equal(attest.Attest.Creation().ObjectName, name) {
		t.Errorf("certifyInfo has the wrong objectName")
	}
	if !bytes.Equal(attest.Attest.Creation().CreationHash, creationHash) {
		t.Errorf("certifyInfo has the wrong creationHash")
	}
	if signature == nil {
		t.Fatalf("CertifyCreation returned a nil signature")
	}
	if signature.SigAlg != AlgorithmNull {
		t.Errorf("CertifyCreation returned the wrong sigAlg")
	}
}
