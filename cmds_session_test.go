package tpm2

import (
	"testing"
)

func TestStartAuthSessionHMACUnbound(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	if sessionHandle.Handle()&HandleTypeHMACSession != HandleTypeHMACSession {
		t.Errorf("StartAuthSession returned a handle of the wrong type")
	}
}

func TestStartAuthSessionHMACBound(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	owner, err := tpm.WrapHandle(HandleOwner)
	if err != nil {
		t.Fatalf("WrapHandle failed: %v", err)
	}

	sessionHandle, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, "")
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	if sessionHandle.Handle()&HandleTypeHMACSession != HandleTypeHMACSession {
		t.Errorf("StartAuthSession returned a handle of the wrong type")
	}
}

func TestStartAuthSessionHMACUnboundSaltedRSA(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: AlgorithmAES,
					KeyBits:   SymKeyBitsU{Sym: 128},
					Mode:      SymModeU{Sym: AlgorithmCFB}},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}

	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	sessionHandle, err := tpm.StartAuthSession(objectHandle, nil, SessionTypeHMAC, nil, AlgorithmSHA256, "")
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	if sessionHandle.Handle()&HandleTypeHMACSession != HandleTypeHMACSession {
		t.Errorf("StartAuthSession returned a handle of the wrong type")
	}
}

func TestStartAuthSessionHMACUnboundSaltedECC(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	template := Public{
		Type:    AlgorithmECC,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			ECCDetail: &ECCParams{
				Symmetric: SymDefObject{
					Algorithm: AlgorithmAES,
					KeyBits:   SymKeyBitsU{Sym: 128},
					Mode:      SymModeU{Sym: AlgorithmCFB}},
				Scheme:  ECCScheme{Scheme: AlgorithmNull},
				CurveID: ECCCurveNIST_P256,
				KDF:     KDFScheme{Scheme: AlgorithmNull}}},
		Unique: PublicIDU{ECC: &ECCPoint{}}}

	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	sessionHandle, err := tpm.StartAuthSession(objectHandle, nil, SessionTypeHMAC, nil, AlgorithmSHA256, "")
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	if sessionHandle.Handle()&HandleTypeHMACSession != HandleTypeHMACSession {
		t.Errorf("StartAuthSession returned a handle of the wrong type")
	}
}
