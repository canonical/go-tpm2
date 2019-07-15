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
