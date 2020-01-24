// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"reflect"
	"testing"
)

func TestContextSave(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, rc HandleContext, savedHandle, hierarchy Handle) {
		context, err := tpm.ContextSave(rc)
		if err != nil {
			t.Fatalf("ContextSave failed: %v", err)
		}
		if context.SavedHandle != savedHandle {
			t.Errorf("context has an unexpected handle (0x%08x)", context.SavedHandle)
		}
		if context.Hierarchy != hierarchy {
			t.Errorf("context specifies the wrong hierarchy (0x%08x)", context.Hierarchy)
		}
	}

	t.Run("TransientObject", func(t *testing.T) {
		rc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, rc)
		run(t, rc, Handle(0x80000000), HandleOwner)
	})
	t.Run("Session", func(t *testing.T) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		run(t, sessionContext, sessionContext.Handle(), HandleNull)
		// Make sure that ContextSave marked the session context as not loaded, and that we get the expected error if we attempt to use it
		err = tpm.Clear(tpm.LockoutHandleContext(), &Session{Context: sessionContext})
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "error whilst processing handle with authorization for authContext: invalid resource context for session: not "+
			"complete and loaded" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
	t.Run("IncompleteSession", func(t *testing.T) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		sessionHandle := sessionContext.Handle()
		tpm.ForgetResource(sessionContext)

		sessionContext, err = tpm.WrapSessionHandle(sessionHandle)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		_, err = tpm.ContextSave(sessionContext)
		if err == nil {
			t.Fatalf("Expected an error")
		}
		if err.Error() != "invalid saveContext parameter: unusable session HandleContext" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestContextSaveAndLoad(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	t.Run("TransientObject", func(t *testing.T) {
		rc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, rc)

		context, err := tpm.ContextSave(rc)
		if err != nil {
			t.Fatalf("ContextSave failed: %v", err)
		}
		restoredRc, err := tpm.ContextLoad(context)
		if err != nil {
			t.Fatalf("ContextLoad failed: %v", err)
		}
		defer flushContext(t, tpm, restoredRc)

		if restoredRc.Handle().Type() != HandleTypeTransient {
			t.Errorf("ContextLoad returned an invalid handle 0x%08x", restoredRc.Handle())
		}

		rcImpl := rc.(*objectContext)
		restoredRcImpl := restoredRc.(*objectContext)

		if !reflect.DeepEqual(rcImpl.public, restoredRcImpl.public) {
			t.Errorf("Restored context has the wrong public data")
		}
		if !bytes.Equal(rcImpl.name, restoredRcImpl.name) {
			t.Errorf("Restored context has the wrong name")
		}
	})

	runSessionTest := func(t *testing.T, forget bool, tpmKey, bind HandleContext, sessionType SessionType, hashAlg HashAlgorithmId) {
		sc, err := tpm.StartAuthSession(tpmKey, bind, sessionType, nil, hashAlg, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sc)

		scImpl := sc.(*sessionContext)
		var data struct {
			handle         Handle
			hashAlg        HashAlgorithmId
			sessionType    SessionType
			policyHMACType policyHMACType
			isBound        bool
			boundEntity    Name
			sessionKey     []byte
			nonceCaller    Nonce
			nonceTPM       Nonce
			symmetric      *SymDef
		}
		data.handle = scImpl.handle
		data.hashAlg = scImpl.hashAlg
		data.sessionType = scImpl.sessionType
		data.policyHMACType = scImpl.policyHMACType
		data.isBound = scImpl.isBound
		data.boundEntity = scImpl.boundEntity
		data.sessionKey = scImpl.sessionKey
		data.nonceCaller = scImpl.nonceCaller
		data.nonceTPM = scImpl.nonceTPM
		data.symmetric = scImpl.symmetric

		context, err := tpm.ContextSave(sc)
		if err != nil {
			t.Fatalf("ContextSave failed: %v", err)
		}
		if forget {
			tpm.ForgetResource(sc)
		}
		restoredSc, err := tpm.ContextLoad(context)
		if err != nil {
			t.Fatalf("ContextLoad failed: %v", err)
		}
		defer flushContext(t, tpm, restoredSc)

		if !forget && restoredSc != sc {
			t.Errorf("Expected the same HandleContext back")
		}

		if restoredSc.Handle() != data.handle {
			t.Errorf("ContextLoad returned an invalid handle 0x%08x", restoredSc.Handle())
		}

		scImpl = restoredSc.(*sessionContext)

		if scImpl.hashAlg != data.hashAlg {
			t.Errorf("Restored context has the wrong hash algorithm")
		}
		if scImpl.sessionType != data.sessionType {
			t.Errorf("Restored context has the wrong session type")
		}
		if scImpl.policyHMACType != data.policyHMACType {
			t.Errorf("Restored context has the wrong policy HMAC type")
		}
		if scImpl.isBound != data.isBound {
			t.Errorf("Restored context has the wrong bind status")
		}
		if !bytes.Equal(scImpl.boundEntity, data.boundEntity) {
			t.Errorf("Restored context has the wrong bound resource entity")
		}
		if !bytes.Equal(scImpl.sessionKey, data.sessionKey) {
			t.Errorf("Restored context has the wrong session key")
		}
		if !bytes.Equal(scImpl.nonceCaller, data.nonceCaller) {
			t.Errorf("Restored context has the wrong nonceCaller")
		}
		if !bytes.Equal(scImpl.nonceTPM, data.nonceTPM) {
			t.Errorf("Restored context has the wrong nonceTPM")
		}
		if !reflect.DeepEqual(scImpl.symmetric, data.symmetric) {
			t.Errorf("Restored context has the wrong symmetric")
		}
	}

	t.Run("Session1", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		runSessionTest(t, false, primary, tpm.OwnerHandleContext(), SessionTypeHMAC, HashAlgorithmSHA256)
	})
	t.Run("Session2", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		runSessionTest(t, false, nil, primary, SessionTypeHMAC, HashAlgorithmSHA1)
	})
	t.Run("Session3", func(t *testing.T) {
		runSessionTest(t, false, nil, nil, SessionTypeHMAC, HashAlgorithmSHA256)
	})
	t.Run("Session4", func(t *testing.T) {
		runSessionTest(t, false, nil, nil, SessionTypePolicy, HashAlgorithmSHA256)
	})
	t.Run("Session5", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		runSessionTest(t, true, primary, tpm.OwnerHandleContext(), SessionTypeHMAC, HashAlgorithmSHA256)
	})
}

func TestEvictControl(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, transient HandleContext, persist Handle, authAuth interface{}) {
		owner := tpm.OwnerHandleContext()
		if handle, err := tpm.WrapHandle(persist); err == nil {
			_, err := tpm.EvictControl(owner, handle, persist, authAuth)
			if err != nil {
				t.Logf("EvictControl failed whilst trying to remove a handle at the start of the test: %v", err)
			}
		}

		outContext, err := tpm.EvictControl(owner, transient, persist, authAuth)
		if err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}

		if outContext.Handle() != persist {
			t.Errorf("outContext has the wrong id (0x%08x)", outContext.Handle())
		}

		if !bytes.Equal(transient.Name(), outContext.Name()) {
			t.Errorf("outContext has the wrong name")
		}

		outContext2, err := tpm.EvictControl(owner, outContext, outContext.Handle(), authAuth)
		if err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}
		if outContext2 != nil {
			t.Errorf("EvictControl should return a nil handle when evicting a persistent object")
		}

		if outContext.Handle() != HandleUnassigned {
			t.Errorf("EvictControl should set the persistent context's handle to %v", HandleUnassigned)
		}

		_, err = tpm.WrapHandle(persist)
		if err == nil {
			t.Fatalf("WrapHandle on an evicted resource should fail")
		}
		if _, ok := err.(ResourceUnavailableError); !ok {
			t.Errorf("WrapHandle returned an unexpected error: %v", err)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		context := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, context)
		run(t, context, Handle(0x8100ffff), nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		context := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, context)
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())
		run(t, context, Handle(0x8100fff0), testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		context := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, context)
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())
		sessionContext, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		run(t, context, Handle(0x8100ff00), &Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth})
	})
}

func TestFlushContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	context := createRSASrkForTesting(t, tpm, nil)
	h := context.Handle()

	handles, err := tpm.GetCapabilityHandles(h, 1)
	if err != nil {
		t.Errorf("GetCapability failed: %v", err)
	}
	if len(handles) != 1 {
		t.Errorf("GetCapability should have returned the primary key handle")
	}

	if err := tpm.FlushContext(context); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}

	handles, err = tpm.GetCapabilityHandles(h, 1)
	if err != nil {
		t.Errorf("GetCapability failed: %v", err)
	}
	if len(handles) != 0 {
		t.Errorf("FlushContext didn't flush the transient handle")
	}

	if context.Handle() != HandleUnassigned {
		t.Errorf("FlushContext should set the context's handle to %v", HandleUnassigned)
	}

	_, err = tpm.WrapHandle(h)
	if err == nil {
		t.Fatalf("WrapHandle on a flushed resource should fail")
	}
	if _, ok := err.(ResourceUnavailableError); !ok {
		t.Fatalf("WrapHandle on a flushed resource should fail")
	}
}
