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

	run := func(t *testing.T, rc ResourceContext, savedHandle, hierarchy Handle) {
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
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, sessionContext, sessionContext.Handle(), HandleNull)
	})
}

func TestContextSaveAndLoad(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, rc ResourceContext) ResourceContext {
		context, err := tpm.ContextSave(rc)
		if err != nil {
			t.Fatalf("ContextSave failed: %v", err)
		}

		restoredContext, err := tpm.ContextLoad(context)
		if err != nil {
			t.Fatalf("ContextLoad failed: %v", err)
		}

		return restoredContext
	}

	runSessionTest := func(t *testing.T, tpmKey, bind ResourceContext, sessionType SessionType, hashAlg AlgorithmId) {
		sc, err := tpm.StartAuthSession(tpmKey, bind, sessionType, nil, hashAlg, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sc)
		restoredSc := run(t, sc)
		defer flushContext(t, tpm, restoredSc)

		handleType := HandleTypePolicySession
		if sessionType == SessionTypeHMAC {
			handleType = HandleTypeHMACSession
		}

		if restoredSc.Handle().Type() != handleType {
			t.Errorf("ContextLoad returned an invalid handle 0x%08x", restoredSc.Handle())
		}

		scImpl := sc.(*sessionContext)
		restoredScImpl := restoredSc.(*sessionContext)

		if scImpl.hashAlg != restoredScImpl.hashAlg {
			t.Errorf("Restored context has the wrong hash algorithm")
		}
		if scImpl.sessionType != restoredScImpl.sessionType {
			t.Errorf("Restored context has the wrong session type")
		}
		if scImpl.policyHMACType != restoredScImpl.policyHMACType {
			t.Errorf("Restored context has the wrong policy HMAC type")
		}
		if scImpl.isBound != restoredScImpl.isBound {
			t.Errorf("Restored context has the wrong bind status")
		}
		if !bytes.Equal(scImpl.boundEntity, restoredScImpl.boundEntity) {
			t.Errorf("Restored context has the wrong bound resource entity")
		}
		if !bytes.Equal(scImpl.sessionKey, restoredScImpl.sessionKey) {
			t.Errorf("Restored context has the wrong session key")
		}
		if !bytes.Equal(scImpl.nonceCaller, restoredScImpl.nonceCaller) {
			t.Errorf("Restored context has the wrong nonceCaller")
		}
		if !bytes.Equal(scImpl.nonceTPM, restoredScImpl.nonceTPM) {
			t.Errorf("Restored context has the wrong nonceTPM")
		}
	}

	t.Run("TransientObject", func(t *testing.T) {
		rc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, rc)
		restoredRc := run(t, rc)
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
	t.Run("Session1", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		owner, _ := tpm.WrapHandle(HandleOwner)
		runSessionTest(t, primary, owner, SessionTypeHMAC, AlgorithmSHA256)
	})
	t.Run("Session2", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)
		runSessionTest(t, nil, primary, SessionTypeHMAC, AlgorithmSHA1)
	})
	t.Run("Session3", func(t *testing.T) {
		runSessionTest(t, nil, nil, SessionTypeHMAC, AlgorithmSHA256)
	})
	t.Run("Session4", func(t *testing.T) {
		runSessionTest(t, nil, nil, SessionTypePolicy, AlgorithmSHA256)
	})
}

func TestEvictControl(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, transient ResourceContext, persist Handle, authAuth interface{}) {
		if handle, err := tpm.WrapHandle(persist); err == nil {
			_, err := tpm.EvictControl(HandleOwner, handle, persist, authAuth)
			if err != nil {
				t.Logf("EvictControl failed whilst trying to remove a handle at the start of the test: %v", err)
			}
		}

		outContext, err := tpm.EvictControl(HandleOwner, transient, persist, authAuth)
		if err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}

		if outContext.Handle() != persist {
			t.Errorf("outContext has the wrong id (0x%08x)", outContext.Handle())
		}

		if !bytes.Equal(transient.Name(), outContext.Name()) {
			t.Errorf("outContext has the wrong name")
		}

		outContext2, err := tpm.EvictControl(HandleOwner, outContext, outContext.Handle(), authAuth)
		if err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}
		if outContext2 != nil {
			t.Errorf("EvictControl should return a nil handle when evicting a persistent object")
		}

		if outContext.Handle() != HandleNull {
			t.Errorf("EvictControl should set the persistent context's handle to NULL")
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
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)
		run(t, context, Handle(0x8100fff0), testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		context := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, context)
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, testAuth)
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

	if context.Handle() != HandleNull {
		t.Errorf("FlushContext should set the context's handle to NULL")
	}

	_, err = tpm.WrapHandle(h)
	if err == nil {
		t.Fatalf("WrapHandle on a flushed resource should fail")
	}
	if _, ok := err.(ResourceUnavailableError); !ok {
		t.Fatalf("WrapHandle on a flushed resource should fail")
	}
}
