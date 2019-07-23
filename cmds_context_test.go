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

	run := func(t *testing.T, handle ResourceContext, savedHandle, hierarchy Handle) {
		context, err := tpm.ContextSave(handle)
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
		handle := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, handle)
		run(t, handle, Handle(0x80000000), HandleOwner)
	})
	t.Run("Session", func(t *testing.T) {
		handle, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		flushed := false
		defer func() {
			if flushed {
				return
			}
			flushContext(t, tpm, handle)
		}()
		run(t, handle, handle.Handle(), HandleNull)
		flushed = true
	})
}

func TestContextSaveAndLoad(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, handle ResourceContext) ResourceContext {
		context, err := tpm.ContextSave(handle)
		if err != nil {
			t.Fatalf("ContextSave failed: %v", err)
		}

		restoredHandle, err := tpm.ContextLoad(context)
		if err != nil {
			t.Fatalf("ContextLoad failed: %v", err)
		}

		return restoredHandle
	}

	runSessionTest := func(t *testing.T, tpmKey, bind ResourceContext, sessionType SessionType,
		hashAlg AlgorithmId) {
		handle, err := tpm.StartAuthSession(tpmKey, bind, sessionType, nil, hashAlg, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		flushed := false
		defer func() {
			if flushed {
				return
			}
			flushContext(t, tpm, handle)
		}()
		restoredHandle := run(t, handle)
		flushed = true
		defer flushContext(t, tpm, restoredHandle)

		handleType := HandleTypePolicySession
		if sessionType == SessionTypeHMAC {
			handleType = HandleTypeHMACSession
		}

		if restoredHandle.Handle()&handleType != handleType {
			t.Errorf("ContextLoad returned an invalid handle 0x%08x", restoredHandle.Handle())
		}

		rc := handle.(*sessionContext)
		restoredRc := restoredHandle.(*sessionContext)

		if rc.hashAlg != restoredRc.hashAlg {
			t.Errorf("Restored context has the wrong hash algorithm")
		}
		if !bytes.Equal(rc.boundResource, restoredRc.boundResource) {
			t.Errorf("Restored context has the wrong bound resource name")
		}
		if !bytes.Equal(rc.sessionKey, restoredRc.sessionKey) {
			t.Errorf("Restored context has the wrong session key")
		}
		if !bytes.Equal(rc.nonceCaller, restoredRc.nonceCaller) {
			t.Errorf("Restored context has the wrong nonceCaller")
		}
		if !bytes.Equal(rc.nonceTPM, restoredRc.nonceTPM) {
			t.Errorf("Restored context has the wrong nonceTPM")
		}
	}

	t.Run("TransientObject", func(t *testing.T) {
		handle := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, handle)
		restoredHandle := run(t, handle)
		defer flushContext(t, tpm, restoredHandle)

		if restoredHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
			t.Errorf("ContextLoad returned an invalid handle 0x%08x", restoredHandle.Handle())
		}

		rc := handle.(*objectContext)
		restoredRc := restoredHandle.(*objectContext)

		if !reflect.DeepEqual(rc.public, restoredRc.public) {
			t.Errorf("Restored context has the wrong public data")
		}
		if !bytes.Equal(rc.name, restoredRc.name) {
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
				t.Logf("EvictControl failed whilst trying to remove a handle at the start of "+
					"the test: %v", err)
			}
		}

		outHandle, err := tpm.EvictControl(HandleOwner, transient, persist, authAuth)
		if err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}

		if outHandle.Handle() != persist {
			t.Errorf("outHandle has the wrong id (0x%08x)", outHandle.Handle())
		}

		if !bytes.Equal(transient.Name(), outHandle.Name()) {
			t.Errorf("outHandle has the wrong name")
		}

		outHandle2, err := tpm.EvictControl(HandleOwner, outHandle, outHandle.Handle(), authAuth)
		if err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}
		if outHandle2 != nil {
			t.Errorf("EvictControl should return a nil handle when evicting a persistent object")
		}

		if outHandle.Handle() != HandleNull {
			t.Errorf("EvictControl should set the persistent context's handle to NULL")
		}

		_, _, _, err = tpm.ReadPublic(outHandle)
		if err == nil {
			t.Fatalf("Calling ReadPublic on a dead resource context should fail")
		}
		if err.Error() != "invalid resource context for objectHandle: resource has been closed" {
			t.Errorf("ReadPublic returned an unexpected error: %v", err)
		}
	}

	setupOwnerAuth := func(t *testing.T) {
		if err := tpm.HierarchyChangeAuth(HandleOwner, Auth(testAuth), nil); err != nil {
			t.Fatalf("HierarchyChangeAuth failed: %v", err)
		}
	}

	resetOwnerAuth := func(t *testing.T) {
		if err := tpm.HierarchyChangeAuth(HandleOwner, nil, testAuth); err != nil {
			t.Errorf("HierarchyChangeAuth failed to clear the auth value: %v", err)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		objectHandle := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, objectHandle)
		run(t, objectHandle, Handle(0x81020000), nil)
	})
	t.Run("PasswordAuth", func(t *testing.T) {
		objectHandle := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, objectHandle)
		setupOwnerAuth(t)
		defer resetOwnerAuth(t)
		run(t, objectHandle, Handle(0x81020001), testAuth)
	})
	t.Run("SessionAuth", func(t *testing.T) {
		objectHandle := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, objectHandle)
		setupOwnerAuth(t)
		defer resetOwnerAuth(t)
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionHandle, err :=
			tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionHandle)
		run(t, objectHandle, Handle(0x81020001),
			&Session{Handle: sessionHandle, Attrs: AttrContinueSession, AuthValue: dummyAuth})
	})
}

func TestFlushContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	objectHandle := createRSASrkForTesting(t, tpm, nil)
	h := objectHandle.Handle()

	handles, err := tpm.GetCapabilityHandles(h, 1)
	if err != nil {
		t.Errorf("GetCapability failed: %v", err)
	}
	if len(handles) != 1 {
		t.Errorf("GetCapability should have returned the primary key handle")
	}

	if err := tpm.FlushContext(objectHandle); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}

	handles, err = tpm.GetCapabilityHandles(h, 1)
	if err != nil {
		t.Errorf("GetCapability failed: %v", err)
	}
	if len(handles) != 0 {
		t.Errorf("FlushContext didn't flush the transient handle")
	}

	if objectHandle.Handle() != HandleNull {
		t.Errorf("FlushContext should set the context's handle to NULL")
	}

	_, _, _, err = tpm.ReadPublic(objectHandle)
	if err == nil {
		t.Errorf("Calling ReadPublic on a dead resource context should fail")
	}
	if err.Error() != "invalid resource context for objectHandle: resource has been closed" {
		t.Errorf("ReadPublic returned an unexpected error: %v", err)
	}
}
