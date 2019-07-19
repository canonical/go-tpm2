package tpm2

import (
	"bytes"
	"testing"
)

func TestContextSaveTransient(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	objectHandle, _ := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, objectHandle)

	context, err := tpm.ContextSave(objectHandle)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}
	if context.SavedHandle != objectHandle.Handle() {
		t.Errorf("context has an unexpected handle (0x%08x)", context.SavedHandle)
	}
	if context.Hierarchy != HandleOwner {
		t.Errorf("context specifies the wrong hierarchy (0x%08x)", context.Hierarchy)
	}
}

func TestContextLoadTransient(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	objectHandle, name := createRSASrkForTesting(t, tpm, nil)
	flushed := false
	defer func() {
		if flushed {
			return
		}
		flushContext(t, tpm, objectHandle)
	}()

	context, err := tpm.ContextSave(objectHandle)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}

	if err := tpm.FlushContext(objectHandle); err != nil {
		t.Fatalf("FlushContext failed: %v", err)
	}
	flushed = true

	restoredHandle, err := tpm.ContextLoad(context)
	if err != nil {
		t.Fatalf("ContextLoad failed: %v", err)
	}
	defer flushContext(t, tpm, restoredHandle)

	if restoredHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
		t.Errorf("ContextLoad returned an invalid handle 0x%08x", restoredHandle.Handle())
	}

	_, restoredName, _, err := tpm.ReadPublic(restoredHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	if !bytes.Equal(name, restoredName) {
		t.Errorf("Name of restored object doesn't match that of the saved object")
	}
}

func TestEvictControl(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	run := func(t *testing.T, transient ResourceContext, persist Handle, authAuth interface{}) {
		handle, err := tpm.WrapHandle(persist)
		if err == nil {
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

		outHandle2, err := tpm.EvictControl(HandleOwner, outHandle, outHandle.Handle(), authAuth)
		if err != nil {
			t.Errorf("EvictControl failed: %v", err)
		}
		if outHandle2 != nil {
			t.Errorf("EvictControl should return a nil handle when evicting a persistent object")
		}

		_, _, _, err = tpm.ReadPublic(outHandle)
		if err == nil {
			t.Fatalf("Calling ReadPublic on a dead resource context should fail")
		}
		if err.Error() != "invalid resource context for objectHandle: resource has been closed" {
			t.Errorf("ReadPublic returned an unexpected error: %v", err)
		}
	}

	auth := []byte("1234")

	setupOwnerAuth := func(t *testing.T) {
		if err := tpm.HierarchyChangeAuth(HandleOwner, Auth(auth), nil); err != nil {
			t.Fatalf("HierarchyChangeAuth failed: %v", err)
		}
	}

	resetOwnerAuth := func(t *testing.T) {
		if err := tpm.HierarchyChangeAuth(HandleOwner, nil, auth); err != nil {
			t.Errorf("HierarchyChangeAuth failed to clear the auth value: %v", err)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		objectHandle, _ := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, objectHandle)
		run(t, objectHandle, Handle(0x81020000), nil)
	})
	t.Run("PasswordAuth", func(t *testing.T) {
		objectHandle, _ := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, objectHandle)
		setupOwnerAuth(t)
		defer resetOwnerAuth(t)
		run(t, objectHandle, Handle(0x81020001), auth)
	})
	t.Run("SessionAuth", func(t *testing.T) {
		objectHandle, _ := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, objectHandle)
		setupOwnerAuth(t)
		defer resetOwnerAuth(t)
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionHandle, err :=
			tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, auth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionHandle)
		run(t, objectHandle, Handle(0x81020001),
			&Session{Handle: sessionHandle, Attributes: AttrContinueSession})
	})
}

func TestFlushContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	objectHandle, _ := createRSASrkForTesting(t, tpm, nil)
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

	_, _, _, err = tpm.ReadPublic(objectHandle)
	if err == nil {
		t.Errorf("Calling ReadPublic on a dead resource context should fail")
	}
	if err.Error() != "invalid resource context for objectHandle: resource has been closed" {
		t.Errorf("ReadPublic returned an unexpected error: %v", err)
	}
}
