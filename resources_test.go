// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestGetOrCreateResourceContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	closed := false
	defer func() {
		if closed {
			return
		}
		closeTPM(t, tpm)
	}()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer verifyContextFlushed(t, tpm, primary)
	primaryHandle := primary.Handle()
	primaryName := primary.Name()

	persistentHandle := Handle(0x81000008)
	persistentPrimary := persistObjectForTesting(t, tpm, tpm.OwnerHandleContext(), primary, persistentHandle)
	defer verifyPersistentObjectEvicted(t, tpm, tpm.OwnerHandleContext(), persistentPrimary)

	nvPub := NVPublic{
		Index:   0x018100ff,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
		Size:    8}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer verifyNVSpaceUndefined(t, tpm, index, tpm.OwnerHandleContext(), nil)

	verifyGet := func(context ResourceContext) {
		if rc, err := tpm.GetOrCreateResourceContext(context.Handle()); err != nil {
			t.Errorf("GetOrCreateResourceContext failed: %v", err)
		} else if rc != context {
			t.Errorf("GetOrCreateResourceContext returned the wrong context")
		}
	}
	verifyGet(primary)
	verifyGet(persistentPrimary)
	verifyGet(index)

	closeTPM(t, tpm)
	closed = true

	if primary.Handle() != HandleUnassigned || persistentPrimary.Handle() != HandleUnassigned || index.Handle() != HandleUnassigned {
		t.Fatalf("Expected resource contexts to be invalid")
	}

	tpm = openTPMForTesting(t)
	defer closeTPM(t, tpm)

	verifyCreate := func(handle Handle, name Name) ResourceContext {
		rc, err := tpm.GetOrCreateResourceContext(handle)
		if err != nil {
			t.Fatalf("GetOrCreateResourceContext failed: %v", err)
		}
		if rc == nil {
			t.Fatalf("GetOrCreateResourceContext returned a nil context")
		}
		if rc.Handle() != handle {
			t.Errorf("GetOrCreateResourceContext returned a context with the wrong handle")
		}
		if !bytes.Equal(rc.Name(), name) {
			t.Errorf("GetOrCreateResourceContext returned a context with the wrong name")
		}
		return rc
	}
	primary = verifyCreate(primaryHandle, primaryName)
	persistentPrimary = verifyCreate(persistentHandle, primaryName)
	nvName, _ := nvPub.Name()
	index = verifyCreate(nvPub.Index, nvName)
	defer flushContext(t, tpm, primary)
	defer evictPersistentObject(t, tpm, tpm.OwnerHandleContext(), persistentPrimary)
	defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext(), nil)

	verifyCreateUnavailable := func(handle Handle) {
		_, err = tpm.GetOrCreateResourceContext(handle)
		if err == nil {
			t.Fatalf("GetOrCreateResourceContext should return an error for a resource that doesn't exist")
		}
		if e, ok := err.(ResourceUnavailableError); !ok || e.Handle != handle {
			t.Errorf("GetOrCreateResourceContext returned an unexpected error for a resource that doesn't exist: %v", err)
		}
	}
	verifyCreateUnavailable(primaryHandle + 1)
	verifyCreateUnavailable(persistentHandle + 1)
	verifyCreateUnavailable(nvPub.Index + 1)
}

func TestGetOrCreateSessionContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	closed := false
	defer func() {
		if closed {
			return
		}
		closeTPM(t, tpm)
	}()

	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer verifyContextFlushed(t, tpm, sessionContext)
	sessionHandle := sessionContext.Handle()

	savedSessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer verifyContextFlushed(t, tpm, savedSessionContext)
	savedSessionHandle := savedSessionContext.Handle()

	if _, err := tpm.ContextSave(savedSessionContext); err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}

	verifyGet := func(context SessionContext) {
		if rc, err := tpm.GetOrCreateSessionContext(context.Handle()); err != nil {
			t.Errorf("GetOrCreateSessionContext failed: %v", err)
		} else if rc != context {
			t.Errorf("GetOrCreateSessionContext returned the wrong context")
		}
	}
	verifyGet(sessionContext)
	verifyGet(savedSessionContext)

	closeTPM(t, tpm)
	closed = true

	if sessionContext.Handle() != HandleUnassigned || savedSessionContext.Handle() != HandleUnassigned {
		t.Fatalf("Expected session contexts to be invalid")
	}

	tpm = openTPMForTesting(t)
	defer closeTPM(t, tpm)

	verifyCreate := func(handle, expected Handle) SessionContext {
		rc, err := tpm.GetOrCreateSessionContext(handle)
		if err != nil {
			t.Fatalf("GetOrCreateSessionContext failed: %v", err)
		}
		if rc == nil {
			t.Fatalf("GetOrCreateSessionContext returned a nil context")
		}
		if rc.Handle() != expected {
			t.Errorf("GetOrCreateSessionContext returned a context with the wrong handle")
		}
		name := make(Name, binary.Size(Handle(0)))
		binary.BigEndian.PutUint32(name, uint32(expected))
		if !bytes.Equal(rc.Name(), name) {
			t.Errorf("GetOrCreateSessionContext returned a context with the wrong name")
		}
		return rc
	}
	sessionContext = verifyCreate(sessionHandle, sessionHandle)
	savedSessionContext = verifyCreate(savedSessionHandle, (savedSessionHandle&0xffffff)|(Handle(HandleTypeHMACSession)<<24))
	defer flushContext(t, tpm, sessionContext)
	defer flushContext(t, tpm, savedSessionContext)
}

func TestCreateHandleContextFromBytes(t *testing.T) {
	tpm := openTPMForTesting(t)
	closed := false
	defer func() {
		if closed {
			return
		}
		closeTPM(t, tpm)
	}()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer verifyContextFlushed(t, tpm, primary)
	primaryHandle := primary.Handle()
	primaryName := primary.Name()

	persistentHandle := Handle(0x81000008)
	persistentPrimary := persistObjectForTesting(t, tpm, tpm.OwnerHandleContext(), primary, persistentHandle)
	defer verifyPersistentObjectEvicted(t, tpm, tpm.OwnerHandleContext(), persistentPrimary)

	nvPub := NVPublic{
		Index:   0x018100ff,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
		Size:    8}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer verifyNVSpaceUndefined(t, tpm, index, tpm.OwnerHandleContext(), nil)

	primarySaved := primary.SerializeToBytes()
	persistentPrimarySaved := persistentPrimary.SerializeToBytes()
	indexSaved := index.SerializeToBytes()

	closeTPM(t, tpm)
	closed = true

	tpm = openTPMForTesting(t)
	defer closeTPM(t, tpm)

	verify := func(b []byte, handle Handle, name Name) ResourceContext {
		rc, n, err := tpm.CreateHandleContextFromBytes(b)
		if err != nil {
			t.Errorf("CreateHandleContextFromBytes failed: %v", err)
		}
		if n != len(b) {
			t.Errorf("CreateHandleContextFromBytes consumed the wrong number of bytes")
		}
		if rc == nil {
			t.Fatalf("CreateHandleContextFromBytes returned a nil context")
		}
		if rc.Handle() != handle {
			t.Errorf("CreateHandleContextFromBytes returned a context with the wrong handle")
		}
		if !bytes.Equal(rc.Name(), name) {
			t.Errorf("CreateHandleContextFromBytes returned a context with the wrong name")
		}
		if _, ok := rc.(ResourceContext); !ok {
			t.Fatalf("CreateHandleContextFromBytes returned the wrong HandleContext type")
		}
		return rc.(ResourceContext)
	}
	primary = verify(primarySaved, primaryHandle, primaryName)
	persistentPrimary = verify(persistentPrimarySaved, persistentHandle, primaryName)
	nvName, _ := nvPub.Name()
	index = verify(indexSaved, nvPub.Index, nvName)
	defer flushContext(t, tpm, primary)
	defer evictPersistentObject(t, tpm, tpm.OwnerHandleContext(), persistentPrimary)
	defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext(), nil)
}

func TestGetOrCreateResourceContextWithSession(t *testing.T) {
	tpm := openTPMForTesting(t)
	closed := false
	defer func() {
		if closed {
			return
		}
		closeTPM(t, tpm)
	}()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer verifyContextFlushed(t, tpm, primary)
	primaryHandle := primary.Handle()
	primaryName := primary.Name()

	nvPub := NVPublic{
		Index:   0x018100ff,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
		Size:    8}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer verifyNVSpaceUndefined(t, tpm, index, tpm.OwnerHandleContext(), nil)

	closeTPM(t, tpm)
	closed = true

	if primary.Handle() != HandleUnassigned || index.Handle() != HandleUnassigned {
		t.Fatalf("Expected resource contexts to be invalid")
	}

	tpm = openTPMForTesting(t)
	defer closeTPM(t, tpm)

	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionContext)
	session := &Session{Context: sessionContext, Attrs: AttrContinueSession | AttrAudit}

	var lastAuditDigest Digest

	verifyCreate := func(handle Handle, name Name) ResourceContext {
		rc, err := tpm.GetOrCreateResourceContext(handle, session)
		if err != nil {
			t.Fatalf("GetOrCreateResourceContext failed: %v", err)
		}
		if rc == nil {
			t.Fatalf("GetOrCreateResourceContext returned a nil context")
		}
		if rc.Handle() != handle {
			t.Errorf("GetOrCreateResourceContext returned a context with the wrong handle")
		}
		if !bytes.Equal(rc.Name(), name) {
			t.Errorf("GetOrCreateResourceContext returned a context with the wrong name")
		}

		attestRaw, _, err := tpm.GetSessionAuditDigest(tpm.EndorsementHandleContext(), nil, sessionContext, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("GetSessionAuditDigest failed: %v", err)
		}
		attest, _ := attestRaw.Decode()
		if bytes.Equal(attest.Attested.SessionAudit().SessionDigest, lastAuditDigest) {
			t.Errorf("GetOrCreateResourceContext didn't use session")
		}
		lastAuditDigest = attest.Attested.SessionAudit().SessionDigest

		return rc
	}

	primary = verifyCreate(primaryHandle, primaryName)
	nvName, _ := nvPub.Name()
	index = verifyCreate(nvPub.Index, nvName)
	defer flushContext(t, tpm, primary)
	defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext(), nil)
}
