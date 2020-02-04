// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
)

func TestCreateResourceContextFromTPM(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	runCreate := func(t *testing.T, context ResourceContext) {
		rc, err := tpm.CreateResourceContextFromTPM(context.Handle())
		if err != nil {
			t.Errorf("CreateResourceContextFromTPM failed: %v", err)
		}
		if rc == nil {
			t.Fatalf("CreateResourceContextFromTPM returned a nil context")
		}
		if rc == context {
			t.Errorf("CreateResourceContextFromTPM didn't return a new context")
		}
		if rc.Handle() != context.Handle() {
			t.Errorf("CreateResourceContextFromTPM returned a context with the wrong handle")
		}
		if !bytes.Equal(rc.Name(), context.Name()) {
			t.Errorf("CreateResourceContextFromTPM returned a context with the wrong name")
		}
	}

	runCreateUnavailable := func(t *testing.T, handle Handle) {
		rc, err := tpm.CreateResourceContextFromTPM(handle)
		if rc != nil {
			t.Errorf("CreateResourceContextFromTPM returned a non-nil context for a resource that doesn't exist")
		}
		if err == nil {
			t.Fatalf("CreateResourceContextFromTPM should return an error for a resource that doesn't exist")
		}
		if e, ok := err.(ResourceUnavailableError); !ok || e.Handle != handle {
			t.Errorf("CreateResourceContextFromTPM returned an unexpected error for a resource that doesn't exist: %v", err)
		}
	}

	t.Run("Transient", func(t *testing.T) {
		rc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, rc)
		runCreate(t, rc)
		runCreateUnavailable(t, rc.Handle()+1)
	})
	t.Run("Persistent", func(t *testing.T) {
		trc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, trc)
		rc := persistObjectForTesting(t, tpm, tpm.OwnerHandleContext(), trc, Handle(0x81000008))
		defer evictPersistentObject(t, tpm, tpm.OwnerHandleContext(), rc)
		runCreate(t, rc)
		runCreateUnavailable(t, rc.Handle()+1)
	})
	t.Run("NV", func(t *testing.T) {
		pub := NVPublic{
			Index:   0x018100ff,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
			Size:    8}
		rc, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, rc, tpm.OwnerHandleContext(), nil)
		runCreate(t, rc)
		runCreateUnavailable(t, rc.Handle()+1)
	})
}

func TestCreateIncompleteSessionContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	context, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, context)

	sc := CreateIncompleteSessionContext(context.Handle())
	if sc == nil {
		t.Fatalf("CreateIncompleteSessionContext returned a nil context")
	}
	if sc == context {
		t.Errorf("CreateIncompleteSessionContext didn't return a new context")
	}
	if sc.Handle() != context.Handle() {
		t.Errorf("CreateIncompleteSessionContext returned a context with the wrong handle")
	}
	if !bytes.Equal(sc.Name(), context.Name()) {
		t.Errorf("CreateIncompleteSessionContext returned a context with the wrong name")
	}
}

func TestCreateHandleContextFromBytes(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, context ResourceContext) {
		b := context.SerializeToBytes()
		rc, n, err := CreateHandleContextFromBytes(b)
		if err != nil {
			t.Errorf("CreateHandleContextFromBytes failed: %v", err)
		}
		if n != len(b) {
			t.Errorf("CreateHandleContextFromBytes consumed the wrong number of bytes")
		}
		if rc == nil {
			t.Fatalf("CreateHandleContextFromBytes returned a nil context")
		}
		if rc.Handle() != context.Handle() {
			t.Errorf("CreateHandleContextFromBytes returned a context with the wrong handle")
		}
		if !bytes.Equal(rc.Name(), context.Name()) {
			t.Errorf("CreateHandleContextFromBytes returned a context with the wrong name")
		}
		if _, ok := rc.(ResourceContext); !ok {
			t.Fatalf("CreateHandleContextFromBytes returned the wrong HandleContext type")
		}
	}
	t.Run("Transient", func(t *testing.T) {
		rc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, rc)
		run(t, rc)
	})
	t.Run("Persistent", func(t *testing.T) {
		trc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, trc)
		rc := persistObjectForTesting(t, tpm, tpm.OwnerHandleContext(), trc, Handle(0x81000008))
		defer evictPersistentObject(t, tpm, tpm.OwnerHandleContext(), rc)
		run(t, rc)
	})
	t.Run("NV", func(t *testing.T) {
		pub := NVPublic{
			Index:   0x018100ff,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
			Size:    8}
		rc, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, rc, tpm.OwnerHandleContext(), nil)
		run(t, rc)
	})
}

func TestCreateResourceContextFromTPMWithSession(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, context ResourceContext) {
		sc, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sc)
		session := &Session{Context: sc, Attrs: AttrContinueSession | AttrAudit}

		rc, err := tpm.CreateResourceContextFromTPM(context.Handle(), session)
		if err != nil {
			t.Errorf("CreateResourceContextFromTPM failed: %v", err)
		}
		if rc == nil {
			t.Fatalf("CreateResourceContextFromTPM returned a nil context")
		}
		if rc == context {
			t.Errorf("CreateResourceContextFromTPM didn't return a new context")
		}
		if rc.Handle() != context.Handle() {
			t.Errorf("CreateResourceContextFromTPM returned a context with the wrong handle")
		}
		if !bytes.Equal(rc.Name(), context.Name()) {
			t.Errorf("CreateResourceContextFromTPM returned a context with the wrong name")
		}
		if !sc.IsAudit() {
			t.Errorf("CreateResourceContextFromTPM didn't use the provided session")
		}
	}

	t.Run("Transient", func(t *testing.T) {
		rc := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, rc)
		run(t, rc)
	})
	t.Run("NV", func(t *testing.T) {
		pub := NVPublic{
			Index:   0x018100ff,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
			Size:    8}
		rc, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, rc, tpm.OwnerHandleContext(), nil)
		run(t, rc)
	})
}
