// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func TestWrapHandle(t *testing.T) {
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

	persistentHandle := Handle(0x81000008)
	persistentPrimary := persistObjectForTesting(t, tpm, HandleOwner, primary, persistentHandle)
	defer verifyPersistentObjectEvicted(t, tpm, HandleOwner, persistentPrimary)

	closeTPM(t, tpm)
	closed = true
	if primary.Handle() != HandleNull || persistentPrimary.Handle() != HandleNull {
		t.Fatalf("Expected resource contexts to be invalid")
	}

	tpm = openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary, err := tpm.WrapHandle(primaryHandle)
	if err != nil {
		t.Errorf("WrapHandle failed with a live transient object: %v", err)
	}
	if primary == nil {
		t.Errorf("WrapHandle returned a nil pointer for a live transient object")
	}
	if primary.Handle() != primaryHandle {
		t.Errorf("WrapHandle returned an invalid context for a live transient object")
	}
	defer flushContext(t, tpm, primary)

	persistentPrimary, err = tpm.WrapHandle(persistentHandle)
	if err != nil {
		t.Errorf("WrapHandle failed with a live persistent object: %v", err)
	}
	if persistentPrimary == nil {
		t.Errorf("WrapHandle returned a nil pointer for a live persistent object")
	}
	if persistentPrimary.Handle() != persistentHandle {
		t.Errorf("WrapHandle returned an invalid context for a live persistent object")
	}
	defer evictPersistentObject(t, tpm, HandleOwner, persistentPrimary)

	nvPub := NVPublic{
		Index:   0x018100ff,
		NameAlg: AlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
		Size:    8}
	if err := tpm.NVDefineSpace(HandleOwner, nil, &nvPub, nil); err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	index, err := tpm.WrapHandle(nvPub.Index)
	if err != nil {
		t.Errorf("WrapHandle failed with a live NV index: %v", err)
	}
	if index == nil {
		t.Errorf("WrapHandle returned a nil pointer for a live NV index")
	}
	if index.Handle() != nvPub.Index {
		t.Errorf("WrapHandle returned an invalid context for a live NV index")
	}
	defer undefineNVSpace(t, tpm, index, HandleOwner, nil)

	_, err = tpm.WrapHandle(primaryHandle + 1)
	if err == nil {
		t.Fatalf("WrapHandle should return an error for a dead transient object")
	}
	switch e := err.(type) {
	case ResourceDoesNotExistError:
		if e.Handle != primaryHandle + 1 {
			t.Errorf("WrapHandle returned the correct error with the wrong handle")
		}
	default:
		t.Errorf("WrapHandle returned an unexpected error for a dead transient object: %v", err)
	}
	_, err = tpm.WrapHandle(persistentHandle + 1)
	if err == nil {
		t.Fatalf("WrapHandle should return an error for a dead persistent object")
	}
	switch e := err.(type) {
	case ResourceDoesNotExistError:
		if e.Handle != persistentHandle + 1 {
			t.Errorf("WrapHandle returned the correct error with the wrong handle")
		}
	default:
		t.Errorf("WrapHandle returned an unexpected error for a dead persistent object: %v", err)
	}
	_, err = tpm.WrapHandle(nvPub.Index + 1)
	if err == nil {
		t.Fatalf("WrapHandle should return an error for a dead NV index")
	}
	switch e := err.(type) {
	case ResourceDoesNotExistError:
		if e.Handle != nvPub.Index + 1 {
			t.Errorf("WrapHandle returned the correct error with the wrong handle")
		}
	default:
		t.Errorf("WrapHandle returned an unexpected error for a dead NV index: %v", err)
	}
}
