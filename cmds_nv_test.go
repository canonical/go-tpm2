// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestNVDefineAndUndefineSpace(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, auth Auth, publicInfo *NVPublic, ownerAuth interface{}) {
		if err := tpm.NVDefineSpace(HandleOwner, auth, publicInfo, ownerAuth); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer func() {
			rc, err := tpm.WrapHandle(publicInfo.Index)
			if err != nil {
				t.Fatalf("WrapHandle failed: %v", err)
			}
			if err := tpm.NVUndefineSpace(HandleOwner, rc, ownerAuth); err != nil {
				t.Errorf("NVUndefineSpace failed: %v", err)
			}
			if rc.Handle() != HandleNull {
				t.Errorf("Context should be invalid after NVUndefineSpace")
			}
		}()

		nvContext, err := tpm.WrapHandle(publicInfo.Index)
		if err != nil {
			t.Fatalf("Failed to create context for newly created NV index: %v", err)
		}

		nvPub := nvContext.(*nvIndexContext).public

		if nvPub.NameAlg != publicInfo.NameAlg {
			t.Errorf("Unexpected nameAlg")
		}
		if nvPub.Attrs != publicInfo.Attrs {
			t.Errorf("Unexpected attrs")
		}
		if !bytes.Equal(nvPub.AuthPolicy, publicInfo.AuthPolicy) {
			t.Errorf("Unexpected authPolicy")
		}
		if nvPub.Size != publicInfo.Size {
			t.Errorf("Unexpected size (%d)", nvPub.Size)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: AlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteAll|AttrNVAuthRead, NVTypeOrdinary),
			Size:    64}
		run(t, nil, &pub, nil)
	})
	t.Run("RequirePWAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: AlgorithmSHA256,
			Attrs: MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteAll|AttrNVAuthRead|
				AttrNVOwnerRead, NVTypeOrdinary),
			Size: 32}
		run(t, nil, &pub, testAuth)
	})
	t.Run("RequireSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: dummyAuth}

		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: AlgorithmSHA256,
			Attrs: MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteAll|AttrNVAuthRead|
				AttrNVOwnerRead, NVTypeOrdinary),
			Size: 64}
		run(t, nil, &pub, &session)
	})
	t.Run("WithAuth", func(t *testing.T) {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: AlgorithmSHA1,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
			Size:    32}
		if err := tpm.NVDefineSpace(HandleOwner, testAuth, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		rc, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("Failed to create context for newly created NV index: %v", err)
		}
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)

		if err := tpm.NVWrite(rc, rc, []byte{0}, 0, testAuth); err != nil {
			t.Errorf("Failed to write to NV index with authValue: %v", err)
		}
	})
}

func TestNVReadAndWrite(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	pub := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: AlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
		Size:    64}

	define := func(t *testing.T, authValue Auth) ResourceContext {
		if err := tpm.NVDefineSpace(HandleOwner, authValue, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		rc, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}

		return rc
	}

	runWrite := func(t *testing.T, rc ResourceContext, data MaxNVBuffer, offset uint16, auth interface{}) {
		if err := tpm.NVWrite(rc, rc, data, offset, auth); err != nil {
			t.Fatalf("NVWrite failed: %v", err)
		}

		pub, name, err := tpm.NVReadPublic(rc)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}

		if pub.Attrs&AttrNVWritten == 0 {
			t.Errorf("Unexpected attributes")
		}
		if !bytes.Equal(name, rc.Name()) {
			t.Errorf("Name of NV resource context should have been refreshed")
		}
	}

	runRead := func(t *testing.T, rc ResourceContext, data MaxNVBuffer, offset uint16, auth interface{}) {
		d, err := tpm.NVRead(rc, rc, uint16(len(data)), offset, auth)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}

		if !bytes.Equal(d, data) {
			t.Errorf("Unexpected data read back")
		}

		d, err = tpm.NVRead(rc, rc, pub.Size, 0, auth)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}

		expected := make([]byte, pub.Size)
		for i := range expected {
			expected[i] = 0xff
		}
		copy(expected[offset:], data)

		if !bytes.Equal(d, expected) {
			t.Errorf("Unexpected data read back")
		}
	}

	t.Run("Full", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		d := make([]byte, pub.Size)
		rand.Read(d)
		runWrite(t, rc, d, 0, nil)
		runRead(t, rc, d, 0, nil)
	})
	t.Run("Partial", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		d := []byte{1, 2, 3, 4}
		runWrite(t, rc, d, 10, nil)
		runRead(t, rc, d, 10, nil)
	})
	t.Run("WithPWAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		d := []byte{1, 2, 3, 4}
		runWrite(t, rc, d, 10, testAuth)
		runRead(t, rc, d, 10, testAuth)
	})
	t.Run("WithSessionAuthBound1", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: dummyAuth}
		d := make([]byte, pub.Size)
		rand.Read(d)
		runWrite(t, rc, d, 0, &session)

		// Writing updates the NV index's attributes which also changes the name. This means that the
		// session is no longer bound to it
		session.AuthValue = testAuth
		runRead(t, rc, d, 0, &session)
	})
	t.Run("WithSessionAuthBound2", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext1, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext1)
		session := Session{Context: sessionContext1, Attrs: AttrContinueSession, AuthValue: dummyAuth}
		d := make([]byte, pub.Size)
		rand.Read(d)
		runWrite(t, rc, d, 0, &session)

		// Writing updates the NV index's attributes which also changes the name. This means that the
		// session is no longer bound to it. Create a new bound session
		sessionContext2, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext2)
		session = Session{Context: sessionContext2, Attrs: AttrContinueSession, AuthValue: dummyAuth}
		runRead(t, rc, d, 0, &session)
	})
}

func TestNVIncrement(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: AlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeCounter),
			Size:    8}

		if err := tpm.NVDefineSpace(HandleOwner, authValue, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		rc, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, authInc interface{}) {
		if err := tpm.NVIncrement(rc, rc, authInc); err != nil {
			t.Fatalf("NVIncrement failed: %v", err)
		}

		pub, name, err := tpm.NVReadPublic(rc)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}

		if pub.Attrs&AttrNVWritten == 0 {
			t.Errorf("Unexpected attributes")
		}
		if !bytes.Equal(name, rc.Name()) {
			t.Errorf("Name of NV resource context should have been refreshed")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, nil)
	})
	t.Run("RequirePWAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, testAuth)
	})
	t.Run("RequireSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		session := Session{Context: sessionContext, AuthValue: dummyAuth}
		run(t, rc, &session)
	})
}

func TestNVExtend(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: AlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeExtend),
			Size:    32}

		if err := tpm.NVDefineSpace(HandleOwner, authValue, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		rc, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, data []byte, auth interface{}) {
		h := sha256.New()
		h.Write(data)
		dataH := h.Sum(nil)

		if err := tpm.NVExtend(rc, rc, dataH, auth); err != nil {
			t.Fatalf("NVExtend failed: %v", err)
		}

		pub, name, err := tpm.NVReadPublic(rc)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}

		if pub.Attrs&AttrNVWritten == 0 {
			t.Errorf("Unexpected attributes")
		}
		if !bytes.Equal(name, rc.Name()) {
			t.Errorf("Name of NV resource context should have been refreshed")
		}

		h = sha256.New()
		h.Write(make([]byte, 32))
		h.Write(dataH)

		d, err := tpm.NVRead(rc, rc, 32, 0, auth)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}

		if !bytes.Equal(d, h.Sum(nil)) {
			t.Errorf("Unexpected data returned from NV index")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, []byte("foo"), nil)
	})
	t.Run("RequirePWAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, []byte("bar"), testAuth)
	})
	t.Run("RequireSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth}
		run(t, rc, []byte("foo"), &session)
	})
}

func TestNVSetBits(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: AlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeBits),
			Size:    8}

		if err := tpm.NVDefineSpace(HandleOwner, authValue, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		rc, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, bits []uint64, auth interface{}) {
		var expected uint64
		for _, b := range bits {
			if err := tpm.NVSetBits(rc, rc, b, auth); err != nil {
				t.Fatalf("NVSetBits failed: %v", err)
			}
			expected |= b
		}

		pub, name, err := tpm.NVReadPublic(rc)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}

		if pub.Attrs&AttrNVWritten == 0 {
			t.Errorf("Unexpected attributes")
		}
		if !bytes.Equal(name, rc.Name()) {
			t.Errorf("Name of NV resource context should have been refreshed")
		}

		d, err := tpm.NVRead(rc, rc, 8, 0, auth)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}

		if binary.BigEndian.Uint64(d) != expected {
			t.Errorf("Unexpected data returned from NV index")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, []uint64{0x1, 0x4000000000000}, nil)
	})
	t.Run("RequirePWAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, []uint64{0x2, 0xf2610ea91007d0}, testAuth)
	})
	t.Run("RequireSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth}
		run(t, rc, []uint64{0xde45670980, 0x456, 0xe}, &session)
	})
}

func TestNVWriteLock(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: AlgorithmSHA256,
			Attrs: MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteDefine|AttrNVAuthRead,
				NVTypeOrdinary),
			Size: 8}

		if err := tpm.NVDefineSpace(HandleOwner, authValue, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		rc, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, auth interface{}) {
		if err := tpm.NVWriteLock(rc, rc, auth); err != nil {
			t.Fatalf("NVWriteLock failed: %v", err)
		}

		pub, name, err := tpm.NVReadPublic(rc)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}

		if pub.Attrs&AttrNVWriteLocked == 0 {
			t.Errorf("Unexpected attributes")
		}
		if !bytes.Equal(name, rc.Name()) {
			t.Errorf("Name of NV resource context should have been refreshed")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, nil)
	})
	t.Run("RequirePWAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, testAuth)
	})
	t.Run("RequireSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		session := Session{Context: sessionContext, AuthValue: dummyAuth}
		run(t, rc, &session)
	})
}

func TestNVReadLock(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: AlgorithmSHA256,
			Attrs: MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead|AttrNVReadStClear,
				NVTypeOrdinary),
			Size: 8}

		if err := tpm.NVDefineSpace(HandleOwner, authValue, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		rc, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, auth interface{}) {
		if err := tpm.NVReadLock(rc, rc, auth); err != nil {
			t.Fatalf("NVWriteLock failed: %v", err)
		}

		pub, name, err := tpm.NVReadPublic(rc)
		if err != nil {
			t.Fatalf("NVReadPublic failed: %v", err)
		}

		if pub.Attrs&AttrNVReadLocked == 0 {
			t.Errorf("Unexpected attributes")
		}
		if !bytes.Equal(name, rc.Name()) {
			t.Errorf("Name of NV resource context should have been refreshed")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, nil)
	})
	t.Run("RequirePWAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, testAuth)
	})
	t.Run("RequireSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		session := Session{Context: sessionContext, AuthValue: dummyAuth}
		run(t, rc, &session)
	})
}

func TestNVGlobalLock(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, auth interface{}) {
		var rcs []ResourceContext
		for _, data := range []NVPublic{
			{
				Index:   Handle(0x0181fff0),
				NameAlg: AlgorithmSHA256,
				Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
				Size:    8,
			},
			{
				Index:   Handle(0x0181ffe0),
				NameAlg: AlgorithmSHA256,
				Attrs: MakeNVAttributes(AttrNVAuthWrite|AttrNVGlobalLock|AttrNVAuthRead,
					NVTypeOrdinary),
				Size: 8,
			},
			{
				Index:   Handle(0x0181ffff),
				NameAlg: AlgorithmSHA256,
				Attrs: MakeNVAttributes(AttrNVOwnerWrite|AttrNVGlobalLock|AttrNVOwnerRead,
					NVTypeOrdinary),
				Size: 8,
			},
		} {
			if err := tpm.NVDefineSpace(HandleOwner, nil, &data, auth); err != nil {
				t.Fatalf("NVDefineSpace failed: %v", err)
			}
			rc, err := tpm.WrapHandle(data.Index)
			if err != nil {
				t.Fatalf("WrapHandle failed: %v", err)
			}
			defer undefineNVSpace(t, tpm, rc, HandleOwner, auth)
			rcs = append(rcs, rc)
		}

		if err := tpm.NVGlobalWriteLock(HandleOwner, auth); err != nil {
			t.Fatalf("NVGlobalWriteLock failed: %v", err)
		}

		for _, rc := range rcs {
			pub, name, err := tpm.NVReadPublic(rc)
			if err != nil {
				t.Fatalf("NVReadPublic failed: %v", err)
			}

			if pub.Attrs&AttrNVGlobalLock > 0 && pub.Attrs&AttrNVWriteLocked == 0 {
				t.Errorf("NV index with TPMA_NV_GLOBALLOCK set wasn't write locked")
			} else if pub.Attrs&AttrNVGlobalLock == 0 && pub.Attrs&AttrNVWriteLocked > 0 {
				t.Errorf("NV index without TPMA_NV_GLOBALLOCK set was write locked")
			}
			if !bytes.Equal(name, rc.Name()) {
				t.Errorf("Name of NV resource context should have been refreshed")
			}
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})
	t.Run("RequirePWAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)
		run(t, testAuth)
	})
	t.Run("RequireSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: dummyAuth}
		run(t, &session)
	})
}
