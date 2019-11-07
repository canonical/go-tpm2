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
			if rc.Handle() != HandleUnassigned {
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
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteAll|AttrNVAuthRead, NVTypeOrdinary),
			Size:    64}
		run(t, nil, &pub, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteAll|AttrNVAuthRead|AttrNVOwnerRead, NVTypeOrdinary),
			Size:    32}
		run(t, nil, &pub, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth}

		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteAll|AttrNVAuthRead|AttrNVOwnerRead, NVTypeOrdinary),
			Size:    64}
		run(t, nil, &pub, &session)
	})
	t.Run("DefineWithAuthValue", func(t *testing.T) {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA1,
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

func TestNVUndefineSpaceSpecial(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	h := sha256.New()
	h.Write(make([]byte, 32))
	binary.Write(h, binary.BigEndian, CommandPolicyAuthValue)

	authPolicy := h.Sum(nil)

	h = sha256.New()
	h.Write(authPolicy)
	binary.Write(h, binary.BigEndian, CommandPolicyCommandCode)
	binary.Write(h, binary.BigEndian, CommandNVUndefineSpaceSpecial)

	authPolicy = h.Sum(nil)

	define := func(t *testing.T) ResourceContext {
		pub := NVPublic{
			Index:      0x0141ffff,
			NameAlg:    HashAlgorithmSHA256,
			Attrs:      MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead|AttrNVPlatformCreate|AttrNVPolicyDelete, NVTypeOrdinary),
			AuthPolicy: authPolicy,
			Size:       8}
		if err := tpm.NVDefineSpace(HandlePlatform, testAuth, &pub, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		context, err := tpm.WrapHandle(pub.Index)
		if err != nil {
			t.Fatalf("WrapHandle failed: %v", err)
		}

		return context
	}

	run := func(t *testing.T, context ResourceContext, platformAuth interface{}) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		if err := tpm.PolicyAuthValue(sessionContext); err != nil {
			t.Errorf("PolicyAuthValue failed: %v", err)
		}
		if err := tpm.PolicyCommandCode(sessionContext, CommandNVUndefineSpaceSpecial); err != nil {
			t.Errorf("PolicyCommandCode failed: %v", err)
		}

		session := Session{Context: sessionContext, AuthValue: testAuth}

		if err := tpm.NVUndefineSpaceSpecial(context, HandlePlatform, &session, platformAuth); err != nil {
			t.Errorf("NVUndefineSpaceSpecial failed: %v", err)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		context := define(t)
		defer verifyNVSpaceUndefined(t, tpm, context, HandlePlatform, nil)
		run(t, context, nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		context := define(t)
		defer verifyNVSpaceUndefined(t, tpm, context, HandlePlatform, nil)
		setHierarchyAuthForTest(t, tpm, HandlePlatform)
		defer resetHierarchyAuth(t, tpm, HandlePlatform)
		run(t, context, testAuth)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		context := define(t)
		defer verifyNVSpaceUndefined(t, tpm, context, HandlePlatform, nil)
		setHierarchyAuthForTest(t, tpm, HandlePlatform)
		defer resetHierarchyAuth(t, tpm, HandlePlatform)

		platformContext, _ := tpm.WrapHandle(HandlePlatform)
		sessionContext, err := tpm.StartAuthSession(nil, platformContext, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, context, &Session{Context: sessionContext})
	})
}

func TestNVWriteZeroSized(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	pub := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
		Size:    0}
	if err := tpm.NVDefineSpace(HandleOwner, nil, &pub, nil); err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	rc, err := tpm.WrapHandle(pub.Index)
	if err != nil {
		t.Fatalf("WrapHandle failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)

	if err := tpm.NVWrite(rc, rc, nil, 0, nil); err != nil {
		t.Fatalf("NVWrite failed: %v", err)
	}

	pub2, name, err := tpm.NVReadPublic(rc)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}

	if pub2.Attrs&AttrNVWritten == 0 {
		t.Errorf("Unexpected attributes")
	}

	if !bytes.Equal(name, rc.Name()) {
		t.Errorf("Name of NV resource context should have been refreshed")
	}
}

func TestNVReadAndWrite(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	pub1 := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
		Size:    64}
	pub2 := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
		Size:    1600}

	define := func(t *testing.T, pub *NVPublic, authValue Auth) ResourceContext {
		if err := tpm.NVDefineSpace(HandleOwner, authValue, pub, nil); err != nil {
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

	runRead := func(t *testing.T, rc ResourceContext, pub *NVPublic, data MaxNVBuffer, offset uint16, auth interface{}) {
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
		rc := define(t, &pub1, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		d := make([]byte, pub1.Size)
		rand.Read(d)
		runWrite(t, rc, d, 0, nil)
		runRead(t, rc, &pub1, d, 0, nil)
	})
	t.Run("Partial", func(t *testing.T) {
		rc := define(t, &pub1, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		d := []byte{1, 2, 3, 4}
		runWrite(t, rc, d, 10, nil)
		runRead(t, rc, &pub1, d, 10, nil)
	})

	for _, data := range []struct {
		desc string
		pub  *NVPublic
	}{
		{
			desc: "Small",
			pub:  &pub1,
		},
		{
			desc: "Large",
			pub:  &pub2,
		},
	} {
		t.Run(data.desc+"/UsePasswordAuth", func(t *testing.T) {
			rc := define(t, data.pub, testAuth)
			defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
			d := make([]byte, data.pub.Size)
			rand.Read(d)
			runWrite(t, rc, d, 0, testAuth)
			runRead(t, rc, data.pub, d, 0, testAuth)
		})

		t.Run(data.desc+"/UseSessionAuthBound1", func(t *testing.T) {
			rc := define(t, data.pub, testAuth)
			defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
			sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)
			session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth}
			d := make([]byte, data.pub.Size)
			rand.Read(d)
			runWrite(t, rc, d, 0, &session)

			// Writing updates the NV index's attributes which also changes the name. This means that the
			// session is no longer bound to it
			runRead(t, rc, data.pub, d, 0, &session)
		})

		t.Run(data.desc+"/UseSessionAuthBound2", func(t *testing.T) {
			rc := define(t, data.pub, testAuth)
			defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
			sessionContext1, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext1)
			session := Session{Context: sessionContext1, Attrs: AttrContinueSession, AuthValue: testAuth}
			d := make([]byte, data.pub.Size)
			rand.Read(d)
			runWrite(t, rc, d, 0, &session)

			// Writing updates the NV index's attributes which also changes the name. This means that the
			// session is no longer bound to it. Create a new bound session
			sessionContext2, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext2)
			session = Session{Context: sessionContext2, Attrs: AttrContinueSession, AuthValue: testAuth}
			runRead(t, rc, data.pub, d, 0, &session)
		})
	}
}

func TestNVIncrement(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
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
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		session := Session{Context: sessionContext, AuthValue: testAuth}
		run(t, rc, &session)
	})
}

func TestNVReadCounter(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
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

		count1, err := tpm.NVReadCounter(rc, rc, authInc)
		if err != nil {
			t.Fatalf("NVReadCounter failed: %v", err)
		}

		if err := tpm.NVIncrement(rc, rc, authInc); err != nil {
			t.Fatalf("NVIncrement failed: %v", err)
		}

		count2, err := tpm.NVReadCounter(rc, rc, authInc)
		if err != nil {
			t.Fatalf("NVReadCounter failed: %v", err)
		}

		if count2-count1 != 1 {
			t.Errorf("Unexpected count values (%d and %d)", count1, count2)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		session := Session{Context: sessionContext, AuthValue: testAuth, Attrs: AttrContinueSession}
		run(t, rc, &session)
	})
}

func TestNVExtend(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
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
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, []byte("bar"), testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256, nil)
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
			NameAlg: HashAlgorithmSHA256,
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
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, []uint64{0x2, 0xf2610ea91007d0}, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256, nil)
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
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVWriteDefine|AttrNVAuthRead, NVTypeOrdinary),
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
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		session := Session{Context: sessionContext, AuthValue: testAuth}
		run(t, rc, &session)
	})
}

func TestNVReadLock(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead|AttrNVReadStClear, NVTypeOrdinary),
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
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		run(t, rc, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		session := Session{Context: sessionContext, AuthValue: testAuth}
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
				NameAlg: HashAlgorithmSHA256,
				Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
				Size:    8,
			},
			{
				Index:   Handle(0x0181ffe0),
				NameAlg: HashAlgorithmSHA256,
				Attrs: MakeNVAttributes(AttrNVAuthWrite|AttrNVGlobalLock|AttrNVAuthRead,
					NVTypeOrdinary),
				Size: 8,
			},
			{
				Index:   Handle(0x0181ffff),
				NameAlg: HashAlgorithmSHA256,
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
	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)
		run(t, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		session := Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth}
		run(t, &session)
	})
}

func TestNVChangeAuth(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	executePolicy := func(context ResourceContext) {
		if err := tpm.PolicyCommandCode(context, CommandNVChangeAuth); err != nil {
			t.Fatalf("PolicyCommandCode failed: %v", err)
		}
		if err := tpm.PolicyAuthValue(context); err != nil {
			t.Fatalf("PolicyAuthValue failed: %v", err)
		}
	}

	trialSession, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, HashAlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, trialSession)

	executePolicy(trialSession)
	authPolicy, err := tpm.PolicyGetDigest(trialSession)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc   string
		tpmKey ResourceContext
	}{
		{
			desc: "Unsalted",
		},
		{
			// This test highlights a bug where we didn't preserve the value of
			// Session.includeAuthValue (which should be true) before computing the response HMAC.
			// It's not caught by the "Unsalted" test because the lack of session key combined with
			// Session.includeAuthValue incorrectly being false was causing processResponseSessionAuth
			// to bail out early
			desc:   "Salted",
			tpmKey: primary,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pub := NVPublic{
				Index:      Handle(0x0181ffff),
				NameAlg:    HashAlgorithmSHA256,
				Attrs:      MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
				AuthPolicy: authPolicy,
				Size:       8}
			if err := tpm.NVDefineSpace(HandleOwner, nil, &pub, nil); err != nil {
				t.Fatalf("NVDefineSpace failed: %v", err)
			}
			rc, err := tpm.WrapHandle(pub.Index)
			if err != nil {
				t.Fatalf("WrapHandle failed: %v", err)
			}
			defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)

			sessionContext, err := tpm.StartAuthSession(data.tpmKey, nil, SessionTypePolicy, nil, HashAlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			executePolicy(sessionContext)

			session := Session{Context: sessionContext, Attrs: AttrContinueSession}
			if err := tpm.NVChangeAuth(rc, testAuth, &session); err != nil {
				t.Fatalf("NVChangeAuth failed: %v", err)
			}

			if err := tpm.NVWrite(rc, rc, make([]byte, 8), 0, testAuth); err != nil {
				t.Errorf("NVWrite failed: %v", err)
			}

			executePolicy(sessionContext)

			session.AuthValue = testAuth
			if err := tpm.NVChangeAuth(rc, nil, &session); err != nil {
				t.Errorf("NVChangeAuth failed: %v", err)
			}
		})
	}
}
