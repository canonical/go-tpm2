// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func TestNVDefineAndUndefineSpace(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	run := func(t *testing.T, auth Auth, publicInfo *NVPublic, ownerAuthSession SessionContext) {
		nvContext, err := tpm.NVDefineSpace(owner, auth, publicInfo, ownerAuthSession)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer func() {
			handle := nvContext.Handle()
			if err := tpm.NVUndefineSpace(owner, nvContext, ownerAuthSession); err != nil {
				t.Errorf("NVUndefineSpace failed: %v", err)
			}
			if nvContext.Handle() != HandleUnassigned {
				t.Errorf("Context should be invalid after NVUndefineSpace")
			}
			_, err := tpm.CreateResourceContextFromTPM(handle)
			if err == nil {
				t.Fatalf("NVUndefineSpace didn't execute properly")
			}
			if !IsResourceUnavailableError(err, handle) {
				t.Errorf("Unexpected error: %v", err)
			}
		}()

		nvPub := nvContext.(*NvIndexContext).GetPublic()

		if nvPub.Index != publicInfo.Index {
			t.Errorf("Unexpected index")
		}
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

		rc, err := tpm.CreateResourceContextFromTPM(publicInfo.Index)
		if err != nil {
			t.Fatalf("CreateResourceContextFromTPM failed: %v", err)
		}
		if !bytes.Equal(rc.Name(), nvContext.Name()) {
			t.Errorf("Unexpected name")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteAll | AttrNVAuthRead),
			Size:    64}
		run(t, nil, &pub, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())

		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteAll | AttrNVAuthRead | AttrNVOwnerRead),
			Size:    32}
		run(t, nil, &pub, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())

		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteAll | AttrNVAuthRead | AttrNVOwnerRead),
			Size:    64}
		run(t, nil, &pub, sessionContext.WithAttrs(AttrContinueSession))
	})
	t.Run("DefineWithAuthValue", func(t *testing.T) {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA1,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
			Size:    32}
		rc, err := tpm.NVDefineSpace(owner, testAuth, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer undefineNVSpace(t, tpm, rc, owner)

		// We shouldn't have to call ResourceContext.SetAuthValue
		if err := tpm.NVWrite(rc, rc, []byte{0}, 0, nil); err != nil {
			t.Errorf("Failed to write to NV index with authValue: %v", err)
		}

		// Try again after calling ResourceContext.SetAuthValue to make sure that NVDefineSpace actually
		// created the index with the specified auth value.
		rc.SetAuthValue(testAuth)
		if err := tpm.NVWrite(rc, rc, []byte{0}, 0, nil); err != nil {
			t.Errorf("Failed to write to NV index with authValue: %v", err)
		}
	})
}

func TestNVUndefineSpaceSpecial(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeaturePlatformHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	trial, _ := ComputeAuthPolicy(HashAlgorithmSHA256)
	trial.PolicyAuthValue()
	trial.PolicyCommandCode(CommandNVUndefineSpaceSpecial)
	authPolicy := trial.GetDigest()

	platform := tpm.PlatformHandleContext()

	define := func(t *testing.T) ResourceContext {
		pub := NVPublic{
			Index:      0x0141ffff,
			NameAlg:    HashAlgorithmSHA256,
			Attrs:      NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVPlatformCreate | AttrNVPolicyDelete | AttrNVNoDA),
			AuthPolicy: authPolicy,
			Size:       8}
		context, err := tpm.NVDefineSpace(platform, testAuth, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		return context
	}

	run := func(t *testing.T, context ResourceContext, platformAuthSession SessionContext) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
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

		if err := tpm.NVUndefineSpaceSpecial(context, platform, sessionContext, platformAuthSession); err != nil {
			t.Errorf("NVUndefineSpaceSpecial failed: %v", err)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		context := define(t)
		run(t, context, nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		context := define(t)
		setHierarchyAuthForTest(t, tpm, tpm.PlatformHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.PlatformHandleContext())
		run(t, context, nil)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		context := define(t)
		setHierarchyAuthForTest(t, tpm, tpm.PlatformHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.PlatformHandleContext())

		sessionContext, err := tpm.StartAuthSession(nil, platform, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, context, sessionContext)
	})

	t.Run("MissingPolicySession", func(t *testing.T) {
		context := define(t)
		err := tpm.NVUndefineSpaceSpecial(context, platform, nil, nil)
		if !IsTPMError(err, ErrorAuthType, CommandNVUndefineSpaceSpecial) {
			t.Errorf("Unexpected error: %v", err)
		}
		run(t, context, nil)
	})
}

func TestNVWriteZeroSized(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	pub := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    0}
	rc, err := tpm.NVDefineSpace(owner, nil, &pub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, rc, owner)

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
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	pub1 := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    64}
	pub2 := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    1600}

	define := func(t *testing.T, pub *NVPublic, authValue Auth) ResourceContext {
		rc, err := tpm.NVDefineSpace(owner, authValue, pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		return rc
	}

	runWrite := func(t *testing.T, rc ResourceContext, data []byte, offset uint16, authSession SessionContext) {
		if err := tpm.NVWrite(rc, rc, data, offset, authSession); err != nil {
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

	runRead := func(t *testing.T, rc ResourceContext, pub *NVPublic, data []byte, offset uint16, authSession SessionContext) {
		d, err := tpm.NVRead(rc, rc, uint16(len(data)), offset, authSession)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}

		if !bytes.Equal(d, data) {
			t.Errorf("Unexpected data read back")
		}

		d, err = tpm.NVRead(rc, rc, pub.Size, 0, authSession)
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
		defer undefineNVSpace(t, tpm, rc, owner)
		d := make([]byte, pub1.Size)
		rand.Read(d)
		runWrite(t, rc, d, 0, nil)
		runRead(t, rc, &pub1, d, 0, nil)
	})
	t.Run("Partial", func(t *testing.T) {
		rc := define(t, &pub1, nil)
		defer undefineNVSpace(t, tpm, rc, owner)
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
			defer undefineNVSpace(t, tpm, rc, owner)
			d := make([]byte, data.pub.Size)
			rand.Read(d)
			runWrite(t, rc, d, 0, nil)
			runRead(t, rc, data.pub, d, 0, nil)
		})

		t.Run(data.desc+"/UseSessionAuthBound1", func(t *testing.T) {
			rc := define(t, data.pub, testAuth)
			defer undefineNVSpace(t, tpm, rc, owner)
			sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)
			sessionContext.SetAttrs(AttrContinueSession)
			d := make([]byte, data.pub.Size)
			rand.Read(d)
			runWrite(t, rc, d, 0, sessionContext)

			// Writing updates the NV index's attributes which also changes the name. This means that the
			// session is no longer bound to it
			runRead(t, rc, data.pub, d, 0, sessionContext)
		})

		t.Run(data.desc+"/UseSessionAuthBound2", func(t *testing.T) {
			rc := define(t, data.pub, testAuth)
			defer undefineNVSpace(t, tpm, rc, owner)
			sessionContext1, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext1)
			d := make([]byte, data.pub.Size)
			rand.Read(d)
			runWrite(t, rc, d, 0, sessionContext1.WithAttrs(AttrContinueSession))

			// Writing updates the NV index's attributes which also changes the name. This means that the
			// session is no longer bound to it. Create a new bound session
			sessionContext2, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext2)
			runRead(t, rc, data.pub, d, 0, sessionContext2.WithAttrs(AttrContinueSession))
		})
	}
}

func TestNVIncrement(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeCounter.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
			Size:    8}

		rc, err := tpm.NVDefineSpace(owner, authValue, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, authSession SessionContext) {
		if err := tpm.NVIncrement(rc, rc, authSession); err != nil {
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
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, rc, sessionContext)
	})
}

func TestNVReadCounter(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeCounter.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
			Size:    8}

		rc, err := tpm.NVDefineSpace(owner, authValue, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, authSession SessionContext) {
		if err := tpm.NVIncrement(rc, rc, authSession); err != nil {
			t.Fatalf("NVIncrement failed: %v", err)
		}

		count1, err := tpm.NVReadCounter(rc, rc, authSession)
		if err != nil {
			t.Fatalf("NVReadCounter failed: %v", err)
		}

		if err := tpm.NVIncrement(rc, rc, authSession); err != nil {
			t.Fatalf("NVIncrement failed: %v", err)
		}

		count2, err := tpm.NVReadCounter(rc, rc, authSession)
		if err != nil {
			t.Fatalf("NVReadCounter failed: %v", err)
		}

		if count2-count1 != 1 {
			t.Errorf("Unexpected count values (%d and %d)", count1, count2)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		run(t, rc, sessionContext.WithAttrs(AttrContinueSession))
	})
}

func TestNVExtend(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeExtend.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
			Size:    32}

		rc, err := tpm.NVDefineSpace(owner, authValue, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, data []byte, authSession SessionContext) {
		h := sha256.New()
		h.Write(data)
		dataH := h.Sum(nil)

		if err := tpm.NVExtend(rc, rc, dataH, authSession); err != nil {
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

		d, err := tpm.NVRead(rc, rc, 32, 0, nil)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}

		if !bytes.Equal(d, h.Sum(nil)) {
			t.Errorf("Unexpected data returned from NV index")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, []byte("foo"), nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, []byte("bar"), nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, rc, []byte("foo"), sessionContext)
	})
}

func TestNVSetBits(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181ffff),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeBits.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
			Size:    8}

		rc, err := tpm.NVDefineSpace(owner, authValue, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, bits []uint64, authSession SessionContext) {
		var expected uint64
		for _, b := range bits {
			if err := tpm.NVSetBits(rc, rc, b, authSession); err != nil {
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

		d, err := tpm.NVRead(rc, rc, 8, 0, authSession)
		if err != nil {
			t.Fatalf("NVRead failed: %v", err)
		}

		if binary.BigEndian.Uint64(d) != expected {
			t.Errorf("Unexpected data returned from NV index")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		rc := define(t, nil)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, []uint64{0x1, 0x4000000000000}, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, []uint64{0x2, 0xf2610ea91007d0}, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		run(t, rc, []uint64{0xde45670980, 0x456, 0xe}, sessionContext.WithAttrs(AttrContinueSession))
	})
}

func TestNVWriteLock(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteDefine | AttrNVAuthRead | AttrNVNoDA),
			Size:    8}

		rc, err := tpm.NVDefineSpace(owner, authValue, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, authSession SessionContext) {
		if err := tpm.NVWriteLock(rc, rc, authSession); err != nil {
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
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, rc, sessionContext)
	})
}

func TestNVReadLock(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	define := func(t *testing.T, authValue Auth) ResourceContext {
		pub := NVPublic{
			Index:   Handle(0x0181fff0),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVReadStClear | AttrNVNoDA),
			Size:    8}

		rc, err := tpm.NVDefineSpace(owner, authValue, &pub, nil)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}

		return rc
	}

	run := func(t *testing.T, rc ResourceContext, authSession SessionContext) {
		if err := tpm.NVReadLock(rc, rc, authSession); err != nil {
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
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		run(t, rc, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		rc := define(t, testAuth)
		defer undefineNVSpace(t, tpm, rc, owner)
		sessionContext, err := tpm.StartAuthSession(nil, rc, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, rc, sessionContext)
	})
}

func TestNVGlobalLock(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNVGlobalWriteLock|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	run := func(t *testing.T, authSession SessionContext) {
		var rcs []ResourceContext
		for _, data := range []NVPublic{
			{
				Index:   Handle(0x0181fff0),
				NameAlg: HashAlgorithmSHA256,
				Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead),
				Size:    8,
			},
			{
				Index:   Handle(0x0181ffe0),
				NameAlg: HashAlgorithmSHA256,
				Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVGlobalLock | AttrNVAuthRead),
				Size:    8,
			},
		} {
			rc, err := tpm.NVDefineSpace(owner, nil, &data, nil)
			if err != nil {
				t.Fatalf("NVDefineSpace failed: %v", err)
			}
			defer undefineNVSpace(t, tpm, rc, owner)
			rcs = append(rcs, rc)
		}

		if err := tpm.NVGlobalWriteLock(owner, authSession); err != nil {
			t.Fatalf("NVGlobalWriteLock failed: %v", err)
		}

		for _, rc := range rcs {
			pub, _, err := tpm.NVReadPublic(rc)
			if err != nil {
				t.Fatalf("NVReadPublic failed: %v", err)
			}

			if pub.Attrs&AttrNVGlobalLock > 0 && pub.Attrs&AttrNVWriteLocked == 0 {
				t.Errorf("NV index with TPMA_NV_GLOBALLOCK set wasn't write locked")
			} else if pub.Attrs&AttrNVGlobalLock == 0 && pub.Attrs&AttrNVWriteLocked > 0 {
				t.Errorf("NV index without TPMA_NV_GLOBALLOCK set was write locked")
			}
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())
		run(t, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())
		sessionContext, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, sessionContext)
	})
}

func TestNVChangeAuth(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	executePolicy := func(context SessionContext) {
		if err := tpm.PolicyCommandCode(context, CommandNVChangeAuth); err != nil {
			t.Fatalf("PolicyCommandCode failed: %v", err)
		}
		if err := tpm.PolicyAuthValue(context); err != nil {
			t.Fatalf("PolicyAuthValue failed: %v", err)
		}
	}

	trialSession, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, HashAlgorithmSHA256)
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
				Attrs:      NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
				AuthPolicy: authPolicy,
				Size:       8}
			rc, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &pub, nil)
			if err != nil {
				t.Fatalf("NVDefineSpace failed: %v", err)
			}
			defer undefineNVSpace(t, tpm, rc, tpm.OwnerHandleContext())

			sessionContext, err := tpm.StartAuthSession(data.tpmKey, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			executePolicy(sessionContext)

			sessionContext.SetAttrs(AttrContinueSession)
			if err := tpm.NVChangeAuth(rc, testAuth, sessionContext); err != nil {
				t.Fatalf("NVChangeAuth failed: %v", err)
			}

			// We shouldn't have to call ResourceContext.SetAuthValue
			if err := tpm.NVWrite(rc, rc, make([]byte, 8), 0, nil); err != nil {
				t.Errorf("NVWrite failed: %v", err)
			}

			// Try again after calling ResourceContext.SetAuthValue to make sure that NVChangeAuth actually did change
			// the auth value of the index.
			rc.SetAuthValue(testAuth)
			if err := tpm.NVWrite(rc, rc, make([]byte, 8), 0, nil); err != nil {
				t.Errorf("NVWrite failed: %v", err)
			}

			executePolicy(sessionContext)

			if err := tpm.NVChangeAuth(rc, nil, sessionContext); err != nil {
				t.Errorf("NVChangeAuth failed: %v", err)
			}

			if err := tpm.NVWrite(rc, rc, make([]byte, 8), 0, nil); err != nil {
				t.Errorf("NVWrite failed: %v", err)
			}
			rc.SetAuthValue(nil)
			if err := tpm.NVWrite(rc, rc, make([]byte, 8), 0, nil); err != nil {
				t.Errorf("NVWrite failed: %v", err)
			}
		})
	}
}
