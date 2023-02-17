// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"encoding/binary"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/testutil"
)

type resourcesSuite struct {
	testutil.TPMTest
}

func (s *resourcesSuite) SetUpTest(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
	s.TPMTest.SetUpTest(c)
}

var _ = Suite(&resourcesSuite{})

type testNewObjectResourceContextFromTPMData struct {
	handle Handle
	public *Public
	name   Name
}

func (s *resourcesSuite) testNewObjectResourceContextFromTPM(c *C, data *testNewObjectResourceContextFromTPMData) {
	rc, err := s.TPM.NewResourceContext(data.handle)
	c.Assert(err, IsNil)
	c.Assert(rc, NotNil)
	c.Check(rc.Handle(), Equals, data.handle)
	c.Check(rc.Name(), DeepEquals, data.name)
	c.Assert(rc, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(rc.(*ObjectContext).GetPublic(), DeepEquals, data.public)
}

func (s *resourcesSuite) TestNewResourceContextTransient(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	s.testNewObjectResourceContextFromTPM(c, &testNewObjectResourceContextFromTPMData{
		handle: rc.Handle(),
		public: rc.(*ObjectContext).GetPublic(),
		name:   rc.Name()})
}

func (s *resourcesSuite) TestNewResourceContextPersistent(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	rc = s.EvictControl(c, HandleOwner, rc, s.NextAvailableHandle(c, 0x81000008))
	s.testNewObjectResourceContextFromTPM(c, &testNewObjectResourceContextFromTPMData{
		handle: rc.Handle(),
		public: rc.(*ObjectContext).GetPublic(),
		name:   rc.Name()})
}

func (s *resourcesSuite) TestNewResourceContextNV(c *C) {
	pub := NVPublic{
		Index:   s.NextAvailableHandle(c, 0x018100ff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthRead | AttrNVAuthWrite),
		Size:    8}
	rc := s.NVDefineSpace(c, HandleOwner, nil, &pub)

	rc2, err := s.TPM.NewResourceContext(rc.Handle())
	c.Assert(err, IsNil)
	c.Assert(rc, NotNil)
	c.Check(rc2.Handle(), Equals, rc.Handle())
	c.Check(rc2.Name(), DeepEquals, rc.Name())
	c.Assert(rc, internal_testutil.ConvertibleTo, &NvIndexContext{})

	c.Check(rc2.(*NvIndexContext).GetPublic(), testutil.TPMValueDeepEquals, &pub)
}

func (s *resourcesSuite) testNewResourceContextUnavailable(c *C, handle Handle) {
	rc, err := s.TPM.NewResourceContext(handle)
	c.Check(rc, IsNil)
	c.Check(err, DeepEquals, ResourceUnavailableError{handle})
}

func (s *resourcesSuite) TestNewResourceContextUnavailableTransient(c *C) {
	s.testNewResourceContextUnavailable(c, 0x80000000)
}

func (s *resourcesSuite) TestNewResourceContextUnavailablePersistent(c *C) {
	s.testNewResourceContextUnavailable(c, 0x8100ff00)
}

func (s *resourcesSuite) TestNewResourceContextUnavailableNV(c *C) {
	s.testNewResourceContextUnavailable(c, 0x018100ff)
}

func (s *resourcesSuite) TestNewResourceContextPanicsForWrongType(c *C) {
	c.Check(func() { s.TPM.NewResourceContext(HandleOwner) }, PanicMatches, "invalid handle type")
}

func (s *resourcesSuite) testNewLimitedHandleContext(c *C, handle Handle) {
	hc := NewLimitedHandleContext(handle)
	c.Assert(hc, NotNil)
	c.Check(hc.Handle(), Equals, handle)

	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	c.Check(hc.Name(), DeepEquals, name)
}

func (s *resourcesSuite) TestNewLimitedHandleContextSession(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	s.testNewLimitedHandleContext(c, session.Handle())
}

func (s *resourcesSuite) TestNewLimitedHandleContextTransient(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	s.testNewLimitedHandleContext(c, rc.Handle())
}

func (s *resourcesSuite) TestNewLimitedHandleContextForWrongType(c *C) {
	c.Check(func() { NewLimitedHandleContext(0x00000000) }, PanicMatches, "invalid handle type")
}

func (s *resourcesSuite) testNewLimitedResourceContext(c *C, handle Handle, name Name) {
	rc := NewLimitedResourceContext(handle, name)
	c.Assert(rc, NotNil)
	c.Check(rc.Handle(), Equals, handle)
	c.Check(rc.Name(), DeepEquals, name)
}

func (s *resourcesSuite) TestNewLimitedResourceContextTransient(c *C) {
	s.testNewLimitedResourceContext(c, 0x80000001, internal_testutil.DecodeHexString(c, "000b000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
}

func (s *resourcesSuite) TestNewLimitedResourceContextPersistent(c *C) {
	s.testNewLimitedResourceContext(c, 0x81000002, internal_testutil.DecodeHexString(c, "0004000102030405060708090a0b0c0d0e0f10111213"))
}

type testNewObjectHandleContextFromBytesData struct {
	b      []byte
	handle Handle
	public *Public
	name   Name
}

func (s *resourcesSuite) testNewObjectHandleContextFromBytes(c *C, data *testNewObjectHandleContextFromBytesData) {
	context, n, err := NewHandleContextFromBytes(data.b)
	c.Assert(err, IsNil)
	c.Check(n, Equals, len(data.b))
	c.Assert(context, NotNil)

	c.Check(context.Handle(), Equals, data.handle)
	c.Check(context.Name(), DeepEquals, data.name)
	c.Assert(context, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(context.(*ObjectContext).GetPublic(), DeepEquals, data.public)
}

func (s *resourcesSuite) TestNewHandleContextFromBytesTransient(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	s.testNewObjectHandleContextFromBytes(c, &testNewObjectHandleContextFromBytesData{
		b:      rc.SerializeToBytes(),
		handle: rc.Handle(),
		public: rc.(*ObjectContext).GetPublic(),
		name:   rc.Name()})
}

func (s *resourcesSuite) TestNewHandleContextFromBytesPersistent(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	rc = s.EvictControl(c, HandleOwner, rc, s.NextAvailableHandle(c, 0x81000008))
	s.testNewObjectHandleContextFromBytes(c, &testNewObjectHandleContextFromBytesData{
		b:      rc.SerializeToBytes(),
		handle: rc.Handle(),
		public: rc.(*ObjectContext).GetPublic(),
		name:   rc.Name()})
}

func (s *resourcesSuite) TestNewHandleContextFromBytesNV(c *C) {
	pub := NVPublic{
		Index:   s.NextAvailableHandle(c, 0x018100ff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthRead | AttrNVAuthWrite),
		Size:    8}
	rc := s.NVDefineSpace(c, HandleOwner, nil, &pub)
	b := rc.SerializeToBytes()

	rc2, n, err := NewHandleContextFromBytes(b)
	c.Assert(err, IsNil)
	c.Check(n, Equals, len(b))
	c.Assert(rc2, NotNil)

	c.Check(rc2.Handle(), Equals, rc.Handle())
	c.Check(rc2.Name(), DeepEquals, rc.Name())
	c.Assert(rc2, internal_testutil.ConvertibleTo, &NvIndexContext{})

	c.Check(rc2.(*NvIndexContext).GetPublic(), testutil.TPMValueDeepEquals, &pub)
}

func (s *resourcesSuite) TestNewHandleContextFromBytesSession(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	b := session.SerializeToBytes()

	session2, n, err := NewHandleContextFromBytes(b)
	c.Assert(err, IsNil)
	c.Check(n, Equals, len(b))
	c.Assert(session2, NotNil)

	c.Check(session2.Handle(), Equals, session.Handle())
	c.Check(session2.Name(), DeepEquals, session.Name())
	c.Assert(session2, internal_testutil.ConvertibleTo, &SessionContextImpl{})

	c.Check(session2.(SessionContextInternal).Data(), testutil.TPMValueDeepEquals, session.(SessionContextInternal).Data())

	_, err = s.TPM.ContextSave(session)
	c.Check(err, IsNil)
	c.Check(session.(SessionContextInternal).Data(), IsNil)

	b = session.SerializeToBytes()

	session2, n, err = NewHandleContextFromBytes(b)
	c.Assert(err, IsNil)
	c.Check(n, Equals, len(b))
	c.Assert(session2, NotNil)

	c.Check(session2.Handle(), Equals, session.Handle())
	c.Check(session2.Name(), DeepEquals, session.Name())
	c.Assert(session2, internal_testutil.ConvertibleTo, &SessionContextImpl{})

	c.Check(session2.(SessionContextInternal).Data(), IsNil)
}

type testNewResourceContextWithSessionData struct {
	handle Handle
	name   Name
}

func (s *resourcesSuite) testNewResourceContextWithSession(c *C, data *testNewResourceContextWithSessionData) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)

	rc, err := s.TPM.NewResourceContext(data.handle, session.WithAttrs(AttrContinueSession|AttrAudit))
	c.Assert(err, IsNil)
	c.Assert(rc, NotNil)
	c.Check(rc.Handle(), Equals, data.handle)
	c.Check(rc.Name(), DeepEquals, data.name)

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, session.Handle())
}

func (s *resourcesSuite) TestNewResourceContextWithSessionTransient(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	s.testNewResourceContextWithSession(c, &testNewResourceContextWithSessionData{
		handle: rc.Handle(),
		name:   rc.Name()})
}

func (s *resourcesSuite) TestNewResourceContextWithSessionNV(c *C) {
	pub := NVPublic{
		Index:   s.NextAvailableHandle(c, 0x018100ff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthRead | AttrNVAuthWrite),
		Size:    8}
	rc := s.NVDefineSpace(c, HandleOwner, nil, &pub)
	s.testNewResourceContextWithSession(c, &testNewResourceContextWithSessionData{
		handle: rc.Handle(),
		name:   rc.Name()})
}

func (s *resourcesSuite) TestNewNVIndexResourceContextFromPub(c *C) {
	pub := NVPublic{
		Index:   s.NextAvailableHandle(c, 0x018100ff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthRead | AttrNVAuthWrite),
		Size:    8}
	rc, err := NewNVIndexResourceContextFromPub(&pub)
	c.Assert(err, IsNil)
	c.Assert(rc, NotNil)
	c.Check(rc.Handle(), Equals, pub.Index)

	name := pub.Name()

	c.Check(rc.Name(), DeepEquals, name)
	c.Check(rc, internal_testutil.ConvertibleTo, &NvIndexContext{})
	c.Check(rc.(*NvIndexContext).GetPublic(), DeepEquals, &pub)
}

func (s *resourcesSuite) TestNewNVIndexResourceContext(c *C) {
	pub := NVPublic{
		Index:   s.NextAvailableHandle(c, 0x018100ff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthRead | AttrNVAuthWrite),
		Size:    8}
	name, err := pub.ComputeName()
	c.Assert(err, IsNil)

	rc := NewNVIndexResourceContext(&pub, name)
	c.Assert(rc, NotNil)
	c.Check(rc.Handle(), Equals, pub.Index)
	c.Check(rc.Name(), DeepEquals, name)
	c.Check(rc, internal_testutil.ConvertibleTo, &NvIndexContext{})
	c.Check(rc.(*NvIndexContext).GetPublic(), DeepEquals, &pub)
}

func (s *resourcesSuite) TestNewObjectResourceContextFromPub(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)

	pub, _, _, err := s.TPM.ReadPublic(rc)
	c.Assert(err, IsNil)

	rc2, err := NewObjectResourceContextFromPub(rc.Handle(), pub)
	c.Assert(err, IsNil)
	c.Assert(rc2, NotNil)
	c.Check(rc2.Handle(), Equals, rc.Handle())
	c.Check(rc2.Name(), DeepEquals, rc.Name())
	c.Check(rc2, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(rc2.(*ObjectContext).GetPublic(), DeepEquals, pub)
}

func (s *resourcesSuite) TestNewObjectResourceContext(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)

	pub, name, _, err := s.TPM.ReadPublic(rc)
	c.Assert(err, IsNil)

	rc2 := NewObjectResourceContext(rc.Handle(), pub, name)
	c.Assert(rc2, NotNil)
	c.Check(rc2.Handle(), Equals, rc.Handle())
	c.Check(rc2.Name(), DeepEquals, rc.Name())
	c.Check(rc2, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(rc2.(*ObjectContext).GetPublic(), DeepEquals, pub)
}

func (s *resourcesSuite) SessionContextImplSetAttrs(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)

	session.SetAttrs(AttrContinueSession)
	c.Check(session.(SessionContextInternal).Attrs(), Equals, AttrContinueSession)
}

func (s *resourcesSuite) SessionContextImplWithAttrs(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)

	session2 := session.WithAttrs(AttrAudit)
	c.Check(session2.Handle(), Equals, session.Handle())
	c.Check(session2.Name(), DeepEquals, session.Name())
	c.Check(session.(SessionContextInternal).Attrs(), Equals, SessionAttributes(0))
	c.Check(session2.(SessionContextInternal).Attrs(), Equals, AttrAudit)
}

func (s *resourcesSuite) SessionContextImplIncludeAttrs(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	session.SetAttrs(AttrContinueSession)

	session2 := session.IncludeAttrs(AttrResponseEncrypt)
	c.Check(session2.Handle(), Equals, session.Handle())
	c.Check(session2.Name(), DeepEquals, session.Name())
	c.Check(session.(SessionContextInternal).Attrs(), Equals, AttrContinueSession)
	c.Check(session2.(SessionContextInternal).Attrs(), Equals, AttrContinueSession|AttrResponseEncrypt)
}

func (s *resourcesSuite) SessionContextImplExcludeAttrs(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	session.SetAttrs(AttrAudit | AttrContinueSession | AttrCommandEncrypt)

	session2 := session.ExcludeAttrs(AttrAudit)
	c.Check(session2.Handle(), Equals, session.Handle())
	c.Check(session2.Name(), DeepEquals, session.Name())
	c.Check(session.(SessionContextInternal).Attrs(), Equals, AttrAudit|AttrContinueSession|AttrCommandEncrypt)
	c.Check(session2.(SessionContextInternal).Attrs(), Equals, AttrContinueSession|AttrCommandEncrypt)
}

func (s *resourcesSuite) TestResourceContextGetAuth(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	rc.SetAuthValue([]byte("foo"))
	c.Check(rc.(ResourceContextInternal).GetAuthValue(), DeepEquals, []byte("foo"))
}

func (s *resourcesSuite) TestResourceContextGetAuthWithTrailingZeroes(c *C) {
	rc := s.CreateStoragePrimaryKeyRSA(c)
	rc.SetAuthValue([]byte("foo\x00bar\x00\x00"))
	c.Check(rc.(ResourceContextInternal).GetAuthValue(), DeepEquals, []byte("foo\x00bar"))
}
