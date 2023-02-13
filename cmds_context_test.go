// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"
)

type contextSuiteBase struct {
	testutil.TPMTest
}

type testEvictControlData struct {
	auth            ResourceContext
	handle          Handle
	authAuthSession SessionContext
}

func (s *contextSuiteBase) testEvictControl(c *C, data *testEvictControlData) {
	sessionHandle := authSessionHandle(data.authAuthSession)

	object := s.CreatePrimary(c, data.auth.Handle(), testutil.NewRSAStorageKeyTemplate())

	persist, err := s.TPM.EvictControl(data.auth, object, data.handle, data.authAuthSession)
	c.Assert(err, IsNil)
	c.Check(persist.Handle(), Equals, data.handle)
	c.Check(persist.Name(), DeepEquals, object.Name())

	c.Check(persist, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(persist.(*ObjectContext).GetPublic(), DeepEquals, object.(*ObjectContext).GetPublic())

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

	pub, name, _, err := s.TPM.ReadPublic(persist)
	c.Assert(err, IsNil)
	c.Check(pub, DeepEquals, object.(*ObjectContext).GetPublic())
	c.Check(name, DeepEquals, object.Name())

	persist2, err := s.TPM.EvictControl(data.auth, persist, data.handle, nil)
	c.Check(err, IsNil)
	c.Check(persist2, IsNil)

	c.Check(persist.Handle(), Equals, HandleUnassigned)

	// XXX: Make ReadPublic work with HandleContext and use that directly here
	_, err = s.TPM.NewResourceContext(data.handle)
	c.Check(err, DeepEquals, ResourceUnavailableError{data.handle})
}

type contextSuite struct {
	contextSuiteBase
}

func (s *contextSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&contextSuite{})

type contextSuitePlatform struct {
	contextSuiteBase
}

func (s *contextSuitePlatform) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeaturePlatformHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&contextSuitePlatform{})

func (s *contextSuite) TestContextSaveTransient(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)

	context, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)
	c.Check(context.SavedHandle, Equals, Handle(0x80000000))
	c.Check(context.Hierarchy, Equals, HandleOwner)
	c.Check(context.Blob, NotNil)

	context2, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)
	c.Check(context2.Sequence, internal_testutil.IntGreater, context.Sequence)
}

func (s *contextSuite) TestContextSaveStClear(c *C) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	template := testutil.NewRSAStorageKeyTemplate()
	template.Attrs |= AttrStClear

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	context, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)
	c.Check(context.SavedHandle, Equals, Handle(0x80000002))
	c.Check(context.Hierarchy, Equals, HandleOwner)
	c.Check(context.Blob, NotNil)
}

func (s *contextSuite) TestContextSaveSession(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)

	context, err := s.TPM.ContextSave(session)
	c.Assert(err, IsNil)
	c.Check(context.SavedHandle, Equals, session.Handle())
	c.Check(context.Hierarchy, Equals, HandleNull)
	c.Check(context.Blob, NotNil)

	c.Check(session.(SessionContextInternal).Data(), IsNil)

	handles, err := s.TPM.GetCapabilityHandles(HandleTypeLoadedSession.BaseHandle(), CapabilityMaxProperties)
	c.Assert(err, IsNil)

	c.Check(session.Handle(), Not(internal_testutil.IsOneOf(Equals)), handles)
}

func (s *contextSuite) TestContextSavePartialHandle(c *C) {
	session := NewLimitedHandleContext(0x02000000)

	_, err := s.TPM.ContextSave(session)
	c.Check(err, ErrorMatches, `invalid saveContext argument: unusable limited HandleContext`)
}

func (s *contextSuite) TestContextSaveSavedSession(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)

	_, err := s.TPM.ContextSave(session)
	c.Check(err, IsNil)

	_, err = s.TPM.ContextSave(session)
	c.Check(err, DeepEquals, &TPMWarning{Command: CommandContextSave, Code: WarningReferenceH0})
}

func (s *contextSuite) TestContextSaveAndLoadTransient(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)

	context, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)

	restored, err := s.TPM.ContextLoad(context)
	c.Assert(err, IsNil)

	var sample ResourceContext
	c.Check(restored, Implements, &sample)

	c.Check(restored.Handle().Type(), Equals, HandleTypeTransient)
	c.Check(restored.Handle(), Not(Equals), object.Handle())
	c.Check(restored.Name(), DeepEquals, object.Name())

	c.Assert(restored, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(restored.(*ObjectContext).GetPublic(), DeepEquals, object.(*ObjectContext).GetPublic())

	pub, name, _, err := s.TPM.ReadPublic(restored.(ResourceContext))
	c.Assert(err, IsNil)
	c.Check(pub, DeepEquals, object.(*ObjectContext).GetPublic())
	c.Check(name, DeepEquals, object.Name())
}

func (s *contextSuite) TestContextSaveAndLoadSession(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)

	origData := session.(SessionContextInternal).Data()
	{
		b, err := mu.MarshalToBytes(origData)
		c.Assert(err, IsNil)
		_, err = mu.UnmarshalFromBytes(b, &origData)
		c.Assert(err, IsNil)
	}

	context, err := s.TPM.ContextSave(session)
	c.Assert(err, IsNil)

	restored, err := s.TPM.ContextLoad(context)
	c.Assert(err, IsNil)

	var sample SessionContext
	c.Check(restored, Implements, &sample)

	c.Check(restored.Handle(), Equals, session.Handle())
	c.Check(restored.Name(), DeepEquals, session.Name())

	c.Check(restored, internal_testutil.ConvertibleTo, &SessionContextImpl{})
	c.Check(restored.(SessionContextInternal).Data(), DeepEquals, origData)

	handles, err := s.TPM.GetCapabilityHandles(HandleTypeLoadedSession.BaseHandle(), CapabilityMaxProperties)
	c.Assert(err, IsNil)
	c.Check(session.Handle(), internal_testutil.IsOneOf(Equals), handles)
}

func (s *contextSuite) TestEvictControl(c *C) {
	s.testEvictControl(c, &testEvictControlData{
		auth:   s.TPM.OwnerHandleContext(),
		handle: s.NextAvailableHandle(c, 0x81000000)})
}

func (s *contextSuite) TestEvictControlAuthAuthSession(c *C) {
	s.testEvictControl(c, &testEvictControlData{
		auth:            s.TPM.OwnerHandleContext(),
		handle:          s.NextAvailableHandle(c, 0x81000000),
		authAuthSession: s.StartAuthSession(c, nil, s.TPM.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *contextSuitePlatform) TestEvictControlAuthAuthSession(c *C) {
	s.testEvictControl(c, &testEvictControlData{
		auth:   s.TPM.PlatformHandleContext(),
		handle: s.NextAvailableHandle(c, 0x81800000)})
}

func (s *contextSuite) TestFlushContextTransient(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)
	handle := object.Handle()

	c.Check(s.TPM.FlushContext(object), IsNil)

	c.Check(object.Handle(), Equals, HandleUnassigned)

	// XXX: Make ReadPublic work with HandleContext and use that directly here
	_, err := s.TPM.NewResourceContext(handle)
	c.Check(err, DeepEquals, ResourceUnavailableError{handle})
}

func (s *contextSuite) TestFlushContextSession(c *C) {
	session := s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	handle := session.Handle()

	c.Check(s.TPM.FlushContext(session), IsNil)

	c.Check(session.Handle(), Equals, HandleUnassigned)

	handles, err := s.TPM.GetCapabilityHandles(HandleTypeHMACSession.BaseHandle(), CapabilityMaxProperties)
	c.Assert(err, IsNil)
	c.Check(handle, Not(internal_testutil.IsOneOf(Equals)), handles)
}
