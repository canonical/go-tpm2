// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto"
	"crypto/rand"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"
)

type nvSuiteBase struct {
	testutil.TPMTest
}

type nvSuite struct {
	nvSuiteBase
}

func (s *nvSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
}

type nvSuitePlatform struct {
	nvSuiteBase
}

func (s *nvSuitePlatform) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeaturePlatformHierarchy | testutil.TPMFeatureNV
}

type nvGlobalLockSuiteBase struct {
	testutil.TPMTest
}

type nvGlobalLockSuite struct {
	nvGlobalLockSuiteBase
}

func (s *nvGlobalLockSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNVGlobalWriteLock | testutil.TPMFeatureNV
}

type nvGlobalLockSuitePlatform struct {
	nvGlobalLockSuiteBase
}

func (s *nvGlobalLockSuitePlatform) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeaturePlatformHierarchy | testutil.TPMFeatureNVGlobalWriteLock | testutil.TPMFeatureNV
}

var _ = Suite(&nvSuite{})
var _ = Suite(&nvSuitePlatform{})
var _ = Suite(&nvGlobalLockSuite{})
var _ = Suite(&nvGlobalLockSuitePlatform{})

type testNVDefineAndUndefineSpaceData struct {
	authContext            ResourceContext
	auth                   Auth
	publicInfo             *NVPublic
	authContextAuthSession SessionContext

	cb func(ResourceContext)
}

func (s *nvSuiteBase) testDefineAndUndefineSpace(c *C, data *testNVDefineAndUndefineSpaceData) {
	sessionHandle := authSessionHandle(data.authContextAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || data.authContextAuthSession.State().NeedsPassword

	index, err := s.TPM.NVDefineSpace(data.authContext, data.auth, data.publicInfo, data.authContextAuthSession)
	c.Assert(err, IsNil)

	c.Check(index.Handle(), Equals, data.publicInfo.Index)

	expectedName := data.publicInfo.Name()
	c.Check(index.Name(), DeepEquals, expectedName)

	var sample NVIndexContext
	c.Assert(index, Implements, &sample)

	c.Assert(index, internal_testutil.ConvertibleTo, &NvIndexContextImpl{})
	c.Check(index.(*NvIndexContextImpl).Public(), testutil.TPMValueDeepEquals, data.publicInfo)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.authContext.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.authContext.AuthValue()))
		}
	}

	pub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(pub, testutil.TPMValueDeepEquals, data.publicInfo)
	c.Check(name, DeepEquals, expectedName)

	if data.cb != nil {
		data.cb(index)
	}

	c.Check(s.TPM.NVUndefineSpace(data.authContext, index, data.authContextAuthSession), IsNil)
	c.Check(index.Handle(), Equals, HandleUnassigned)

	cmd = s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.authContext.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.authContext.AuthValue()))
		}
	}

	c.Check(s.TPM.DoesHandleExist(data.publicInfo.Index), internal_testutil.IsFalse)
}

func (s *nvSuite) TestDefineAndUndefineSpace(c *C) {
	s.testDefineAndUndefineSpace(c, &testNVDefineAndUndefineSpaceData{
		authContext: s.TPM.OwnerHandleContext(),
		publicInfo: &NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteAll | AttrNVAuthRead),
			Size:    64}})
}

func (s *nvSuitePlatform) TestDefineAndUndefineSpaceWithPlatform(c *C) {
	s.testDefineAndUndefineSpace(c, &testNVDefineAndUndefineSpaceData{
		authContext: s.TPM.PlatformHandleContext(),
		publicInfo: &NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0141f000),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteAll | AttrNVAuthRead | AttrNVPlatformCreate),
			Size:    64}})
}

func (s *nvSuite) TestDefineAndUndefineSpaceDifferentPublic(c *C) {
	s.testDefineAndUndefineSpace(c, &testNVDefineAndUndefineSpaceData{
		authContext: s.TPM.OwnerHandleContext(),
		publicInfo: &NVPublic{
			Index:   s.NextAvailableHandle(c, 0x01bff000),
			NameAlg: HashAlgorithmSHA1,
			Attrs:   NVTypeCounter.WithAttrs(AttrNVAuthWrite | AttrNVOwnerRead | AttrNVAuthRead),
			Size:    8}})
}

func (s *nvSuite) TestDefineAndUndefineSpaceWithAuthValue(c *C) {
	auth := []byte("12345678")

	testAuthValue := func(index ResourceContext) {
		// NVDefineSpace should set the auth value on the returned
		// context.
		c.Check(s.TPM.NVWrite(index, index, nil, 0, nil), IsNil)
		cmd := s.LastCommand(c)
		c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
		c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(auth))
	}

	s.testDefineAndUndefineSpace(c, &testNVDefineAndUndefineSpaceData{
		authContext: s.TPM.OwnerHandleContext(),
		auth:        auth,
		publicInfo: &NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
			Size:    64},
		cb: testAuthValue})
}

func (s *nvSuite) TestDefineAndUndefineSpaceWithAuthContextSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("password"))

	s.testDefineAndUndefineSpace(c, &testNVDefineAndUndefineSpaceData{
		authContext: s.TPM.OwnerHandleContext(),
		publicInfo: &NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteAll | AttrNVAuthRead),
			Size:    64},
		authContextAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256).WithAttrs(AttrContinueSession)})
}

func (s *nvSuite) TestDefineAndUndefineSpaceWithAuthContextPW(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("password"))

	s.testDefineAndUndefineSpace(c, &testNVDefineAndUndefineSpaceData{
		authContext: s.TPM.OwnerHandleContext(),
		publicInfo: &NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteAll | AttrNVAuthRead),
			Size:    64}})
}

type testNVUndefineSpaceSpecialData struct {
	skipTest            bool
	platformAuthSession SessionContext
}

func (s *nvSuitePlatform) testUndefineSpaceSpecial(c *C, data *testNVUndefineSpaceSpecialData) ResourceContext {
	trial := util.ComputeAuthPolicy(HashAlgorithmSHA256)
	trial.PolicyAuthValue()
	trial.PolicyCommandCode(CommandNVUndefineSpaceSpecial)

	pub := NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0141f000),
		NameAlg:    HashAlgorithmSHA256,
		Attrs:      NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVPlatformCreate | AttrNVPolicyDelete | AttrNVNoDA),
		AuthPolicy: trial.GetDigest(),
		Size:       8}
	index := s.NVDefineSpace(c, HandlePlatform, nil, &pub)

	if data.skipTest {
		return index
	}

	session := s.StartAuthSession(c, nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
	c.Check(s.TPM.PolicyAuthValue(session), IsNil)
	c.Check(s.TPM.PolicyCommandCode(session, CommandNVUndefineSpaceSpecial), IsNil)

	sessionHandles := []Handle{session.Handle(), authSessionHandle(data.platformAuthSession)}
	sessionHMACIsPW := []bool{
		false,
		sessionHandles[1] == HandlePW || data.platformAuthSession.State().NeedsPassword,
	}

	c.Check(s.TPM.NVUndefineSpaceSpecial(index, s.TPM.PlatformHandleContext(), session, data.platformAuthSession), IsNil)
	c.Check(index.Handle(), Equals, HandleUnassigned)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 2)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandles[0])
	c.Check(cmd.CmdAuthArea[1].SessionHandle, Equals, sessionHandles[1])
	if sessionHMACIsPW[1] {
		if len(s.TPM.PlatformHandleContext().AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[1].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[1].HMAC, DeepEquals, Auth(s.TPM.PlatformHandleContext().AuthValue()))
		}
	}

	c.Check(s.TPM.DoesHandleExist(pub.Index), internal_testutil.IsFalse)

	return nil
}

func (s *nvSuitePlatform) TestUndefineSpaceSpecial(c *C) {
	s.testUndefineSpaceSpecial(c, &testNVUndefineSpaceSpecialData{})
}

func (s *nvSuitePlatform) TestUndefineSpaceSpecialWithPlatformAuthSession(c *C) {
	s.HierarchyChangeAuth(c, HandlePlatform, []byte("password"))
	s.testUndefineSpaceSpecial(c, &testNVUndefineSpaceSpecialData{
		platformAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *nvSuitePlatform) TestUndefineSpaceSpecialWithPlatformPWSession(c *C) {
	s.HierarchyChangeAuth(c, HandlePlatform, []byte("password"))
	s.testUndefineSpaceSpecial(c, &testNVUndefineSpaceSpecialData{})
}

func (s *nvSuitePlatform) TestUndefineSpaceSpecialMissingSession(c *C) {
	index := s.testUndefineSpaceSpecial(c, &testNVUndefineSpaceSpecialData{skipTest: true})
	c.Check(s.TPM.NVUndefineSpaceSpecial(index, s.TPM.PlatformHandleContext(), nil, nil), DeepEquals,
		&TPMError{Command: CommandNVUndefineSpaceSpecial, Code: ErrorAuthType})

	session := s.StartAuthSession(c, nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
	c.Check(s.TPM.PolicyAuthValue(session), IsNil)
	c.Check(s.TPM.PolicyCommandCode(session, CommandNVUndefineSpaceSpecial), IsNil)
	c.Check(s.TPM.NVUndefineSpaceSpecial(index, s.TPM.PlatformHandleContext(), session, nil), IsNil)
}

func (s *nvSuite) TestWriteZeroSized(c *C) {
	pub := NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    0}
	index := s.NVDefineSpace(c, HandleOwner, nil, &pub)

	c.Check(s.TPM.NVWrite(index, index, nil, 0, nil), IsNil)

	updatedPub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(updatedPub.Attrs&AttrNVWritten, Equals, AttrNVWritten)
	c.Check(index.Name(), DeepEquals, name)
}

type testNVWriteAndReadData struct {
	auth Auth
	size uint16

	writeData   []byte
	writeOffset uint16

	authSession SessionContext

	readSize   uint16
	readOffset uint16
	expected   []byte
}

func (s *nvSuite) testWriteAndRead(c *C, data *testNVWriteAndReadData) {
	sessionHandle := authSessionHandle(data.authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || data.authSession.State().NeedsPassword

	pub := &NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    data.size}
	index := s.NVDefineSpace(c, HandleOwner, data.auth, pub)

	c.Check(s.TPM.NVWrite(index, index, data.writeData, data.writeOffset, data.authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, data.auth)
		}
	}

	pub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(pub.Attrs&AttrNVWritten, Equals, AttrNVWritten)
	c.Check(index.(*NvIndexContextImpl).Public(), DeepEquals, pub)
	c.Check(index.Name(), DeepEquals, name)

	b, err := s.TPM.NVRead(index, index, data.readSize, data.readOffset, data.authSession)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, data.expected)

	cmd = s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, data.auth)
		}
	}
}

func (s *nvSuite) TestWriteAndRead(c *C) {
	s.testWriteAndRead(c, &testNVWriteAndReadData{
		size:      8,
		writeData: []byte("zyxwvuts"),
		readSize:  8,
		expected:  []byte("zyxwvuts")})
}

func (s *nvSuite) TestWriteAndReadPartialWrite(c *C) {
	s.testWriteAndRead(c, &testNVWriteAndReadData{
		size:        8,
		writeData:   []byte("abcd"),
		writeOffset: 2,
		readSize:    8,
		expected:    []byte("\xff\xffabcd\xff\xff")})
}

func (s *nvSuite) TestWriteAndReadPartialRead(c *C) {
	s.testWriteAndRead(c, &testNVWriteAndReadData{
		size:       8,
		writeData:  []byte("zyxwvuts"),
		readSize:   5,
		readOffset: 3,
		expected:   []byte("wvuts")})
}

func (s *nvSuite) TestWriteAndReadWithAuthSession(c *C) {
	s.testWriteAndRead(c, &testNVWriteAndReadData{
		auth:        []byte("12345678"),
		size:        8,
		writeData:   []byte("zyxwvuts"),
		authSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256).WithAttrs(AttrContinueSession),
		readSize:    8,
		expected:    []byte("zyxwvuts")})
}

func (s *nvSuite) TestWriteAndReadWithPWSession(c *C) {
	s.testWriteAndRead(c, &testNVWriteAndReadData{
		auth:      []byte("12345678"),
		size:      8,
		writeData: []byte("zyxwvuts"),
		readSize:  8,
		expected:  []byte("zyxwvuts")})
}

func (s *nvSuite) TestWriteAndReadLargerThanNVBufferMax(c *C) {
	bufferMax, err := s.TPM.GetNVBufferMax()
	c.Check(err, IsNil)

	indexMax, err := s.TPM.GetNVIndexMax()
	c.Check(err, IsNil)

	if indexMax <= bufferMax {
		c.Skip("TPM_PT_NV_INDEX_MAX not larger than TPM_PT_NV_BUFFER_MAX")
	}

	data := make([]byte, indexMax)
	rand.Read(data)

	s.testWriteAndRead(c, &testNVWriteAndReadData{
		size:      uint16(indexMax),
		writeData: data,
		readSize:  uint16(indexMax),
		expected:  data})
}

func (s *nvSuite) testIncrementAndRead(c *C, auth Auth, authSession SessionContext) {
	sessionHandle := authSessionHandle(authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || authSession.State().NeedsPassword

	s.RequireCommand(c, CommandNVIncrement)

	pub := &NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeCounter.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    8}
	index := s.NVDefineSpace(c, HandleOwner, auth, pub)

	c.Check(s.TPM.NVIncrement(index, index, authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, auth)
		}
	}

	pub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(pub.Attrs&AttrNVWritten, Equals, AttrNVWritten)
	c.Check(index.(*NvIndexContextImpl).Public(), DeepEquals, pub)
	c.Check(index.Name(), DeepEquals, name)

	initialValue, err := s.TPM.NVReadCounter(index, index, authSession)
	c.Check(err, IsNil)

	cmd = s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, auth)
		}
	}

	c.Check(s.TPM.NVIncrement(index, index, authSession), IsNil)
	value, err := s.TPM.NVReadCounter(index, index, authSession)
	c.Check(err, IsNil)
	c.Check(value, Equals, initialValue+1)
}

func (s *nvSuite) TestIncrementAndRead(c *C) {
	s.testIncrementAndRead(c, nil, nil)
}

func (s *nvSuite) TestIncrementAndReadWithAuthSession(c *C) {
	s.testIncrementAndRead(c, []byte("1234"), s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256).WithAttrs(AttrContinueSession))
}

func (s *nvSuite) TestIncrementAndReadWithPWSession(c *C) {
	s.testIncrementAndRead(c, []byte("5678"), nil)
}

type testNVExtendData struct {
	auth        Auth
	data        []byte
	authSession SessionContext
}

func (s *nvSuite) testExtend(c *C, data *testNVExtendData) {
	s.RequireCommand(c, CommandNVExtend)

	sessionHandle := authSessionHandle(data.authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || data.authSession.State().NeedsPassword

	pub := &NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeExtend.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    32}
	index := s.NVDefineSpace(c, HandleOwner, data.auth, pub)

	c.Check(s.TPM.NVExtend(index, index, data.data, data.authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, data.auth)
		}
	}

	pub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(pub.Attrs&AttrNVWritten, Equals, AttrNVWritten)
	c.Check(index.(*NvIndexContextImpl).Public(), DeepEquals, pub)
	c.Check(index.Name(), DeepEquals, name)

	h := crypto.SHA256.New()
	h.Write(make([]byte, 32))
	h.Write(data.data)

	value, err := s.TPM.NVRead(index, index, 32, 0, nil)
	c.Check(err, IsNil)
	c.Check(value, DeepEquals, h.Sum(nil))
}

func (s *nvSuite) TestExtend(c *C) {
	s.testExtend(c, &testNVExtendData{data: []byte("foo")})
}

func (s *nvSuite) TestExtendDifferentData(c *C) {
	s.testExtend(c, &testNVExtendData{data: []byte("bar")})
}

func (s *nvSuite) TestExtendWithAuthSession(c *C) {
	s.testExtend(c, &testNVExtendData{
		auth:        []byte("password"),
		data:        []byte("foo"),
		authSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *nvSuite) TestExtendWithPWSession(c *C) {
	s.testExtend(c, &testNVExtendData{
		auth: []byte("12345678"),
		data: []byte("foo")})
}

type testNVSetBitsAndReadData struct {
	auth        Auth
	bits        []uint64
	authSession SessionContext
}

func (s *nvSuite) testSetBitsAndRead(c *C, data *testNVSetBitsAndReadData) {
	s.RequireCommand(c, CommandNVSetBits)

	sessionHandle := authSessionHandle(data.authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || data.authSession.State().NeedsPassword

	pub := &NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeBits.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		Size:    8}
	index := s.NVDefineSpace(c, HandleOwner, data.auth, pub)

	var expected uint64
	for _, b := range data.bits {
		c.Check(s.TPM.NVSetBits(index, index, b, data.authSession), IsNil)
		expected |= b
	}

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, data.auth)
		}
	}

	pub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(pub.Attrs&AttrNVWritten, Equals, AttrNVWritten)
	c.Check(index.(*NvIndexContextImpl).Public(), DeepEquals, pub)
	c.Check(index.Name(), DeepEquals, name)

	value, err := s.TPM.NVReadBits(index, index, data.authSession)
	c.Check(err, IsNil)
	c.Check(value, Equals, expected)

	cmd = s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, data.auth)
		}
	}
}

func (s *nvSuite) TestSetBitsAndRead(c *C) {
	s.testSetBitsAndRead(c, &testNVSetBitsAndReadData{
		bits: []uint64{0x3a293e8e64736c75, 0xe89dc5bfff5bad0f}})
}

func (s *nvSuite) TestSetBitsAndReadWithAuthSession(c *C) {
	s.testSetBitsAndRead(c, &testNVSetBitsAndReadData{
		auth:        []byte("password"),
		bits:        []uint64{0x3a293e8e64736c75, 0xe89dc5bfff5bad0f, 0x0f77ffc72a0d78e1},
		authSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256).WithAttrs(AttrContinueSession)})
}

func (s *nvSuite) TestSetBitsAndReadWithPWSession(c *C) {
	s.testSetBitsAndRead(c, &testNVSetBitsAndReadData{
		auth: []byte("87654321"),
		bits: []uint64{0x3a293e8e64736c75, 0xe89dc5bfff5bad0f, 0x0f77ffc72a0d78e1}})
}

func (s *nvSuite) testWriteLock(c *C, auth Auth, authSession SessionContext) {
	sessionHandle := authSessionHandle(authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || authSession.State().NeedsPassword

	pub := &NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181ff00),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVWriteDefine | AttrNVAuthRead | AttrNVNoDA),
		Size:    8}
	index := s.NVDefineSpace(c, HandleOwner, auth, pub)

	c.Check(s.TPM.NVWriteLock(index, index, authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, auth)
		}
	}

	pub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(pub.Attrs&AttrNVWriteLocked, Equals, AttrNVWriteLocked)
	c.Check(index.(*NvIndexContextImpl).Public(), DeepEquals, pub)
	c.Check(index.Name(), DeepEquals, name)
}

func (s *nvSuite) TestWriteLock(c *C) {
	s.testWriteLock(c, nil, nil)
}

func (s *nvSuite) TestWriteLockWithAuthSession(c *C) {
	s.testWriteLock(c, []byte("passphrase"), s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256))
}

func (s *nvSuite) TestWriteLockWithPWSession(c *C) {
	s.testWriteLock(c, []byte("12345"), nil)
}

func (s *nvSuite) testReadLock(c *C, auth Auth, authSession SessionContext) {
	sessionHandle := authSessionHandle(authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || authSession.State().NeedsPassword

	pub := &NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181ff00),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVReadStClear | AttrNVNoDA),
		Size:    8}
	index := s.NVDefineSpace(c, HandleOwner, auth, pub)

	c.Check(s.TPM.NVReadLock(index, index, authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(auth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, auth)
		}
	}

	pub, name, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)
	c.Check(pub.Attrs&AttrNVReadLocked, Equals, AttrNVReadLocked)
	c.Check(index.(*NvIndexContextImpl).Public(), DeepEquals, pub)
	c.Check(index.Name(), DeepEquals, name)
}

func (s *nvSuite) TestReadLock(c *C) {
	s.testReadLock(c, nil, nil)
}

func (s *nvSuite) TestReadLockWithAuthSession(c *C) {
	s.testReadLock(c, []byte("12345678"), s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256))
}

func (s *nvSuite) TestReadLockWithPWSession(c *C) {
	s.testReadLock(c, []byte("87654321"), nil)
}

type testNVGlobalWriteLockData struct {
	auth        ResourceContext
	authSession SessionContext
}

func (s *nvGlobalLockSuiteBase) testGlobalWriteLock(c *C, data *testNVGlobalWriteLockData) {
	sessionHandle := authSessionHandle(data.authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || data.authSession.State().NeedsPassword

	var indices []ResourceContext

	for _, pub := range []NVPublic{
		{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead),
			Size:    8,
		},
		{
			Index:   s.NextAvailableHandle(c, 0x0181e000),
			NameAlg: HashAlgorithmSHA256,
			Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVGlobalLock | AttrNVAuthRead),
			Size:    8,
		},
	} {
		indices = append(indices, s.NVDefineSpace(c, HandleOwner, nil, &pub))
	}

	c.Check(s.TPM.NVGlobalWriteLock(data.auth, data.authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.auth.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.auth.AuthValue()))
		}
	}

	for _, index := range indices {
		pub, _, err := s.TPM.NVReadPublic(index)
		c.Assert(err, IsNil)

		if pub.Attrs&AttrNVGlobalLock != 0 {
			c.Check(pub.Attrs&AttrNVWriteLocked, Equals, AttrNVWriteLocked)
		} else {
			c.Check(pub.Attrs&AttrNVWriteLocked, Equals, NVAttributes(0))
		}
	}
}

func (s *nvGlobalLockSuite) TestGlobalWriteLock(c *C) {
	s.testGlobalWriteLock(c, &testNVGlobalWriteLockData{auth: s.TPM.OwnerHandleContext()})
}

func (s *nvGlobalLockSuite) TestGlobalWriteLockWithAuthSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("23456"))
	s.testGlobalWriteLock(c, &testNVGlobalWriteLockData{
		auth:        s.TPM.OwnerHandleContext(),
		authSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *nvGlobalLockSuite) TestGlobalWriteLockWithPWSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("23456"))
	s.testGlobalWriteLock(c, &testNVGlobalWriteLockData{
		auth: s.TPM.OwnerHandleContext()})
}

func (s *nvGlobalLockSuitePlatform) TestGlobalWriteLockPlatform(c *C) {
	s.testGlobalWriteLock(c, &testNVGlobalWriteLockData{auth: s.TPM.PlatformHandleContext()})
}

type testChangeAuthParams struct {
	initialAuth Auth
	newAuth     Auth
	authSession SessionContext
}

func (s *nvSuite) testChangeAuth(c *C, params *testChangeAuthParams) {
	sessionHandle := params.authSession.Handle()
	sessionHMACIsPW := params.authSession.State().NeedsPassword

	trial := util.ComputeAuthPolicy(HashAlgorithmSHA256)
	trial.PolicyAuthValue()
	trial.PolicyCommandCode(CommandNVChangeAuth)

	pub := &NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    HashAlgorithmSHA256,
		Attrs:      NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead | AttrNVNoDA),
		AuthPolicy: trial.GetDigest(),
		Size:       8}
	index := s.NVDefineSpace(c, HandleOwner, params.initialAuth, pub)

	c.Check(s.TPM.PolicyAuthValue(params.authSession), IsNil)
	c.Check(s.TPM.PolicyCommandCode(params.authSession, CommandNVChangeAuth), IsNil)

	c.Check(s.TPM.NVChangeAuth(index, params.newAuth, params.authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(params.initialAuth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, params.initialAuth)
		}
	}

	// NVChangeAuth sets the auth value on index.
	c.Check(s.TPM.NVWrite(index, index, nil, 0, nil), IsNil)

	cmd = s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, HandlePW)
	c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, params.newAuth)
}

func (s *nvSuite) TestChangeAuth(c *C) {
	// It's important that this test is performed with a session that isn't
	// bound to the index that we're using it on. An unbound session appends
	// the auth value to the session key to produce the HMAC key, and the
	// command / response HMAC keys are different because the auth value changes.
	// An unbound session tests the code in NVChangeAuth that updates the auth
	// value on the ResourceContext before processing the response.
	//
	// A session that is bound to the index we're using it on includes the auth
	// value in the session key, and as long as it's still bound when the session
	// is used, the auth value is not appended to the session key for either the
	// command or response HMAC keys.
	s.testChangeAuth(c, &testChangeAuthParams{
		initialAuth: []byte("foo"),
		newAuth:     []byte("bar"),
		authSession: s.StartAuthSession(c, nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256),
	})
}

func (s *nvSuite) TestChangeAuthSalted(c *C) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	// This test highlights a historical bug where we didn't preserve the value of
	// sessionParam.IncludeAuthValue (which should be true) before computing the response HMAC.
	// It wasn't initially caught by the "Unsalted" test because the lack of session key combined
	// with sessionParam.IncludeAuthValue incorrectly being false was causing
	// sessionParam.ProcessResponseAuth to bail out early with success (the HMAC check is optional
	// if the HMAC key is zero length which is the case where IncludeAuthValue is false and there is
	// no session key).
	s.testChangeAuth(c, &testChangeAuthParams{
		initialAuth: []byte("bar"),
		newAuth:     []byte("foo"),
		authSession: s.StartAuthSession(c, primary, nil, SessionTypePolicy, nil, HashAlgorithmSHA256),
	})
}
