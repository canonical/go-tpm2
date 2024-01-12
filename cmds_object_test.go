// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"
)

type objectSuite struct {
	testutil.TPMTest
}

func (s *objectSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy
}

func (s *objectSuite) checkPublicAgainstTemplate(c *C, public, template *Public) {
	unique := public.Unique

	var p *Public
	mu.MustCopyValue(&p, public)

	for _, p := range []*Public{template, p} {
		p.Unique = PublicIDUnion{}
		if p.Type == ObjectTypeRSA && p.Params.RSADetail().Exponent == 0 {
			p.Params.RSADetail().Exponent = DefaultRSAExponent
		}
	}

	c.Check(p, testutil.TPMValueDeepEquals, template)

	switch template.Type {
	case ObjectTypeRSA:
		c.Check(unique.RSA(), internal_testutil.LenEquals, int(template.Params.RSADetail().KeyBits)/8)
	case ObjectTypeECC:
		c.Check(unique.ECC().X, internal_testutil.LenEquals, template.Params.ECCDetail().CurveID.GoCurve().Params().BitSize/8)
		c.Check(unique.ECC().Y, internal_testutil.LenEquals, template.Params.ECCDetail().CurveID.GoCurve().Params().BitSize/8)
	}
}

func (s *objectSuite) checkCreationData(c *C, data *CreationData, hash Digest, template *Public, outsideInfo Data, creationPCR PCRSelectionList, parent ResourceContext) {
	var parentQN Name
	if parent.Handle().Type() == HandleTypePermanent {
		parentQN = parent.Name()
	} else {
		var err error
		_, _, parentQN, err = s.TPM.ReadPublic(parent)
		c.Check(err, IsNil)
	}

	_, pcrValues, err := s.TPM.PCRRead(creationPCR)
	c.Assert(err, IsNil)
	pcrDigest, err := policyutil.ComputePCRDigest(template.NameAlg, creationPCR, pcrValues)
	c.Check(err, IsNil)

	c.Check(data, NotNil)
	c.Check(data.PCRSelect, testutil.TPMValueDeepEquals, creationPCR)
	c.Check(data.PCRDigest, DeepEquals, pcrDigest)
	// XXX: Check locality?

	c.Check(data.ParentNameAlg, Equals, AlgorithmId(parent.Name().Algorithm()))
	c.Check(data.ParentName, DeepEquals, parent.Name())
	c.Check(data.ParentQualifiedName, DeepEquals, parentQN)

	c.Check(data.OutsideInfo, DeepEquals, outsideInfo)

	h := template.NameAlg.NewHash()
	mu.MustMarshalToWriter(h, data)
	c.Check(err, IsNil)

	c.Check(hash, DeepEquals, Digest(h.Sum(nil)))
}

func (s *objectSuite) checkCreationTicket(c *C, ticket *TkCreation, hierarchy Handle) {
	c.Check(ticket, NotNil)
	c.Check(ticket.Tag, Equals, TagCreation)

	props, err := s.TPM.GetCapabilityTPMProperties(PropertyContextHash, 1)
	c.Check(err, IsNil)
	c.Assert(props, internal_testutil.LenEquals, 1)
	c.Check(props[0].Property, Equals, PropertyContextHash)

	contextHash := HashAlgorithmId(props[0].Value)
	c.Check(contextHash.IsValid(), internal_testutil.IsTrue)

	c.Check(ticket.Digest, internal_testutil.LenEquals, contextHash.Size())
}

var _ = Suite(&objectSuite{})

type testCreateData struct {
	parent            ResourceContext
	sensitive         *SensitiveCreate
	template          *Public
	outsideInfo       Data
	creationPCR       PCRSelectionList
	parentAuthSession SessionContext

	sensitiveSize int
	hierarchy     Handle
}

func (s *objectSuite) testCreate(c *C, data *testCreateData) (outPrivate Private, outPublic *Public) {
	sessionHandle := authSessionHandle(data.parentAuthSession)

	outPrivate, outPublic, creationData, creationHash, creationTicket, err := s.TPM.Create(data.parent, data.sensitive, data.template, data.outsideInfo, data.creationPCR, data.parentAuthSession)
	c.Assert(err, IsNil)

	authArea := s.LastCommand(c).CmdAuthArea
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

	seedLength := data.template.NameAlg.Size()
	if (data.template.Type == ObjectTypeRSA || data.template.Type == ObjectTypeECC) &&
		(data.template.Attrs&AttrSign != 0 || data.template.Attrs&AttrRestricted == 0) {
		seedLength = 0
	}

	expectedPrivateLength :=
		2 + data.template.NameAlg.Size() + // Outer integrity
			2 + 16 + // Symmetric IV
			2 + // Sensiive size
			2 + // sensitiveType
			2 + data.template.NameAlg.Size() + // authValue
			2 + seedLength + // seedValue
			2 + data.sensitiveSize // sensitive
	c.Check(outPrivate, internal_testutil.LenEquals, expectedPrivateLength)

	s.checkPublicAgainstTemplate(c, outPublic, data.template)
	s.checkCreationData(c, creationData, creationHash, data.template, data.outsideInfo, data.creationPCR, data.parent)
	s.checkCreationTicket(c, creationTicket, data.hierarchy)

	return outPrivate, outPublic
}

func (s *objectSuite) TestCreateRSA(c *C) {
	s.testCreate(c, &testCreateData{
		parent:        s.CreateStoragePrimaryKeyRSA(c),
		template:      objectutil.NewRSAKeyTemplate(objectutil.UsageSign),
		sensitiveSize: 640,
		hierarchy:     HandleOwner})
}

func (s *objectSuite) TestCreateECCRestricted(c *C) {
	s.testCreate(c, &testCreateData{
		parent:        s.CreatePrimary(c, HandleEndorsement, testutil.NewRSAStorageKeyTemplate()),
		template:      objectutil.NewECCAttestationKeyTemplate(),
		sensitiveSize: 32,
		hierarchy:     HandleEndorsement})
}

func (s *objectSuite) TestCreateWithSensitive(c *C) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	userAuth := []byte("1234")
	data := []byte("foo")

	priv, pub := s.testCreate(c, &testCreateData{
		parent:        primary,
		sensitive:     &SensitiveCreate{UserAuth: userAuth, Data: data},
		template:      testutil.NewSealedObjectTemplate(),
		sensitiveSize: 3,
		hierarchy:     HandleOwner})

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	object.SetAuthValue(userAuth)

	recoveredData, err := s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
	c.Check(recoveredData, DeepEquals, SensitiveData(data))
}

func (s *objectSuite) TestCreateWithOutsideInfo(c *C) {
	s.testCreate(c, &testCreateData{
		parent:        s.CreateStoragePrimaryKeyRSA(c),
		template:      objectutil.NewRSAKeyTemplate(objectutil.UsageSign),
		outsideInfo:   []byte("foo"),
		sensitiveSize: 640,
		hierarchy:     HandleOwner})
}

func (s *objectSuite) TestCreateWithCreationPCR(c *C) {
	s.testCreate(c, &testCreateData{
		parent:        s.CreateStoragePrimaryKeyRSA(c),
		template:      objectutil.NewRSAKeyTemplate(objectutil.UsageSign),
		creationPCR:   PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7}}},
		sensitiveSize: 640,
		hierarchy:     HandleOwner})
}

func (s *objectSuite) TestCreateWithParentAuthSession(c *C) {
	s.testCreate(c, &testCreateData{
		parent:            s.CreateStoragePrimaryKeyRSA(c),
		template:          objectutil.NewRSAKeyTemplate(objectutil.UsageSign),
		parentAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		sensitiveSize:     640,
		hierarchy:         HandleOwner})
}

func (s *objectSuite) testLoad(c *C, parentAuthSession SessionContext) {
	sessionHandle := authSessionHandle(parentAuthSession)

	primary := s.CreateStoragePrimaryKeyRSA(c)

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, objectutil.NewRSAKeyTemplate(objectutil.UsageSign), nil, nil, nil)
	c.Assert(err, IsNil)

	expectedName, err := pub.ComputeName()
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, parentAuthSession)
	c.Assert(err, IsNil)

	authArea := s.LastCommand(c).CmdAuthArea
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

	c.Check(object.Handle(), Equals, s.LastCommand(c).RspHandle)
	c.Check(object.Name(), DeepEquals, expectedName)
	c.Assert(object, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(object.(*ObjectContext).GetPublic(), DeepEquals, pub)

	pub2, name, _, err := s.TPM.ReadPublic(object)
	c.Assert(err, IsNil)
	c.Check(pub2, DeepEquals, pub)
	c.Check(name, DeepEquals, expectedName)
}

func (s *objectSuite) TestLoad(c *C) {
	s.testLoad(c, nil)
}

func (s *objectSuite) TestLoadWithParentAuthSession(c *C) {
	s.testLoad(c, s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256))
}

func (s *objectSuite) TestReadPublic(c *C) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	priv, expectedPub, _, _, _, err := s.TPM.Create(primary, nil, objectutil.NewRSAKeyTemplate(objectutil.UsageSign), nil, nil, nil)
	c.Check(err, IsNil)

	object, err := s.TPM.Load(primary, priv, expectedPub, nil)
	c.Assert(err, IsNil)

	pub, name, qn, err := s.TPM.ReadPublic(object)
	c.Check(err, IsNil)
	c.Check(pub, DeepEquals, expectedPub)
	c.Check(name, DeepEquals, object.Name())

	expectedQn, err := objectutil.ComputeQualifiedNameInHierarchy(object, HandleOwner, primary)
	c.Check(err, IsNil)
	c.Check(qn, DeepEquals, expectedQn)
}

type testLoadExternalData struct {
	inPrivate *Sensitive
	inPublic  *Public
	hierarchy Handle
}

func (s *objectSuite) testLoadExternal(c *C, data *testLoadExternalData) ResourceContext {
	object, err := s.TPM.LoadExternal(data.inPrivate, data.inPublic, data.hierarchy)
	c.Assert(err, IsNil)

	authArea := s.LastCommand(c).CmdAuthArea
	c.Check(authArea, internal_testutil.LenEquals, 0)

	expectedName := data.inPublic.Name()

	c.Check(object.Handle(), Equals, s.LastCommand(c).RspHandle)
	c.Check(object.Name(), DeepEquals, expectedName)
	c.Assert(object, internal_testutil.ConvertibleTo, &ObjectContext{})
	c.Check(object.(*ObjectContext).GetPublic(), testutil.TPMValueDeepEquals, data.inPublic)

	pub, name, _, err := s.TPM.ReadPublic(object)
	c.Assert(err, IsNil)
	c.Check(pub, testutil.TPMValueDeepEquals, data.inPublic)
	c.Check(name, DeepEquals, expectedName)

	return object
}

func (s *objectSuite) TestLoadExternalRSAPub(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	pub, err := objectutil.NewRSAPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testLoadExternal(c, &testLoadExternalData{
		inPublic:  pub,
		hierarchy: HandleOwner})
}

func (s *objectSuite) TestLoadExternalECCPub(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pub, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testLoadExternal(c, &testLoadExternalData{
		inPublic:  pub,
		hierarchy: HandleOwner})
}

func (s *objectSuite) TestLoadExternalWithPrivate(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	authValue := []byte("1234")

	public, sensitive := testutil.NewExternalSealedObject(authValue, key)

	object := s.testLoadExternal(c, &testLoadExternalData{
		inPrivate: sensitive,
		inPublic:  public,
		hierarchy: HandleNull})

	// LoadExternal should set the auth value on the returned
	// context.
	unsealedKey, err := s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
	c.Check(unsealedKey, DeepEquals, SensitiveData(key))

	authArea := s.LastCommand(c).CmdAuthArea
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].HMAC, DeepEquals, Auth(authValue))
}

type testUnsealData struct {
	secret          []byte
	authPolicy      Digest
	itemAuthSession SessionContext
}

func (s *objectSuite) testUnseal(c *C, data *testUnsealData) {
	sessionHandle := authSessionHandle(data.itemAuthSession)

	primary := s.CreateStoragePrimaryKeyRSA(c)

	sensitive := SensitiveCreate{Data: data.secret}
	template := testutil.NewSealedObjectTemplate()
	template.AuthPolicy = data.authPolicy
	if len(data.authPolicy) > 0 {
		template.Attrs &^= AttrUserWithAuth
	}

	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, template, nil, nil, nil)
	c.Check(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	unsealedSecret, err := s.TPM.Unseal(object, data.itemAuthSession)
	c.Check(err, IsNil)
	c.Check(unsealedSecret, DeepEquals, SensitiveData(data.secret))

	authArea := s.LastCommand(c).CmdAuthArea
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)
}

func (s *objectSuite) TestUnseal(c *C) {
	s.testUnseal(c, &testUnsealData{
		secret: []byte("sensitive data")})
}

func (s *objectSuite) TestUnsealDifferentSecret(c *C) {
	s.testUnseal(c, &testUnsealData{
		secret: []byte("another super secret")})
}

func (s *objectSuite) TestUnsealWithItemAuthHMACSession(c *C) {
	s.testUnseal(c, &testUnsealData{
		secret:          []byte("sensitive data"),
		itemAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *objectSuite) TestUnsealWithItemAuthPolicySession(c *C) {
	trial := util.ComputeAuthPolicy(HashAlgorithmSHA256)
	trial.PolicyAuthValue()

	session := s.StartAuthSession(c, nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
	c.Check(s.TPM.PolicyAuthValue(session), IsNil)

	s.testUnseal(c, &testUnsealData{
		secret:          []byte("sensitive data"),
		authPolicy:      trial.GetDigest(),
		itemAuthSession: session})
}

func (s *objectSuite) TestUnsealWithEncryptSession(c *C) {
	trial := util.ComputeAuthPolicy(HashAlgorithmSHA256)
	trial.PolicyAuthValue()

	symmetric := SymDef{
		Algorithm: SymAlgorithmAES,
		KeyBits:   MakeSymKeyBitsUnion[uint16](128),
		Mode:      MakeSymModeUnion(SymModeCFB),
	}
	session := s.StartAuthSession(c, nil, nil, SessionTypePolicy, &symmetric, HashAlgorithmSHA256)
	c.Check(s.TPM.PolicyAuthValue(session), IsNil)

	s.testUnseal(c, &testUnsealData{
		secret:          []byte("sensitive data"),
		authPolicy:      trial.GetDigest(),
		itemAuthSession: session.WithAttrs(AttrResponseEncrypt)})
}

func (s *objectSuite) testObjectChangeAuth(c *C, objectAuthSession SessionContext) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	priv, pub, _, _, _, err := s.TPM.Create(primary, &SensitiveCreate{Data: []byte("foo")}, testutil.NewSealedObjectTemplate(), nil, nil, nil)
	c.Check(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	testAuth := []byte("1234")

	sessionHandle := authSessionHandle(objectAuthSession)

	priv, err = s.TPM.ObjectChangeAuth(object, primary, testAuth, objectAuthSession)
	c.Check(err, IsNil)

	authArea := s.LastCommand(c).CmdAuthArea
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

	object, err = s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	object.SetAuthValue(testAuth)

	_, err = s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
}

func (s *objectSuite) TestObjectChangeAuth(c *C) {
	s.testObjectChangeAuth(c, nil)
}

func (s *objectSuite) TestObjectChangeAuthWithObjectAuthSession(c *C) {
	s.testObjectChangeAuth(c, s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256))
}

func (s *objectSuite) TestMakeCredential(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	ekPub := testutil.NewExternalRSAStoragePublicKey(&key.PublicKey)

	ek, err := s.TPM.LoadExternal(nil, ekPub, HandleOwner)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	h.Write([]byte("fake object"))
	name := h.Sum(nil)

	credential := []byte("secret credential")

	credentialBlob, secret, err := s.TPM.MakeCredential(ek, credential, name)
	c.Check(err, IsNil)

	seed, err := internal_crypt.SecretDecrypt(key, crypto.SHA256, []byte(IdentityKey), secret)
	c.Check(err, IsNil)

	recoveredCredential, err := testutil.UnwrapOuter(HashAlgorithmSHA256, &ekPub.Params.RSADetail().Symmetric, name, seed, false, credentialBlob)
	c.Check(err, IsNil)

	_, err = mu.UnmarshalFromBytes(recoveredCredential, &recoveredCredential)
	c.Check(err, IsNil)
	c.Check(recoveredCredential, DeepEquals, credential)
}

type testActivateCredentialData struct {
	activateAuthSession SessionContext
	keyAuthSession      SessionContext
}

func (s *objectSuite) testActivateCredential(c *C, data *testActivateCredentialData) {
	primary := s.CreatePrimary(c, HandleEndorsement, testutil.NewRSAStorageKeyTemplate())

	primaryPub, _, _, err := s.TPM.ReadPublic(primary)
	c.Assert(err, IsNil)

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, testutil.NewRestrictedRSASigningKeyTemplate(nil), nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	credential := []byte("secret credential")

	credentialBlob, secret, err := objectutil.MakeCredential(rand.Reader, primaryPub, credential, object.Name())
	c.Check(err, IsNil)

	sessionHandles := HandleList{authSessionHandle(data.activateAuthSession), authSessionHandle(data.keyAuthSession)}

	certInfo, err := s.TPM.ActivateCredential(object, primary, credentialBlob, secret, data.activateAuthSession, data.keyAuthSession)
	c.Check(err, IsNil)
	c.Check(certInfo, DeepEquals, Digest(credential))

	authArea := s.LastCommand(c).CmdAuthArea
	c.Assert(authArea, internal_testutil.LenEquals, 2)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandles[0])
	c.Check(authArea[1].SessionHandle, Equals, sessionHandles[1])
}

func (s *objectSuite) TestActivateCredential(c *C) {
	s.testActivateCredential(c, &testActivateCredentialData{})
}
