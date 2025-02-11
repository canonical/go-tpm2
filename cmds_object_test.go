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

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2"
	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"
)

type objectMixin struct {
	tpm *tpm2.TPMContext
}

func (m *objectMixin) setupTest(tpm *tpm2.TPMContext) (restore func(*C)) {
	m.tpm = tpm
	return func(_ *C) {
		m.tpm = nil
	}
}

func (m *objectMixin) checkPublicAgainstTemplate(c *C, public, template *Public) {
	unique := public.Unique

	var p *Public
	mu.MustCopyValue(&p, public)

	for _, p := range []*Public{template, p} {
		p.Unique = nil
		if p.Type == ObjectTypeRSA && p.Params.RSADetail.Exponent == 0 {
			p.Params.RSADetail.Exponent = DefaultRSAExponent
		}
	}

	c.Check(p, testutil.TPMValueDeepEquals, template)

	switch template.Type {
	case ObjectTypeRSA:
		c.Check(unique.RSA, internal_testutil.LenEquals, int(template.Params.RSADetail.KeyBits)/8)
	case ObjectTypeECC:
		c.Check(unique.ECC.X, internal_testutil.LenEquals, template.Params.ECCDetail.CurveID.GoCurve().Params().BitSize/8)
		c.Check(unique.ECC.Y, internal_testutil.LenEquals, template.Params.ECCDetail.CurveID.GoCurve().Params().BitSize/8)
	case ObjectTypeSymCipher:
		c.Check(unique.Sym, internal_testutil.LenEquals, template.NameAlg.Size())
	case ObjectTypeKeyedHash:
		c.Check(unique.KeyedHash, internal_testutil.LenEquals, template.NameAlg.Size())
	}
}

func (m *objectMixin) checkCreationData(c *C, data *CreationData, hash Digest, template *Public, outsideInfo Data, creationPCR PCRSelectionList, parent ResourceContext) {
	var parentQN Name
	if parent.Handle().Type() == HandleTypePermanent {
		parentQN = parent.Name()
	} else {
		var err error
		_, _, parentQN, err = m.tpm.ReadPublic(parent)
		c.Check(err, IsNil)
	}

	_, pcrValues, err := m.tpm.PCRRead(creationPCR)
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

func (m *objectMixin) checkCreationTicket(c *C, ticket *TkCreation, hierarchy Handle) {
	c.Check(ticket, NotNil)
	c.Check(ticket.Tag, Equals, TagCreation)
	c.Check(ticket.Hierarchy, Equals, hierarchy)

	value, err := m.tpm.GetCapabilityTPMProperty(PropertyContextHash)
	c.Assert(err, IsNil)
	contextHash := HashAlgorithmId(value)

	c.Check(contextHash.IsValid(), internal_testutil.IsTrue)

	c.Check(ticket.Digest, internal_testutil.LenEquals, contextHash.Size())
}

type objectSuite struct {
	testutil.TPMTest
	objectMixin
}

func (s *objectSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy
}

func (s *objectSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)
	s.AddFixtureCleanup(s.objectMixin.setupTest(s.TPM))
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
	sessionHMACIsPW := sessionHandle == HandlePW || data.parentAuthSession.State().NeedsPassword

	outPrivate, outPublic, creationData, creationHash, creationTicket, err := s.TPM.Create(data.parent, data.sensitive, data.template, data.outsideInfo, data.creationPCR, data.parentAuthSession)
	c.Assert(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.parent.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.parent.AuthValue()))
		}
	}
	if data.parentAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(data.parentAuthSession.Handle(), Equals, HandleUnassigned)
	}

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

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth("1234"))
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

func (s *objectSuite) TestCreateWithParentPWSession(c *C) {
	parent, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAStorageKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testCreate(c, &testCreateData{
		parent:        parent,
		template:      objectutil.NewRSAKeyTemplate(objectutil.UsageSign),
		sensitiveSize: 640,
		hierarchy:     HandleOwner})
}

type testLoadParams struct {
	parentAuthValue   []byte
	parentAuthSession SessionContext
}

func (s *objectSuite) testLoad(c *C, params *testLoadParams) {
	sessionHandle := authSessionHandle(params.parentAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || params.parentAuthSession.State().NeedsPassword

	parent, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), &SensitiveCreate{UserAuth: params.parentAuthValue}, objectutil.NewRSAStorageKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, objectutil.NewRSAKeyTemplate(objectutil.UsageSign), nil, nil, nil)
	c.Assert(err, IsNil)

	expectedName, err := pub.ComputeName()
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(parent, priv, pub, params.parentAuthSession)
	c.Assert(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(parent.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(parent.AuthValue()))
		}
	}
	if params.parentAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(params.parentAuthSession.Handle(), Equals, HandleUnassigned)
	}

	handle := cmd.RspHandle

	c.Check(object.Handle(), Equals, handle)
	c.Check(object.Name(), DeepEquals, expectedName)

	var sample ObjectContext
	c.Assert(object, Implements, &sample)
	c.Check(object.(ObjectContext).Public(), DeepEquals, pub)

	pub2, name, _, err := s.TPM.ReadPublic(object)
	c.Assert(err, IsNil)
	c.Check(pub2, DeepEquals, pub)
	c.Check(name, DeepEquals, expectedName)
}

func (s *objectSuite) TestLoad(c *C) {
	s.testLoad(c, &testLoadParams{})
}

func (s *objectSuite) TestLoadWithParentAuthSession(c *C) {
	s.testLoad(c, &testLoadParams{parentAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *objectSuite) TestLoadWithParentPWSession(c *C) {
	s.testLoad(c, &testLoadParams{parentAuthValue: []byte("1234")})
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

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Check(authArea, internal_testutil.LenEquals, 0)

	_, handle, _, _ := s.LastCommand(c).UnmarshalResponse(c)
	expectedName := data.inPublic.Name()

	c.Check(object.Handle(), Equals, handle)
	c.Check(object.Name(), DeepEquals, expectedName)

	var sample ObjectContext
	c.Assert(object, Implements, &sample)
	c.Check(object.(ObjectContext).Public(), testutil.TPMValueDeepEquals, data.inPublic)

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

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].HMAC, DeepEquals, Auth(authValue))
}

type testUnsealData struct {
	secret          []byte
	authValue       []byte
	authPolicy      Digest
	itemAuthSession SessionContext
}

func (s *objectSuite) testUnseal(c *C, data *testUnsealData) {
	sessionHandle := authSessionHandle(data.itemAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || data.itemAuthSession.State().NeedsPassword

	primary := s.CreateStoragePrimaryKeyRSA(c)

	sensitive := SensitiveCreate{Data: data.secret, UserAuth: data.authValue}
	template := objectutil.NewSealedObjectTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
		objectutil.WithAuthPolicy(data.authPolicy),
	)

	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	object.SetAuthValue(data.authValue)

	unsealedSecret, err := s.TPM.Unseal(object, data.itemAuthSession)
	c.Check(err, IsNil)
	c.Check(unsealedSecret, DeepEquals, SensitiveData(data.secret))

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.authValue) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.authValue))
		}
	}
	if data.itemAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(data.itemAuthSession.Handle(), Equals, HandleUnassigned)
	}
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

func (s *objectSuite) TestUnsealWithItemAuthPWSession(c *C) {
	s.testUnseal(c, &testUnsealData{
		secret:    []byte("sensitive data"),
		authValue: []byte("password")})
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
		KeyBits:   &SymKeyBitsU{Sym: 128},
		Mode:      &SymModeU{Sym: SymModeCFB}}
	session := s.StartAuthSession(c, nil, nil, SessionTypePolicy, &symmetric, HashAlgorithmSHA256)
	c.Check(s.TPM.PolicyAuthValue(session), IsNil)

	s.testUnseal(c, &testUnsealData{
		secret:          []byte("sensitive data"),
		authPolicy:      trial.GetDigest(),
		itemAuthSession: session.WithAttrs(AttrResponseEncrypt)})
}

func (s *objectSuite) testObjectChangeAuth(c *C, initialAuth, newAuth Auth, newObjectAuthSession func(ResourceContext) SessionContext) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	priv, pub, _, _, _, err := s.TPM.Create(primary, &SensitiveCreate{
		UserAuth: initialAuth,
		Data:     []byte("foo"),
	}, testutil.NewSealedObjectTemplate(), nil, nil, nil)
	c.Check(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	object.SetAuthValue(initialAuth)

	var objectAuthSession SessionContext
	if newObjectAuthSession != nil {
		objectAuthSession = newObjectAuthSession(object)
	}
	sessionHandle := authSessionHandle(objectAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || objectAuthSession.State().NeedsPassword

	priv, err = s.TPM.ObjectChangeAuth(object, primary, newAuth, objectAuthSession)
	c.Check(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(initialAuth) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, initialAuth)
		}
	}
	if objectAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(objectAuthSession.Handle(), Equals, HandleUnassigned)
	}

	object, err = s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	object.SetAuthValue(newAuth)

	_, err = s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)

	cmd = s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, HandlePW)
	c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, newAuth)
}

func (s *objectSuite) TestObjectChangeAuth(c *C) {
	s.testObjectChangeAuth(c, nil, []byte("1234"), nil)
}

func (s *objectSuite) TestObjectChangeAuthDifferentAuthValue(c *C) {
	s.testObjectChangeAuth(c, nil, []byte("5678"), nil)
}

func (s *objectSuite) TestObjectChangeAuthWithObjectAuthSessionUnbound(c *C) {
	s.testObjectChangeAuth(c, nil, []byte("1234"), func(_ ResourceContext) SessionContext {
		return s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	})
}

func (s *objectSuite) TestObjectChangeAuthWithObjectAuthSessionBound(c *C) {
	s.testObjectChangeAuth(c, []byte("4321"), []byte("1234"), func(bind ResourceContext) SessionContext {
		return s.StartAuthSession(c, nil, bind, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	})
}

func (s *objectSuite) TestObjectChangeAuthWithPWSession(c *C) {
	s.testObjectChangeAuth(c, []byte("1234"), []byte("4321"), nil)
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

	recoveredCredential, err := testutil.UnwrapOuter(HashAlgorithmSHA256, &ekPub.Params.RSADetail.Symmetric, name, seed, false, credentialBlob)
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

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 2)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandles[0])
	c.Check(authArea[1].SessionHandle, Equals, sessionHandles[1])
}

func (s *objectSuite) TestActivateCredential(c *C) {
	s.testActivateCredential(c, &testActivateCredentialData{})
}
