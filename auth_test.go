// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"io"
	"testing"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/testutil"
)

type authSuite struct{}

var _ = Suite(&authSuite{})

type mockResourceContext struct {
	handle    Handle
	name      Name
	authValue []byte
}

func (r *mockResourceContext) Handle() Handle                      { return r.handle }
func (r *mockResourceContext) Name() Name                          { return r.name }
func (r *mockResourceContext) SerializeToBytes() []byte            { return nil }
func (r *mockResourceContext) SerializeToWriter(w io.Writer) error { return nil }
func (r *mockResourceContext) SetAuthValue(authValue []byte)       { r.authValue = authValue }
func (r *mockResourceContext) GetAuthValue() []byte                { return r.authValue }
func (r *mockResourceContext) SetHandle(handle Handle)             { r.handle = handle }
func (r *mockResourceContext) Invalidate()                         {}

func (s *authSuite) TestSessionParamIsAuthFalse(c *C) {
	p := MakeMockSessionParam(nil, nil, false, nil, nil)
	c.Check(p.IsAuth(), internal_testutil.IsFalse)
}

func (s *authSuite) TestSessionParamIsAuthTrue(c *C) {
	p := MakeMockSessionParam(nil, new(mockResourceContext), false, nil, nil)
	c.Check(p.IsAuth(), internal_testutil.IsTrue)
}

type testSessionParamComputeSessionHMACKeyData struct {
	sessionKey       []byte
	resource         ResourceContext
	includeAuthValue bool
	expected         []byte
}

func (s *authSuite) testSessionParamComputeSessionHMACKey(c *C, data *testSessionParamComputeSessionHMACKeyData) {
	session := MakeMockSessionContext(0x02000000, &SessionContextData{SessionKey: data.sessionKey})
	p := MakeMockSessionParam(session, data.resource, data.includeAuthValue, nil, nil)
	c.Check(p.ComputeSessionHMACKey(), DeepEquals, data.expected)
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyNoIncludeAuthValue(c *C) {
	resource := new(mockResourceContext)
	resource.SetAuthValue([]byte("bar"))

	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		sessionKey:       []byte("foo"),
		resource:         resource,
		includeAuthValue: false,
		expected:         []byte("foo")})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyIncludeAuthValue(c *C) {
	resource := new(mockResourceContext)
	resource.SetAuthValue([]byte("bar"))

	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		sessionKey:       []byte("foo"),
		resource:         resource,
		includeAuthValue: true,
		expected:         []byte("foobar")})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyNoSessionKeyNoIncludeAuthValue(c *C) {
	resource := new(mockResourceContext)
	resource.SetAuthValue([]byte("bar"))

	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		resource:         resource,
		includeAuthValue: false,
		expected:         []byte(nil)})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyNoSessionKeyIncludeAuthValue(c *C) {
	resource := new(mockResourceContext)
	resource.SetAuthValue([]byte("bar"))

	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		resource:         resource,
		includeAuthValue: true,
		expected:         []byte("bar")})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyIncludeEmptyAuthValue(c *C) {
	resource := new(mockResourceContext)

	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		sessionKey:       []byte("foo"),
		resource:         resource,
		includeAuthValue: true,
		expected:         []byte("foo")})
}

func TestHMACSessions(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	primaryECC := createECCSrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primaryECC)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
		sessionAttrs SessionAttributes
	}{
		{
			desc:         "UnboundUnsalted",
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted",
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource",
			bind:         owner,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc: "UnboundUnsaltedUncontinued",
		},
		{
			desc:         "UnboundSaltedRSA",
			tpmKey:       primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSaltedECC",
			tpmKey:       primaryECC,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSaltedRSA",
			tpmKey:       primary,
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sc, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypeHMAC, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sc)
				} else {
					verifyContextFlushed(t, tpm, sc)
				}
			}()

			template := Public{
				Type:    ObjectTypeRSA,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
				Params: &PublicParamsU{
					RSADetail: &RSAParams{
						Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
						Scheme:    RSAScheme{Scheme: RSASchemeNull},
						KeyBits:   2048,
						Exponent:  0}}}

			sc.SetAttrs(data.sessionAttrs)
			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, sc)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, sc)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent session usage failed: %v", err)
				}
			} else {
				if !IsTPMSessionError(err, ErrorValue, CommandCreate, 1) {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPolicySessions(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	secret := []byte("super secret data")

	template := Public{
		Type:       ObjectTypeKeyedHash,
		NameAlg:    HashAlgorithmSHA256,
		Attrs:      AttrFixedTPM | AttrFixedParent | AttrNoDA,
		AuthPolicy: make([]byte, 32),
		Params:     &PublicParamsU{KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
	sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	objectContext, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	objectContext.SetAuthValue(testAuth)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
		sessionAttrs SessionAttributes
	}{
		{
			desc:         "UnboundUnsalted",
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSalted",
			tpmKey:       primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc: "UnboundUnsaltedUncontinued",
		},
		{
			desc:         "BoundUnsalted",
			bind:         objectContext,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource",
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSalted",
			tpmKey:       primary,
			bind:         objectContext,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sc, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypePolicy, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sc)
				} else {
					verifyContextFlushed(t, tpm, sc)
				}
			}()

			sc.SetAttrs(data.sessionAttrs)
			_, err = tpm.Unseal(objectContext, sc)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, err = tpm.Unseal(objectContext, sc)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent usage of the session failed: %v", err)
				}
			} else {
				if !IsTPMSessionError(err, ErrorValue, CommandUnseal, 1) {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
