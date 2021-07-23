// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"
)

// BaseTest is a base test suite for all tests.
type BaseTest struct {
	cleanupHandlers        []func()
	fixtureCleanupHandlers []func(c *C)
}

func (b *BaseTest) SetUpTest(c *C) {
	if len(b.cleanupHandlers) > 0 || len(b.fixtureCleanupHandlers) > 0 {
		panic("cleanup handlers were not executed at the end of the previous test, missing BaseTest.TearDownTest call?")
	}
}

func (b *BaseTest) TearDownTest(c *C) {
	for len(b.cleanupHandlers) > 0 {
		l := len(b.cleanupHandlers)
		fn := b.cleanupHandlers[l-1]
		b.cleanupHandlers = b.cleanupHandlers[:l-1]
		fn()
	}

	for len(b.fixtureCleanupHandlers) > 0 {
		l := len(b.fixtureCleanupHandlers)
		fn := b.fixtureCleanupHandlers[l-1]
		b.fixtureCleanupHandlers = b.fixtureCleanupHandlers[:l-1]
		fn(c)
	}
}

// AddCleanup queues a function to be called at the end of the test.
func (b *BaseTest) AddCleanup(fn func()) {
	b.cleanupHandlers = append(b.cleanupHandlers, fn)
}

// AddFixtureCleanup queues a function to be called at the end of
// the test, and is intended to be called during SetUpTest. The
// function is called with the TearDownTest *check.C which allows
// failures to result in a fixture panic, as failures recorded to
// the originating *check.C are ignored at this stage.
func (b *BaseTest) AddFixtureCleanup(fn func(c *C)) {
	b.fixtureCleanupHandlers = append(b.fixtureCleanupHandlers, fn)
}

// CommandRecordC is a helper for CommandRecord that integrates with *check.C.
type CommandRecordC struct {
	*CommandRecord
}

func (r *CommandRecordC) GetCommandCode(c *C) tpm2.CommandCode {
	code, err := r.CommandRecord.GetCommandCode()
	c.Assert(err, IsNil)
	return code
}

func (r *CommandRecordC) UnmarshalCommand(c *C) (handles tpm2.HandleList, authArea []tpm2.AuthCommand, parameters []byte) {
	handles, authArea, parameters, err := r.CommandRecord.UnmarshalCommand()
	c.Assert(err, IsNil)
	return handles, authArea, parameters
}

func (r *CommandRecordC) UnmarshalResponse(c *C) (rc tpm2.ResponseCode, handle tpm2.Handle, parameters []byte, authArea []tpm2.AuthResponse) {
	rc, handle, parameters, authArea, err := r.CommandRecord.UnmarshalResponse()
	c.Assert(err, IsNil)
	return rc, handle, parameters, authArea
}

// TPMTest is a base test suite for all tests that use a TPMContext. This test suite will take care of
// restoring the TPM state at the end of each test, as well as closing the TPMContext.
//
// A TPMContext will be created automatically for each test. For tests that want to implement creation
// of the TPMContext, the TPM and TCTI members should be set before SetUpTest is called.
type TPMTest struct {
	BaseTest

	// TPM is the TPM context for the test. Set this before SetUpTest is called in order to override
	// the default context creation. Not anonymous because of TPMContext.TestParms.
	TPM *tpm2.TPMContext

	TCTI *TCTI

	// TPMFeatures defines the features required by this suite. It should be set before SetUpTest
	// is called if the test relies on the default context creation. If the test requires
	// access to features that currently aren't permitted by the current test environment (as
	// defined by the value of the PermittedTPMFeatures variable), then the test will be skipped.
	TPMFeatures TPMFeatureFlags
}

func (b *TPMTest) initTPMContextIfNeeded(c *C) {
	if b.TPM != nil {
		return
	}
	b.TPM, b.TCTI = NewTPMContext(c, b.TPMFeatures)
}

func (b *TPMTest) SetUpTest(c *C) {
	b.BaseTest.SetUpTest(c)

	b.initTPMContextIfNeeded(c)

	b.AddFixtureCleanup(func(c *C) {
		c.Assert(b.TPM.Close(), IsNil)
		b.TPM = nil
	})
}

// CommandLog returns a log of TPM commands that have been executed since
// the start of the test, or since the last call to ForgetCommands.
func (b *TPMTest) CommandLog() (log []*CommandRecordC) {
	for _, r := range b.TCTI.CommandLog {
		log = append(log, &CommandRecordC{r})
	}
	return log
}

// LastCommand returns a record of the last TPM command that was executed.
// It asserts if no command has been executed.
func (b *TPMTest) LastCommand(c *C) *CommandRecordC {
	c.Assert(b.TCTI.CommandLog, Not(HasLen), 0)
	return &CommandRecordC{b.TCTI.CommandLog[len(b.TCTI.CommandLog)-1]}
}

// ForgetCommands forgets the log of TPM commands that have been executed
// since the start of the test or since the last call to ForgetCommands.
func (b *TPMTest) ForgetCommands() {
	b.TCTI.CommandLog = nil
}

// HierarchyChangeAuth calls the tpm2.TPMContext.HierarchyChangeAuth function and
// asserts if it is not successful.
func (b *TPMTest) HierarchyChangeAuth(c *C, hierarchy tpm2.Handle, auth tpm2.Auth) {
	c.Assert(b.TPM.HierarchyChangeAuth(b.TPM.GetPermanentContext(hierarchy), auth, nil), IsNil)
}

// EvictControl calls the tpm2.TPMContext.EvictControl function and asserts if it
// is not successful.
func (b *TPMTest) EvictControl(c *C, auth tpm2.Handle, object tpm2.ResourceContext, persistentHandle tpm2.Handle) tpm2.ResourceContext {
	p, err := b.TPM.EvictControl(b.TPM.GetPermanentContext(auth), object, persistentHandle, nil)
	c.Assert(err, IsNil)
	return p
}

// NVDefineSpace calls the tpm2.TPMContext.NVDefineSpace function and asserts if
// it is not successful.
func (b *TPMTest) NVDefineSpace(c *C, authContext tpm2.ResourceContext, auth tpm2.Auth, publicInfo *tpm2.NVPublic) tpm2.ResourceContext {
	n, err := b.TPM.NVDefineSpace(authContext, auth, publicInfo, nil)
	c.Assert(err, IsNil)
	return n
}

// StartAuthSession calls the tpm2.TPMContext.StartAuthSession function and asserts
// if it is not successful.
func (b *TPMTest) StartAuthSession(c *C, tpmKey, bind tpm2.ResourceContext, sessionType tpm2.SessionType, symmetric *tpm2.SymDef, authHash tpm2.HashAlgorithmId) tpm2.SessionContext {
	session, err := b.TPM.StartAuthSession(tpmKey, bind, sessionType, symmetric, authHash)
	c.Assert(err, IsNil)
	return session
}

// CreateStoragePrimaryKeyRSA creates a primary storage key in the storage
// hierarchy, with the standard SRK template. On success, it returns the context
// for the newly created object. It asserts if it is not successful.
func (b *TPMTest) CreateStoragePrimaryKeyRSA(c *C) tpm2.ResourceContext {
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	rc, _, _, _, _, err := b.TPM.CreatePrimary(b.TPM.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)
	return rc
}

// TPMSimulatorTest is a base test suite for all tests that use the TPM simulator (TctiMssim).
type TPMSimulatorTest struct {
	TPMTest

	TCTI *tpm2.TctiMssim
}

func (b *TPMSimulatorTest) initTPMSimulatorContextIfNeeded(c *C) {
	if b.TPM != nil {
		return
	}
	tpm, tcti := NewTPMSimulatorContext(c)
	b.TPM = tpm
	b.TCTI = tcti.Unwrap().(*tpm2.TctiMssim)
	b.TPMTest.TCTI = tcti
}

func (b *TPMSimulatorTest) SetUpTest(c *C) {
	b.initTPMSimulatorContextIfNeeded(c)
	b.TPMTest.SetUpTest(c)
}

// ResetTPMSimulator issues a Shutdown -> Reset -> Startup cycle of the TPM simulator.
func (b *TPMSimulatorTest) ResetTPMSimulator(c *C) {
	c.Assert(resetTPMSimulator(b.TPM, b.TCTI), IsNil)
}
