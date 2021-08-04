// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"fmt"
	"math"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"

	. "gopkg.in/check.v1"
)

// BaseTest is a base test suite for all tests. It has the ability to run callbacks
// to perform cleanup actions at the end of each test.
type BaseTest struct {
	currentTestName        string
	cleanupHandlers        []func()
	fixtureCleanupHandlers []func(c *C)
}

// InitCleanup should be called before any call to AddCleanup or AddFixtureCleanup.
// It is called by SetUpTest, but can be called prior to this, If InitCleanup is
// called for the first time in a test after a cleanup handler has already been
// registered, it will assert. This is to detect a missing call to TearDownTest,
// which might happen because the fixture decides a test should be skipped after
// registering a cleanup handler.
//
// InitCleanup can be called multiple times in the same test.
func (b *BaseTest) InitCleanup(c *C) {
	if c.TestName() != b.currentTestName {
		c.Assert(b.cleanupHandlers, LenEquals, 0)        // missing BaseTest.TearDownTest call?
		c.Assert(b.fixtureCleanupHandlers, LenEquals, 0) // missing BaseTest.TearDownTest call?
	}
	b.currentTestName = c.TestName()
}

func (b *BaseTest) SetUpTest(c *C) {
	b.InitCleanup(c)
}

func (b *BaseTest) TearDownTest(c *C) {
	c.Assert(c.TestName(), Equals, b.currentTestName) // missing BaseTest.SetUpTest call?

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

	b.currentTestName = ""
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

// TPMTest is a base test suite for all tests that require a TPM and are able to
// execute on a real TPM or a simulator. This test suite requires the use of the
// transmission interface from this package, which takes care of restoring the TPM
// state when it is closed.
type TPMTest struct {
	BaseTest

	TPM         *tpm2.TPMContext // The TPM context for the test
	TCTI        *TCTI            // The TPM transmission interface for the test
	TPMFeatures TPMFeatureFlags  // TPM features required by tests in this suite
}

func (b *TPMTest) initTPMContextIfNeeded(c *C) {
	switch {
	case b.TPM != nil:
		c.Assert(b.TCTI, NotNil)
		b.AddFixtureCleanup(func(c *C) {
			b.TCTI = nil
			b.TPM = nil
		})
	case b.TCTI != nil:
		// Create a TPMContext from the supplied TCTI
		b.TPM, _ = tpm2.NewTPMContext(b.TCTI)
		b.AddFixtureCleanup(func(c *C) {
			c.Check(b.TPM.Close(), IsNil)
			b.TCTI = nil
			b.TPM = nil
		})
	default:
		// Create a new connection
		b.TPM, b.TCTI = NewTPMContext(c, b.TPMFeatures)
		b.AddFixtureCleanup(func(c *C) {
			c.Check(b.TPM.Close(), IsNil)
			b.TCTI = nil
			b.TPM = nil
		})
	}
}

// SetUpTest is called to set up the test fixture before each test. If the TPM and
// TCTI members have not been set before this is called, a TPM connection and
// TPMContext will be created automatically. In this case, the TPMFeatures member
// should be set prior to calling SetUpTest in order to declare the features that
// the test will require. If the test requires any features that are not included
// in PermittedTPMFeatures, the test will be skipped. If TPMBackend is TPMBackendNone,
// then the test will be skipped.
//
// If the TCTI member is set prior to calling SetUpTest, a TPMContext is created
// using this connection if necessary.
//
// Any TPMContext created by SetUpTest is closed automatically when TearDownTest
// is called.
//
// If both TPM and TCTI are set prior to calling SetUpTest, then these will be
// used by the test. In this case, the test is responsible for closing the
// TPMContext.
func (b *TPMTest) SetUpTest(c *C) {
	b.BaseTest.SetUpTest(c)
	b.initTPMContextIfNeeded(c)
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
	c.Assert(b.TCTI.CommandLog, Not(LenEquals), 0)
	return &CommandRecordC{b.TCTI.CommandLog[len(b.TCTI.CommandLog)-1]}
}

// ForgetCommands forgets the log of TPM commands that have been executed
// since the start of the test or since the last call to ForgetCommands.
func (b *TPMTest) ForgetCommands() {
	b.TCTI.CommandLog = nil
}

// NextAvailableHandle returns the next unused handle starting from
// the supplied handle. This upper 17-bits of the returned handle
// will match the upper 17-bits of the supplied handle - ie, if the
// supplied handle is in a reserved group as defined by the "Registry
// of reserved TPM 2.0 handles and localities" specification, the
// returned handle will be in the same reserved group.
//
// It asserts if no handle is available.
func (b *TPMTest) NextAvailableHandle(c *C, handle tpm2.Handle) tpm2.Handle {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	group := handle & 0xffff8000

	handles, err := b.TPM.GetCapabilityHandles(handle, math.MaxUint32)
	c.Assert(err, IsNil)

	for handle&0xffff8000 == group {
		if len(handles) == 0 {
			return handle
		}
		if handle != handles[0] {
			return handle
		}

		handle += 1
		handles = handles[1:]
	}

	c.Fatal("no available handle")
	return tpm2.HandleUnassigned
}

// RequireAlgorithm checks if the required algorithm is known to the
// TPM and skips the test if it isn't.
func (b *TPMTest) RequireAlgorithm(c *C, alg tpm2.AlgorithmId) {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	algs, err := b.TPM.GetCapabilityAlgs(alg, 1)
	c.Assert(err, IsNil)
	if len(algs) == 0 || algs[0].Alg != alg {
		c.Skip(fmt.Sprintf("unsupported algorithm %v", alg))
	}
}

// RequireRSAKeySize checks if a RSA object can be created with the
// specified key size and skips the test if it can't.
func (b *TPMTest) RequireRSAKeySize(c *C, keyBits uint16) {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	template := templates.NewRSAKey(tpm2.HashAlgorithmNull, 0, nil, keyBits)
	if err := b.TPM.TestParms(&tpm2.PublicParams{Type: template.Type, Parameters: template.Params}); err != nil {
		c.Skip(fmt.Sprintf("unsupported RSA key size %d", keyBits))
	}
}

// RequireECCCurve checks if the specified elliptic curve is known
// to the TPM and skips the test if it isn't.
func (b *TPMTest) RequireECCCurve(c *C, curve tpm2.ECCCurve) {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	curves, err := b.TPM.GetCapabilityECCCurves()
	c.Assert(err, IsNil)
	for _, supported := range curves {
		if supported == curve {
			return
		}
	}
	c.Skip(fmt.Sprintf("unsupported elliptic curve %v", curve))
}

// RequireSymmetricAlgorithm checks if an object with the specified
// symmetric algorithm can be created and skips the test if it can't.
func (b *TPMTest) RequireSymmetricAlgorithm(c *C, algorithm tpm2.SymObjectAlgorithmId, keyBits uint16) {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	template := templates.NewSymmetricKey(tpm2.HashAlgorithmNull, 0, algorithm, keyBits, tpm2.SymModeCFB)
	if err := b.TPM.TestParms(&tpm2.PublicParams{Type: template.Type, Parameters: template.Params}); err != nil {
		c.Skip(fmt.Sprintf("unsupported symmetric algorithm %v-%d", algorithm, keyBits))
	}
}

// ClearTPMUsingPlatformHierarchy enables the TPM2_Clear command and then
// clears the TPM using the platform hierarchy. It causes the test to fail
// if it isn't successful.
func (b *TPMTest) ClearTPMUsingPlatformHierarchy(c *C) {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	c.Check(clearTPMUsingPlatform(b.TPM), IsNil)
}

// HierarchyChangeAuth calls the tpm2.TPMContext.HierarchyChangeAuth function and
// causes the test to fail if it is not successful.
func (b *TPMTest) HierarchyChangeAuth(c *C, hierarchy tpm2.Handle, auth tpm2.Auth) {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	c.Check(b.TPM.HierarchyChangeAuth(b.TPM.GetPermanentContext(hierarchy), auth, nil), IsNil)
}

// CreatePrimary calls the tpm2.TPMContext.CreatePrimary function and asserts
// if it is not succesful.
func (b *TPMTest) CreatePrimary(c *C, hierarchy tpm2.Handle, template *tpm2.Public) tpm2.ResourceContext {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	object, _, _, _, _, err := b.TPM.CreatePrimary(b.TPM.GetPermanentContext(hierarchy), nil, template, nil, nil, nil)
	c.Assert(err, IsNil)
	return object
}

// EvictControl calls the tpm2.TPMContext.EvictControl function and asserts if it
// is not successful.
func (b *TPMTest) EvictControl(c *C, auth tpm2.Handle, object tpm2.ResourceContext, persistentHandle tpm2.Handle) tpm2.ResourceContext {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	p, err := b.TPM.EvictControl(b.TPM.GetPermanentContext(auth), object, persistentHandle, nil)
	c.Assert(err, IsNil)
	return p
}

// NVDefineSpace calls the tpm2.TPMContext.NVDefineSpace function and asserts if
// it is not successful.
func (b *TPMTest) NVDefineSpace(c *C, authContext tpm2.ResourceContext, auth tpm2.Auth, publicInfo *tpm2.NVPublic) tpm2.ResourceContext {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	n, err := b.TPM.NVDefineSpace(authContext, auth, publicInfo, nil)
	c.Assert(err, IsNil)
	return n
}

// StartAuthSession calls the tpm2.TPMContext.StartAuthSession function and asserts
// if it is not successful.
func (b *TPMTest) StartAuthSession(c *C, tpmKey, bind tpm2.ResourceContext, sessionType tpm2.SessionType, symmetric *tpm2.SymDef, authHash tpm2.HashAlgorithmId) tpm2.SessionContext {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	session, err := b.TPM.StartAuthSession(tpmKey, bind, sessionType, symmetric, authHash)
	c.Assert(err, IsNil)
	return session
}

// CreateStoragePrimaryKeyRSA creates a primary storage key in the storage
// hierarchy, with the template returned from StorageKeyRSATemplate. On success,
// it returns the context for the newly created object. It asserts if it is not successful.
func (b *TPMTest) CreateStoragePrimaryKeyRSA(c *C) tpm2.ResourceContext {
	return b.CreatePrimary(c, tpm2.HandleOwner, NewRSAStorageKeyTemplate())
}

// TPMSimulatorTest is a base test suite for all tests that require a TPM simulator.
// This test suite requires the use of the transmission interface from this package,
// which takes care of restoring the TPM state when it is closed.
type TPMSimulatorTest struct {
	TPMTest
}

func (b *TPMSimulatorTest) initTPMSimulatorConnectionIfNeeded(c *C) {
	switch {
	case b.TPM != nil:
		c.Assert(b.TCTI, NotNil)
		fallthrough
	case b.TCTI != nil:
		// Assert that it is a simulator
		b.Mssim(c)
		// TPMTest.SetUpTest will create a TPMContext.
	default:
		// No connection was created prior to calling SetUpTest.
		b.TCTI = NewSimulatorTCTI(c)
		// TPMTest.SetUpTest will create a TPMContext.
	}
}

// SetUpTest is called to set up the test fixture before each test. If the
// TCTI member has not been set before this is called, a connection to the TPM
// simulator and a TPMContext will be created automatically. If TPMBackend is
// not TPMBackendMssim, then the test will be skipped.
//
// If the TCTI member is set prior to calling SetUpTest, then a TPMContext is
// created using this connection if necessary.
//
// The TPM simulator will be reset and cleared automatically when TearDownTest
// is called.
//
// Any TPMContext created by SetUpTest is closed automatically when TearDownTest
// is called.
//
// If the TCTI and TPM members are both set prior to calling SetUpTest, then
// these will be used by the test. In this case, the test is responsible for
// closing the TPMContext.
func (b *TPMSimulatorTest) SetUpTest(c *C) {
	b.initTPMSimulatorConnectionIfNeeded(c)
	b.TPMTest.SetUpTest(c)
	b.AddFixtureCleanup(func(c *C) {
		b.ResetAndClearTPMSimulatorUsingPlatformHierarchy(c)
	})
}

// Mssim returns the underlying simulator connection.
func (b *TPMSimulatorTest) Mssim(c *C) *tpm2.TctiMssim {
	var tcti tpm2.TCTI = b.TCTI
	for {
		wrapper, isWrapper := tcti.(TCTIWrapper)
		if !isWrapper {
			break
		}
		tcti = wrapper.Unwrap()
	}
	c.Assert(tcti, ConvertibleTo, &tpm2.TctiMssim{})
	return tcti.(*tpm2.TctiMssim)
}

// ResetTPMSimulator issues a Shutdown -> Reset -> Startup cycle of the TPM simulator
// and causes the test to fail if it is not successful.
func (b *TPMSimulatorTest) ResetTPMSimulator(c *C) {
	b.TCTI.disableCommandLogging = true
	defer func() { b.TCTI.disableCommandLogging = false }()

	c.Check(resetTPMSimulator(b.TPM, b.Mssim(c)), IsNil)
}

// ResetAndClearTPMSimulatorUsingPlatformHierarchy issues a Shutdown -> Reset ->
// Startup cycle of the TPM simulator which ensures that the platform hierarchy is
// enabled, and then enables the TPM2_Clear command and clears the TPM using the
// platform hierarchy.
func (b *TPMSimulatorTest) ResetAndClearTPMSimulatorUsingPlatformHierarchy(c *C) {
	b.ResetTPMSimulator(c)
	b.ClearTPMUsingPlatformHierarchy(c)
}
