// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"fmt"
	"math"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mssim"

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
		c.Assert(b.cleanupHandlers, internal_testutil.LenEquals, 0)        // missing BaseTest.TearDownTest call?
		c.Assert(b.fixtureCleanupHandlers, internal_testutil.LenEquals, 0) // missing BaseTest.TearDownTest call?
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

// Deprecated: use CommandRecord.CmdCode.
func (r *CommandRecordC) GetCommandCode(c *C) tpm2.CommandCode {
	code, err := r.CommandRecord.GetCommandCode()
	c.Assert(err, IsNil)
	return code
}

// Deprecated: use CommandRecord.CmdHandles, CommandRecord.CmdAuthArea and CommandRecord.CpBytes.
func (r *CommandRecordC) UnmarshalCommand(c *C) (handles tpm2.HandleList, authArea []tpm2.AuthCommand, parameters []byte) {
	handles, authArea, parameters, err := r.CommandRecord.UnmarshalCommand()
	c.Assert(err, IsNil)
	return handles, authArea, parameters
}

// Deprecated: use CommandRecord.RspCode, CommandRecord.RspHandle, CommandRecord.RpBytes and CommandRecord.RspAuthArea.
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

	TPM *tpm2.TPMContext // The TPM context for the test

	// TCTI is the TPM transport interface for the test.
	// Deprecated: Use the Transport field instead. Only one of these should be
	//  set at a time before calling SetUpTest, although if neither field is set
	//  then SetUpTest will set them both for backwards compatibility.
	TCTI *Transport

	Transport *Transport     // The TPM transport interface for the test
	Device    tpm2.TPMDevice // The TPM device that supplies the transmission interface

	TPMFeatures TPMFeatureFlags // TPM features required by tests in this suite
}

func (b *TPMTest) initTPMContextIfNeeded(c *C) {
	switch {
	case b.TPM != nil:
		// A TPMContext has been provided by the test. Make sure it set one of TCTI or Transport,
		// but not both - we do that here.
		switch {
		case b.TCTI != nil:
			// The test set the deprecated field.
			c.Assert(b.Transport, IsNil)
			b.Transport = b.TCTI // copy the pointer from the deprecated field to the new field
		case b.Transport != nil:
			// The test set the new field.
			c.Assert(b.TCTI, IsNil)
			b.TCTI = b.Transport // copy the pointer from the new field to the deprecated field
		default:
			c.Fatal("if the TPM field is set prior to calling SetUpTest, one of the TCTI (which is deprecated) or Transport fields must be set")
		}
	case b.TCTI != nil:
		// A transport has been provided by the test using the deprecated field.
		c.Assert(b.Transport, IsNil)
		b.Transport = b.TCTI // copy the pointer to the new field and fallthrough
		fallthrough
	case b.Transport != nil:
		// A transport has been provided by the test using the new field.
		// Create a TPMContext from the supplied transport
		b.TPM, _ = OpenTPMDevice(c, NewTransportPassthroughDevice(b.Transport))
		b.TCTI = b.Transport // populate the deprecated field
	case b.Device != nil:
		// A device has been provided by the test.
		// Create a TPMContext and transport from the supplied device
		b.TPM, b.Transport = OpenTPMDevice(c, b.Device)
		b.TCTI = b.Transport // populate the deprecated field
	default:
		// Nothing has been supplied by the test. Create a default TPMContext and transport
		b.TPM, b.Transport = NewTPMContext(c, b.TPMFeatures)
		b.TCTI = b.Transport // populate the deprecated field
	}
}

// SetUpTest is called to set up the test fixture before each test. If the TPM,
// Transport and Device members have not been set before this is called, a TPM connection
// and TPMContext will be created automatically. In this case, the TPMFeatures member
// should be set prior to calling SetUpTest in order to declare the features that
// the test will require. If the test requires any features that are not included
// in PermittedTPMFeatures, the test will be skipped. If TPMBackend is TPMBackendNone,
// then the test will be skipped.
//
// If the Device member is set prior to calling SetUpTest, a TPM connection and
// TPMContext is created using this.
//
// If the Transport member is set prior to calling SetUpTest, a TPMContext is created
// using this connection if necessary.
//
// If both TPM and Transport are set prior to calling SetUpTest, then these will be
// used by the test.
//
// The TPMContext is closed automatically when TearDownTest is called, unless
// the test clears the TPM member first.
func (b *TPMTest) SetUpTest(c *C) {
	b.BaseTest.SetUpTest(c)
	b.initTPMContextIfNeeded(c)
	b.AddFixtureCleanup(func(c *C) {
		if b.TPM != nil {
			c.Check(b.TPM.Close(), IsNil)
		}
		b.TPM = nil
		b.TCTI = nil
		b.Transport = nil
		b.Device = nil
	})
}

// CommandLog returns a log of TPM commands that have been executed since
// the start of the test, or since the last call to ForgetCommands.
func (b *TPMTest) CommandLog() (log []*CommandRecordC) {
	for _, r := range b.Transport.CommandLog {
		log = append(log, &CommandRecordC{r})
	}
	return log
}

// LastCommand returns a record of the last TPM command that was executed.
// It asserts if no command has been executed.
func (b *TPMTest) LastCommand(c *C) *CommandRecordC {
	c.Assert(b.Transport.CommandLog, Not(internal_testutil.LenEquals), 0)
	return &CommandRecordC{b.Transport.CommandLog[len(b.Transport.CommandLog)-1]}
}

// ForgetCommands forgets the log of TPM commands that have been executed
// since the start of the test or since the last call to ForgetCommands.
func (b *TPMTest) ForgetCommands() {
	b.Transport.CommandLog = nil
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
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

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

// RequireCommand checks if the required command is supported
// by the TPM and skips the test if it isn't.
func (b *TPMTest) RequireCommand(c *C, code tpm2.CommandCode) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	if !b.TPM.IsCommandSupported(code) {
		c.Skip(fmt.Sprintf("unsupported command %v", code))
	}
}

// RequireAlgorithm checks if the required algorithm is known to the
// TPM and skips the test if it isn't.
func (b *TPMTest) RequireAlgorithm(c *C, alg tpm2.AlgorithmId) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	if !b.TPM.IsAlgorithmSupported(alg) {
		c.Skip(fmt.Sprintf("unsupported algorithm %v", alg))
	}
}

// RequireRSAKeySize checks if a RSA object can be created with the
// specified key size and skips the test if it can't.
func (b *TPMTest) RequireRSAKeySize(c *C, keyBits uint16) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	if !b.TPM.IsRSAKeySizeSupported(keyBits) {
		c.Skip(fmt.Sprintf("unsupported RSA key size %d", keyBits))
	}
}

// RequireECCCurve checks if the specified elliptic curve is known
// to the TPM and skips the test if it isn't.
func (b *TPMTest) RequireECCCurve(c *C, curve tpm2.ECCCurve) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	if !b.TPM.IsECCCurveSupported(curve) {
		c.Skip(fmt.Sprintf("unsupported elliptic curve %v", curve))
	}
}

// RequireSymmetricAlgorithm checks if an object with the specified
// symmetric algorithm can be created and skips the test if it can't.
func (b *TPMTest) RequireSymmetricAlgorithm(c *C, algorithm tpm2.SymObjectAlgorithmId, keyBits uint16) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	if !b.TPM.IsSymmetricAlgorithmSupported(algorithm, keyBits) {
		c.Skip(fmt.Sprintf("unsupported symmetric algorithm %v-%d", algorithm, keyBits))
	}
}

// ClearTPMUsingPlatformHierarchy enables the TPM2_Clear command and then
// clears the TPM using the platform hierarchy. It causes the test to fail
// if it isn't successful.
func (b *TPMTest) ClearTPMUsingPlatformHierarchy(c *C) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	c.Check(clearTPMUsingPlatform(b.TPM), IsNil)
}

// HierarchyChangeAuth calls the tpm2.TPMContext.HierarchyChangeAuth function and
// causes the test to fail if it is not successful.
func (b *TPMTest) HierarchyChangeAuth(c *C, hierarchy tpm2.Handle, auth tpm2.Auth) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	c.Check(b.TPM.HierarchyChangeAuth(b.TPM.GetPermanentContext(hierarchy), auth, nil), IsNil)
}

// CreatePrimary calls the tpm2.TPMContext.CreatePrimary function and asserts
// if it is not succesful.
func (b *TPMTest) CreatePrimary(c *C, hierarchy tpm2.Handle, template *tpm2.Public) tpm2.ResourceContext {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	object, _, _, _, _, err := b.TPM.CreatePrimary(b.TPM.GetPermanentContext(hierarchy), nil, template, nil, nil, nil)
	c.Assert(err, IsNil)
	return object
}

// EvictControl calls the tpm2.TPMContext.EvictControl function and asserts if it
// is not successful.
func (b *TPMTest) EvictControl(c *C, auth tpm2.Handle, object tpm2.ResourceContext, persistentHandle tpm2.Handle) tpm2.ResourceContext {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	p, err := b.TPM.EvictControl(b.TPM.GetPermanentContext(auth), object, persistentHandle, nil)
	c.Assert(err, IsNil)
	return p
}

// NVDefineSpace calls the tpm2.TPMContext.NVDefineSpace function and asserts if
// it is not successful.
func (b *TPMTest) NVDefineSpace(c *C, authHandle tpm2.Handle, auth tpm2.Auth, publicInfo *tpm2.NVPublic) tpm2.ResourceContext {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	n, err := b.TPM.NVDefineSpace(b.TPM.GetPermanentContext(authHandle), auth, publicInfo, nil)
	c.Assert(err, IsNil)
	return n
}

// StartAuthSession calls the tpm2.TPMContext.StartAuthSession function and asserts
// if it is not successful.
func (b *TPMTest) StartAuthSession(c *C, tpmKey, bind tpm2.ResourceContext, sessionType tpm2.SessionType, symmetric *tpm2.SymDef, authHash tpm2.HashAlgorithmId) tpm2.SessionContext {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

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

func (b *TPMSimulatorTest) initTPMSimulatorDeviceIfNeeded(c *C) {
	switch {
	case b.TPM != nil:
		// Do nothing for now - TPMTest.SetUpTest will do nothing either,
		// and we'll verify we have a simulator transport.
	case b.TCTI != nil:
		// Do nothing for now - TPMTest.SetUpTest will create a TPMContext,
		// and we'll verify we have a simulator transport.
	case b.Transport != nil:
		// Do nothing for now - TPMTest.SetUpTest will create a TPMContext,
		// and we'll verify we have a simulator transport.
	case b.Device != nil:
		// Do nothing for now - TPMTest.SetUpTest will create a new
		// TPMContext and transport and we'll verify it creates a simulator
		// transport
	default:
		b.Device = NewSimulatorDevice()
		// TPMTest.SetUpTest will create a TPMContext and simulator transport
	}
}

// SetUpTest is called to set up the test fixture before each test. If the TPM,
// Transport and Device members have not been set before this is called, a TPM connection
// and TPMContext will be created automatically. In this case, the TPMFeatures member
// should be set prior to calling SetUpTest in order to declare the features that
// the test will require. If the test requires any features that are not included
// in PermittedTPMFeatures, the test will be skipped. If TPMBackend is TPMBackendNone,
// then the test will be skipped.
//
// If the Device member is set prior to calling SetUpTest, a TPM connection and
// TPMContext is created using this.
//
// If the Transport member is set prior to calling SetUpTest, a TPMContext is created
// using this connection if necessary.
//
// If both TPM and Transport are set prior to calling SetUpTest, then these will be
// used by the test.
//
// The TPMContext is closed automatically when TearDownTest is called, unless
// the test clears the TPM member first.

// SetUpTest is called to set up the test fixture before each test. If the TPM,
// Transport and Device members have not been set before this is called, a TPM simulator
// connection and TPMContext will be created automatically. If TPMBackend is
// not TPMBackendMssim, then the test will be skipped.
//
// If the Device member is set prior to calling SetUpTest, a TPM connection and
// TPMContext is created using this. The test asserts that the device creates a simulator
// transport (ie, *[mssim.Transport]).
//
// If the Transport member is set prior to calling SetUpTest, a TPMContext is created
// using this connection if necessary. The test asserts that the supplied transport
// is a simulator transport (ie, *[mssim.Transport]).
//
// If both TPM and Transport are set prior to calling SetUpTest, then these will be
// used by the test, although the test asserts that the supplied transport is a
// simulator transport (ie, *[mssim.Transport]).
//
// When TearDownTest is called, the TPM simulator will be reset and cleared
// and the TPMContext will be closed, unless the test clears the TPM member
// first.
func (b *TPMSimulatorTest) SetUpTest(c *C) {
	b.initTPMSimulatorDeviceIfNeeded(c)
	b.TPMTest.SetUpTest(c)

	// Assert that we have a simulator
	b.Mssim(c)

	b.AddFixtureCleanup(func(c *C) {
		if b.TPM == nil {
			return
		}
		b.ResetAndClearTPMSimulatorUsingPlatformHierarchy(c)
		c.Check(b.TPM.Close(), IsNil)
		b.TPM = nil

		if b.Transport.didUpdatePcrAllocation {
			// We need to give the TPM one more reset
			c.Assert(b.Device, NotNil)
			tpm, transport := OpenTPMDevice(c, b.Device)
			b.TPM = tpm
			b.Transport = transport
			b.TCTI = transport
			b.ResetTPMSimulator(c)
			c.Check(b.TPM.Close(), IsNil)
			b.TPM = nil
		}
	})
}

// Mssim returns the underlying simulator connection.
func (b *TPMSimulatorTest) Mssim(c *C) *mssim.Transport {
	var transport tpm2.Transport = b.Transport
	for {
		wrapper, isWrapper := transport.(TransportWrapper)
		if !isWrapper {
			break
		}
		transport = wrapper.Unwrap()
	}
	c.Assert(transport, internal_testutil.ConvertibleTo, &mssim.Transport{})
	return transport.(*mssim.Transport)
}

// ResetTPMSimulator issues a Shutdown(Clear) -> Reset -> Startup(Clear) cycle of the TPM
// simulator and causes the test to fail if it is not successful.
func (b *TPMSimulatorTest) ResetTPMSimulator(c *C) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	c.Check(resetTPMSimulator(b.TPM, b.Mssim(c), true), IsNil)
}

// ResetTPMSimulatorNoStartup issues a Shutdown(Clear) -> Reset cycle of the TPM simulator
// and causes the test to fail if it is not successful.
func (b *TPMSimulatorTest) ResetTPMSimulatorNoStartup(c *C) {
	b.Transport.disableCommandLogging = true
	defer func() { b.Transport.disableCommandLogging = false }()

	c.Check(resetTPMSimulator(b.TPM, b.Mssim(c), false), IsNil)
}

// ResetAndClearTPMSimulatorUsingPlatformHierarchy issues a Shutdown(Clear) -> Reset ->
// Startup(Clear) cycle of the TPM simulator which ensures that the platform hierarchy is
// enabled, and then enables the TPM2_Clear command and clears the TPM using the platform
// hierarchy.
func (b *TPMSimulatorTest) ResetAndClearTPMSimulatorUsingPlatformHierarchy(c *C) {
	b.ResetTPMSimulator(c)
	b.ClearTPMUsingPlatformHierarchy(c)
}
