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

// SetHierarchyAuth sets the authorization value for the supplied hierarchy to auth. It is
// restored automatically at the end of the test.
func (b *TPMTest) SetHierarchyAuth(c *C, hierarchy tpm2.Handle, auth tpm2.Auth) {
	c.Assert(b.TPM.HierarchyChangeAuth(b.TPM.GetPermanentContext(hierarchy), auth, nil), IsNil)
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
