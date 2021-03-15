// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"
)

var (
	TestAuth = []byte("1234")
)

// BaseTest is a base test suite for all tests.
type BaseTest struct {
	cleanupHandlers []func()
}

func (b *BaseTest) SetUpTest(c *C) {
	if len(b.cleanupHandlers) > 0 {
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
}

// AddCleanup queues a function to be called at the end of the test.
func (b *BaseTest) AddCleanup(fn func()) {
	b.cleanupHandlers = append(b.cleanupHandlers, fn)
}

// TPMTestBase is a base test suite for all tests that require a TPMContext but want to implement
// creation of the TPMContext themselves. This base test suite will take care of cleaning up all
// flushable resources (transient objects and sessions) at the end of each test, as well as closing
// the supplied TPMContext.
type TPMTestBase struct {
	BaseTest
	TPM  *tpm2.TPMContext // Not anonymous because of TestParms. Should be set before SetUpTest is called
	TCTI tpm2.TCTI        // Should be set before SetUpTest is called
}

func (b *TPMTestBase) SetUpTest(c *C) {
	b.BaseTest.SetUpTest(c)

	b.AddCleanup(func() { c.Assert(b.TPM.Close(), IsNil) })

	getFlushableHandles := func() (out []tpm2.Handle) {
		for _, t := range []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession} {
			h, err := b.TPM.GetCapabilityHandles(t.BaseHandle(), tpm2.CapabilityMaxProperties, nil)
			c.Assert(err, IsNil)
			out = append(out, h...)
		}
		for i, h := range out {
			if h.Type() == tpm2.HandleTypePolicySession {
				out[i] = (h & 0xffffff) | (tpm2.Handle(tpm2.HandleTypeHMACSession) << 24)
			}
		}
		return
	}
	startFlushableHandles := getFlushableHandles()

	b.AddCleanup(func() {
		for _, h := range getFlushableHandles() {
			found := false
			for _, sh := range startFlushableHandles {
				if sh == h {
					found = true
					break
				}
			}
			if found {
				continue
			}
			var hc tpm2.HandleContext
			switch h.Type() {
			case tpm2.HandleTypeTransient:
				var err error
				hc, err = b.TPM.CreateResourceContextFromTPM(h)
				c.Check(err, IsNil)
			case tpm2.HandleTypeHMACSession:
				hc = tpm2.CreateIncompleteSessionContext(h)
			default:
				c.Fatalf("Unexpected handle type")
			}
			c.Check(b.TPM.FlushContext(hc), IsNil)
		}
	})
}

// AddCleanupNVSpace ensures that the supplied NV index is undefined at the end of the test, using
// the supplied authHandle for authorization.
func (b *TPMTestBase) AddCleanupNVSpace(c *C, authHandle, index tpm2.ResourceContext) {
	b.AddCleanup(func() {
		c.Check(b.TPM.NVUndefineSpace(authHandle, index, nil), IsNil)
	})
}

// SetHierarchyAuth sets the authorization value for the supplied hierarchy to TestAuth and automatically
// clears it again at the end of the test.
func (b *TPMTestBase) SetHierarchyAuth(c *C, hierarchy tpm2.Handle) {
	c.Assert(b.TPM.HierarchyChangeAuth(b.TPM.GetPermanentContext(hierarchy), TestAuth, nil), IsNil)
	b.AddCleanup(func() {
		c.Check(b.TPM.HierarchyChangeAuth(b.TPM.GetPermanentContext(hierarchy), nil, nil), IsNil)
	})
}

// TPMTest is a base test suite for all tests that require a TPMContext created for them.
type TPMTest struct {
	TPMTestBase

	// TPMFeatures defines the features required by this suite. It should be set before
	// SetUpTest is called.
	TPMFeatures TPMFeatureFlags
}

func (b *TPMTest) SetUpTest(c *C) {
	b.TPM, b.TCTI = NewTPMContext(c, b.TPMFeatures)
	b.TPMTestBase.SetUpTest(c)
}

// TPMSimulatorTest is a base test suite for all tests that require a TPMContext and TctiMssim
// created for them.
type TPMSimulatorTest struct {
	TPMTestBase
}

func (b *TPMSimulatorTest) SetUpTest(c *C) {
	b.TPM, b.TCTI = NewTPMSimulatorContext(c)
	b.TPMTestBase.SetUpTest(c)
}

// ResetTPMSimulator issues a Shutdown -> Reset -> Startup cycle of the TPM simulator.
func (b *TPMSimulatorTest) ResetTPMSimulator(c *C) {
	mssim, ok := b.TCTI.(*tpm2.TctiMssim)
	if !ok {
		c.Fatalf("No TPM simulator connection available")
	}
	c.Assert(resetTPMSimulator(b.TPM, mssim), IsNil)
}
