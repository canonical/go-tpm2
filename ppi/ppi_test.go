// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_test

import (
	"testing"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2/ppi"
	"github.com/canonical/go-tpm2/testutil"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

type ppiSuite struct{}

var _ = Suite(&ppiSuite{})

func (s *ppiSuite) TestOperationIdClearPPRequiredOperationIdEnableTPM(c *C) {
	c.Check(OperationEnableTPM.ClearPPRequiredOperationId(), Equals, OperationClearPPRequiredForEnableTPM)
}

func (s *ppiSuite) TestOperationIdSetPPRequiredOperationIdEnableTPM(c *C) {
	c.Check(OperationEnableTPM.SetPPRequiredOperationId(), Equals, OperationSetPPRequiredForEnableTPM)
}

func (s *ppiSuite) TestOperationIdClearPPRequiredOperationIdDisableTPM(c *C) {
	c.Check(OperationDisableTPM.ClearPPRequiredOperationId(), Equals, OperationClearPPRequiredForDisableTPM)
}

func (s *ppiSuite) TestOperationIdSetPPRequiredOperationIdDisableTPM(c *C) {
	c.Check(OperationDisableTPM.SetPPRequiredOperationId(), Equals, OperationSetPPRequiredForDisableTPM)
}

func (s *ppiSuite) TestOperationIdClearPPRequiredOperationIdClearTPM(c *C) {
	c.Check(OperationClearTPM.ClearPPRequiredOperationId(), Equals, OperationClearPPRequiredForClearTPM)
}

func (s *ppiSuite) TestOperationIdSetPPRequiredOperationIdClearTPM(c *C) {
	c.Check(OperationClearTPM.SetPPRequiredOperationId(), Equals, OperationSetPPRequiredForClearTPM)
}

func (s *ppiSuite) TestOperationIdClearPPRequiredOperationIdSetPCRBanks(c *C) {
	c.Check(OperationSetPCRBanks.ClearPPRequiredOperationId(), Equals, OperationClearPPRequiredForChangePCRs)
}

func (s *ppiSuite) TestOperationIdSetPPRequiredOperationIdSetPCRBanks(c *C) {
	c.Check(OperationSetPCRBanks.SetPPRequiredOperationId(), Equals, OperationSetPPRequiredForChangePCRs)
}

func (s *ppiSuite) TestOperationIdClearPPRequiredOperationIdChangeEPS(c *C) {
	c.Check(OperationChangeEPS.ClearPPRequiredOperationId(), Equals, OperationClearPPRequiredForChangeEPS)
}

func (s *ppiSuite) TestOperationIdSetPPRequiredOperationIdChangeEPS(c *C) {
	c.Check(OperationChangeEPS.SetPPRequiredOperationId(), Equals, OperationSetPPRequiredForChangeEPS)
}
