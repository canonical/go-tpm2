// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_test

import (
	"io"
	"testing"

	. "gopkg.in/check.v1"

	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
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

func (s *ppiSuite) TestParseVersion13(c *C) {
	version, err := ParseVersion("1.3")
	c.Check(err, IsNil)
	c.Check(version.Major, internal_testutil.IntEqual, 1)
	c.Check(version.Minor, internal_testutil.IntEqual, 3)
}

func (s *ppiSuite) TestParseVersion12(c *C) {
	version, err := ParseVersion("1.2")
	c.Check(err, IsNil)
	c.Check(version.Major, internal_testutil.IntEqual, 1)
	c.Check(version.Minor, internal_testutil.IntEqual, 2)
}

func (s *ppiSuite) TestParseVersionInvalid1(c *C) {
	_, err := ParseVersion("1.")
	c.Check(err, Equals, io.EOF)
}

func (s *ppiSuite) TestParseVersionInvalid2(c *C) {
	_, err := ParseVersion("-1.3")
	c.Check(err, ErrorMatches, `expected integer`)
}

func (s *ppiSuite) TestVersionCompareEqual(c *C) {
	c.Check(Version13.Compare(Version13), Equals, 0)
}

func (s *ppiSuite) TestVersionCompareLT(c *C) {
	c.Check(Version12.Compare(Version13), Equals, -1)
}

func (s *ppiSuite) TestVersionCompareGT(c *C) {
	c.Check(Version13.Compare(Version12), Equals, 1)
}
