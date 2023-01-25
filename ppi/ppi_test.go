// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_test

import (
	"errors"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/ppi"
	"github.com/canonical/go-tpm2/testutil"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

type submittedOp struct {
	op     OperationId
	hasArg bool
	arg    uint64
}

type mockPPIBackend struct {
	version   string
	submitErr error
	sta       StateTransitionAction
	ops       map[OperationId]OperationStatus

	rsp    *OperationResponse
	rspErr error

	submitted []submittedOp
}

func (b *mockPPIBackend) Version() string {
	return b.version
}

func (b *mockPPIBackend) SubmitOperation(op OperationId, arg *uint64) error {
	data := submittedOp{op: op}
	if arg != nil {
		data.hasArg = true
		data.arg = *arg
	}
	b.submitted = append(b.submitted, data)
	return b.submitErr
}

func (b *mockPPIBackend) StateTransitionAction() StateTransitionAction {
	return b.sta
}

func (b *mockPPIBackend) OperationStatus(op OperationId) OperationStatus {
	return b.ops[op]
}

func (b *mockPPIBackend) OperationResponse() (*OperationResponse, error) {
	return b.rsp, b.rspErr
}

type ppiSuite struct{}

var _ = Suite(&ppiSuite{})

func (s *ppiSuite) TestPPIVersion13(c *C) {
	pp := NewPPI(&mockPPIBackend{version: "1.3"})
	c.Check(pp.Version(), Equals, Version13)
}

func (s *ppiSuite) TestPPIVersion12(c *C) {
	pp := NewPPI(&mockPPIBackend{version: "1.2"})
	c.Check(pp.Version(), Equals, Version12)
}

func (s *ppiSuite) TestPPIStateTransitionActionReboot(c *C) {
	pp := NewPPI(&mockPPIBackend{sta: StateTransitionRebootRequired})
	c.Check(pp.StateTransitionAction(), Equals, StateTransitionRebootRequired)
}

func (s *ppiSuite) TestPPIStateTransitionActionShutdown(c *C) {
	pp := NewPPI(&mockPPIBackend{sta: StateTransitionShutdownRequired})
	c.Check(pp.StateTransitionAction(), Equals, StateTransitionShutdownRequired)
}

func (s *ppiSuite) TestPPIOperationStatusDisableTPM(c *C) {
	pp := NewPPI(&mockPPIBackend{ops: map[OperationId]OperationStatus{OperationDisableTPM: OperationFirmwareOnly}})
	c.Check(pp.OperationStatus(OperationDisableTPM), Equals, OperationFirmwareOnly)
}

func (s *ppiSuite) TestPPIOperationStatusClearTPM(c *C) {
	pp := NewPPI(&mockPPIBackend{ops: map[OperationId]OperationStatus{OperationClearTPM: OperationPPRequired}})
	c.Check(pp.OperationStatus(OperationClearTPM), Equals, OperationPPRequired)
}

func (s *ppiSuite) TestPPIEnableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.EnableTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationEnableTPM}})
}

func (s *ppiSuite) TestPPIEnableTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.EnableTPM(), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestPPIDisableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.DisableTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationDisableTPM}})
}

func (s *ppiSuite) TestPPIDisableTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.DisableTPM(), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestPPIClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.ClearTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationClearTPM}})
}

func (s *ppiSuite) TestPPIClearTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.ClearTPM(), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestPPIEnableAndClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.EnableAndClearTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationEnableAndClearTPM}})
}

func (s *ppiSuite) TestPPIEnableAndClearTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.EnableAndClearTPM(), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestPPISetPCRBanksSHA256(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.SetPCRBanks(tpm2.HashAlgorithmSHA256), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationSetPCRBanks, hasArg: true, arg: 2}})
}

func (s *ppiSuite) TestPPISetPCRBanksMultiple(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.SetPCRBanks(tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384, tpm2.HashAlgorithmSHA512), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationSetPCRBanks, hasArg: true, arg: 14}})
}

func (s *ppiSuite) TestPPISetPCRBanksErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.SetPCRBanks(tpm2.HashAlgorithmSHA256), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestPPIChangeEPS(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.ChangeEPS(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationChangeEPS}})
}

func (s *ppiSuite) TestPPIChangeEPSErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.ChangeEPS(), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestPPISetPPRequiredForOperationClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.SetPPRequiredForOperation(OperationClearTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationSetPPRequiredForClearTPM}})
}

func (s *ppiSuite) TestPPISetPPRequiredForOperationDisableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.SetPPRequiredForOperation(OperationDisableTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationSetPPRequiredForDisableTPM}})
}

func (s *ppiSuite) TestPPISetPPRequiredForOperationErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.SetPPRequiredForOperation(OperationClearTPM), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestPPIClearPPRequiredForOperationClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.ClearPPRequiredForOperation(OperationClearTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationClearPPRequiredForClearTPM}})
}

func (s *ppiSuite) TestPPIClearPPRequiredForOperationDisableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := NewPPI(backend)
	c.Check(pp.ClearPPRequiredForOperation(OperationDisableTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: OperationClearPPRequiredForDisableTPM}})
}

func (s *ppiSuite) TestPPIClearPPRequiredForOperationErr(c *C) {
	backend := &mockPPIBackend{submitErr: ErrOperationFailed}
	pp := NewPPI(backend)
	c.Check(pp.ClearPPRequiredForOperation(OperationClearTPM), Equals, ErrOperationFailed)
}

func (s *ppiSuite) TestOperationResponseNone(c *C) {
	pp := NewPPI(new(mockPPIBackend))
	rsp, err := pp.OperationResponse()
	c.Check(err, IsNil)
	c.Check(rsp, IsNil)
}

func (s *ppiSuite) TestOperationResponseErr(c *C) {
	backend := &mockPPIBackend{rspErr: errors.New("some error")}
	pp := NewPPI(backend)
	rsp, err := pp.OperationResponse()
	c.Check(err, Equals, backend.rspErr)
	c.Check(rsp, IsNil)
}

func (s *ppiSuite) TestOperationResponseGood(c *C) {
	backend := &mockPPIBackend{rsp: &OperationResponse{Operation: OperationClearTPM}}
	pp := NewPPI(backend)
	rsp, err := pp.OperationResponse()
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, backend.rsp)
}
