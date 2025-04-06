// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_test

import (
	"errors"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/internal/ppi"
	"github.com/canonical/go-tpm2/ppi"
	"github.com/canonical/go-tpm2/testutil"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

type submittedOp struct {
	op     ppi.OperationId
	hasArg bool
	arg    uint32
}

type mockPPIBackend struct {
	submitted []submittedOp
	submitErr error

	sta    ppi.StateTransitionAction
	staErr error

	ops    map[ppi.OperationId]ppi.OperationStatus
	opsErr error

	rsp    *ppi.OperationResponse
	rspErr error
}

func (b *mockPPIBackend) SubmitOperation(op ppi.OperationId, arg *uint32) error {
	if b.submitErr != nil {
		return b.submitErr
	}

	data := submittedOp{op: op}
	if arg != nil {
		data.hasArg = true
		data.arg = *arg
	}
	b.submitted = append(b.submitted, data)
	return nil
}

func (b *mockPPIBackend) StateTransitionAction() (ppi.StateTransitionAction, error) {
	return b.sta, b.staErr
}

func (b *mockPPIBackend) OperationStatus(op ppi.OperationId) (ppi.OperationStatus, error) {
	return b.ops[op], b.opsErr
}

func (b *mockPPIBackend) OperationResponse() (*ppi.OperationResponse, error) {
	return b.rsp, b.rspErr
}

type ppiSuite struct{}

var _ = Suite(&ppiSuite{})

func (s *ppiSuite) TestPPITypeACPI(c *C) {
	pp := New(ppi.ACPI, ppi.Version13, new(mockPPIBackend))
	c.Check(pp.Type(), Equals, ppi.ACPI)
}

func (s *ppiSuite) TestPPITypeEFI(c *C) {
	pp := New(ppi.EFI, ppi.Version14, new(mockPPIBackend))
	c.Check(pp.Type(), Equals, ppi.EFI)
}

func (s *ppiSuite) TestPPIVersion13(c *C) {
	pp := New(ppi.ACPI, ppi.Version13, new(mockPPIBackend))
	c.Check(pp.Version(), Equals, ppi.Version13)
}

func (s *ppiSuite) TestPPIVersion12(c *C) {
	pp := New(ppi.ACPI, ppi.Version12, new(mockPPIBackend))
	c.Check(pp.Version(), Equals, ppi.Version12)
}

func (s *ppiSuite) TestPPIStateTransitionActionReboot(c *C) {
	pp := New(ppi.ACPI, ppi.Version13, &mockPPIBackend{sta: ppi.StateTransitionRebootRequired})
	action, err := pp.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionRebootRequired)
}

func (s *ppiSuite) TestPPIStateTransitionActionShutdown(c *C) {
	pp := New(ppi.ACPI, ppi.Version13, &mockPPIBackend{sta: ppi.StateTransitionShutdownRequired})
	action, err := pp.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionShutdownRequired)
}

func (s *ppiSuite) TestPPIStateTransitionError(c *C) {
	backend := &mockPPIBackend{staErr: errors.New("some error")}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	_, err := pp.StateTransitionAction()
	c.Check(err, Equals, backend.staErr)
}

func (s *ppiSuite) TestPPIOperationStatusDisableTPM(c *C) {
	pp := New(ppi.ACPI, ppi.Version13, &mockPPIBackend{ops: map[ppi.OperationId]ppi.OperationStatus{ppi.OperationDisableTPM: ppi.OperationFirmwareOnly}})
	status, err := pp.OperationStatus(ppi.OperationDisableTPM)
	c.Check(err, IsNil)
	c.Check(status, Equals, ppi.OperationFirmwareOnly)
}

func (s *ppiSuite) TestPPIOperationStatusClearTPM(c *C) {
	pp := New(ppi.ACPI, ppi.Version13, &mockPPIBackend{ops: map[ppi.OperationId]ppi.OperationStatus{ppi.OperationClearTPM: ppi.OperationPPRequired}})
	status, err := pp.OperationStatus(ppi.OperationClearTPM)
	c.Check(err, IsNil)
	c.Check(status, Equals, ppi.OperationPPRequired)
}

func (s *ppiSuite) TestPPIOperationStatusErr(c *C) {
	backend := &mockPPIBackend{opsErr: errors.New("some error")}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	_, err := pp.OperationStatus(ppi.OperationDisableTPM)
	c.Check(err, Equals, backend.opsErr)
}

func (s *ppiSuite) TestPPIEnableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.EnableTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationEnableTPM}})
}

func (s *ppiSuite) TestPPIEnableTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.EnableTPM(), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPIDisableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.DisableTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationDisableTPM}})
}

func (s *ppiSuite) TestPPIDisableTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.DisableTPM(), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPIClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ClearTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationClearTPM}})
}

func (s *ppiSuite) TestPPIClearTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ClearTPM(), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPIEnableAndClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.EnableAndClearTPM(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationEnableAndClearTPM}})
}

func (s *ppiSuite) TestPPIEnableAndClearTPMErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.EnableAndClearTPM(), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPISetPCRBanksSHA256(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.SetPCRBanks(tpm2.HashAlgorithmSHA256), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationSetPCRBanks, hasArg: true, arg: 2}})
}

func (s *ppiSuite) TestPPISetPCRBanksMultiple(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.SetPCRBanks(tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384, tpm2.HashAlgorithmSHA512), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationSetPCRBanks, hasArg: true, arg: 14}})
}

func (s *ppiSuite) TestPPISetPCRBanksErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.SetPCRBanks(tpm2.HashAlgorithmSHA256), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPIChangeEPS(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ChangeEPS(), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationChangeEPS}})
}

func (s *ppiSuite) TestPPIChangeEPSErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ChangeEPS(), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPISetPPRequiredForOperationClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.SetPPRequiredForOperation(ppi.OperationClearTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationSetPPRequiredForClearTPM}})
}

func (s *ppiSuite) TestPPISetPPRequiredForOperationDisableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.SetPPRequiredForOperation(ppi.OperationDisableTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationSetPPRequiredForDisableTPM}})
}

func (s *ppiSuite) TestPPISetPPRequiredForOperationUnsupported(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.SetPPRequiredForOperation(ppi.OperationSetPPRequiredForClearTPM), Equals, ppi.ErrOperationUnsupported)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPISetPPRequiredForOperationErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.SetPPRequiredForOperation(ppi.OperationClearTPM), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPIClearPPRequiredForOperationClearTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ClearPPRequiredForOperation(ppi.OperationClearTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationClearPPRequiredForClearTPM}})
}

func (s *ppiSuite) TestPPIClearPPRequiredForOperationDisableTPM(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ClearPPRequiredForOperation(ppi.OperationDisableTPM), IsNil)
	c.Check(backend.submitted, DeepEquals, []submittedOp{{op: ppi.OperationClearPPRequiredForDisableTPM}})
}

func (s *ppiSuite) TestPPIClearPPRequiredForOperationUnsupported(c *C) {
	backend := new(mockPPIBackend)
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ClearPPRequiredForOperation(ppi.OperationClearPPRequiredForClearTPM), Equals, ppi.ErrOperationUnsupported)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestPPIClearPPRequiredForOperationErr(c *C) {
	backend := &mockPPIBackend{submitErr: ppi.ErrOperationFailed}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	c.Check(pp.ClearPPRequiredForOperation(ppi.OperationClearTPM), Equals, ppi.ErrOperationFailed)
	c.Check(backend.submitted, DeepEquals, []submittedOp(nil))
}

func (s *ppiSuite) TestOperationResponseNone(c *C) {
	pp := New(ppi.ACPI, ppi.Version13, new(mockPPIBackend))
	rsp, err := pp.OperationResponse()
	c.Check(err, IsNil)
	c.Check(rsp, IsNil)
}

func (s *ppiSuite) TestOperationResponseErr(c *C) {
	backend := &mockPPIBackend{rspErr: errors.New("some error")}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	rsp, err := pp.OperationResponse()
	c.Check(err, Equals, backend.rspErr)
	c.Check(rsp, IsNil)
}

func (s *ppiSuite) TestOperationResponseGood(c *C) {
	backend := &mockPPIBackend{rsp: &ppi.OperationResponse{Operation: ppi.OperationClearTPM}}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	rsp, err := pp.OperationResponse()
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, backend.rsp)
}

func (s *ppiSuite) TestOperationResponseOpErr(c *C) {
	backend := &mockPPIBackend{rsp: &ppi.OperationResponse{Operation: ppi.OperationEnableAndClearTPM, Err: ppi.OperationError(0xfffffff1)}}
	pp := New(ppi.ACPI, ppi.Version13, backend)
	rsp, err := pp.OperationResponse()
	c.Check(err, IsNil)
	c.Check(rsp, DeepEquals, backend.rsp)
}
