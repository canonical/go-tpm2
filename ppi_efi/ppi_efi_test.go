// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_efi_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"testing"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/ppi"
	. "github.com/canonical/go-tpm2/ppi_efi"
	"github.com/canonical/go-tpm2/testutil"
	. "gopkg.in/check.v1"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

var ppGuid = efi.MakeGUID(0xaeb9c5c1, 0x94f1, 0x4d02, 0xbfd9, [...]uint8{0x46, 0x02, 0xdb, 0x2d, 0x3c, 0x54})

type physicalPresence struct {
	PPRequest          uint8
	PPRequestParameter uint32
	LastPPRequest      uint8
	LastPPResponse     uint32
}

type physicalPresenceFlags uint32

type physicalPresenceConfig struct {
	StructVersion    uint32
	PPICapabilities  uint32
	PPIVersion       [8]byte
	TransitionAction uint32
	UserConfirmation [64]uint8
}

type vars struct {
	pp     *physicalPresence
	flags  physicalPresenceFlags
	config *physicalPresenceConfig
}

func (v *vars) Get(name string, guid efi.GUID) (efi.VariableAttributes, []byte, error) {
	if v.pp == nil {
		return 0, nil, efi.ErrVarNotExist
	}
	if guid != ppGuid {
		return 0, nil, efi.ErrVarNotExist
	}

	switch name {
	case "Tcg2PhysicalPresenceFlags":
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(v.flags))
		return efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, buf, nil
	case "Tcg2PhysicalPresenceConfig":
		if v.config == nil {
			return 0, nil, efi.ErrVarNotExist
		}
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, v.config)
		return efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, buf.Bytes(), nil
	case "Tcg2PhysicalPresence":
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, v.pp)
		return efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, buf.Bytes(), nil
	default:
		return 0, nil, efi.ErrVarNotExist
	}
}

func (v *vars) Set(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) error {
	if v.pp == nil {
		return efi.ErrVarPermission
	}
	if guid != ppGuid {
		return efi.ErrVarPermission
	}
	if name != "Tcg2PhysicalPresence" {
		return efi.ErrVarPermission
	}
	if attrs != efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess {
		// XXX: Should probably return efi.ErrVarInvalidParam, although it
		// doesn't matter really.
		return &os.PathError{
			Op:   "write",
			Path: fmt.Sprintf("/sys/firmware/efi/efivars/%s-%s", name, guid),
			Err:  syscall.EINVAL,
		}
	}

	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, v.pp); err != nil {
		// XXX: Should probably return efi.ErrVarInvalidParam, although it
		// doesn't matter really.
		return &os.PathError{
			Op:   "write",
			Path: fmt.Sprintf("/sys/firmware/efi/efivars/%s-%s", name, guid),
			Err:  syscall.EINVAL,
		}
	}
	return nil
}

func (v *vars) List() ([]efi.VariableDescriptor, error) {
	return nil, efi.ErrVarPermission
}

func makeUserConfirmationBitmap(c *C, in map[ppi.OperationId]ppi.OperationStatus) (out [64]uint8) {
	for k, v := range in {
		c.Assert(k, internal_testutil.IntLessEqual, 127)
		index := 63 - int(k>>1)
		shift := 0
		if k&1 == 1 {
			shift = 4
		}
		out[index] = out[index]&(0xf<<(4-shift)) | uint8(v)<<shift
	}
	return out
}

type ppiEfiSuite struct{}

func (s *ppiEfiSuite) SetUpTest(c *C) {
	ResetPPI()
}

var _ = Suite(&ppiEfiSuite{})

func (s *ppiEfiSuite) TestPPIUnavailable(c *C) {
	v := new(vars)
	restore := MockVars(v)
	defer restore()

	_, err := PPI()
	c.Assert(err, Equals, ErrUnavailable)
}

func (s *ppiEfiSuite) TestPPIType(c *C) {
	v := &vars{
		pp: new(physicalPresence),
	}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)
	c.Check(pp.Type(), Equals, ppi.EFI)
}

func (s *ppiEfiSuite) TestPPIVersion(c *C) {
	v := &vars{
		pp: new(physicalPresence),
		config: &physicalPresenceConfig{
			StructVersion: 1,
			PPIVersion:    [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
		},
	}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)
	c.Check(pp.Version(), Equals, ppi.Version14)
}

func (s *ppiEfiSuite) TestPPIStateTransitionAction(c *C) {
	v := &vars{
		pp: new(physicalPresence),
		config: &physicalPresenceConfig{
			StructVersion:    1,
			PPIVersion:       [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			TransitionAction: 2,
		},
	}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)
	action, err := pp.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionRebootRequired)
}

func (s *ppiEfiSuite) TestPPIStateTransitionActionShutdown(c *C) {
	v := &vars{
		pp: new(physicalPresence),
		config: &physicalPresenceConfig{
			StructVersion:    1,
			PPIVersion:       [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			TransitionAction: 1,
		},
	}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)
	action, err := pp.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionShutdownRequired)
}

func (s *ppiEfiSuite) TestPPIStateTransitionActionNoConfig(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)
	action, err := pp.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionRebootRequired)
}

func (s *ppiEfiSuite) TestPPIOperationStatus(c *C) {
	m := map[ppi.OperationId]ppi.OperationStatus{
		ppi.OperationEnableTPM:                    ppi.OperationPPNotRequired,
		ppi.OperationDisableTPM:                   ppi.OperationPPRequired,
		ppi.OperationClearTPM:                     ppi.OperationPPRequired,
		ppi.OperationEnableAndClearTPM:            ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForClearTPM:     ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForClearTPM:   ppi.OperationPPRequired,
		ppi.OperationSetPCRBanks:                  ppi.OperationPPRequired,
		ppi.OperationChangeEPS:                    ppi.OperationPPRequired,
		ppi.OperationClearPPRequiredForChangePCRs: ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForChangePCRs:   ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForEnableTPM:  ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForEnableTPM:    ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForDisableTPM: ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForDisableTPM:   ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForChangeEPS:  ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForChangeEPS:    ppi.OperationPPNotRequired,
	}
	v := &vars{
		pp:    new(physicalPresence),
		flags: 0x700e2,
		config: &physicalPresenceConfig{
			StructVersion:    1,
			PPIVersion:       [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			TransitionAction: 2,
			UserConfirmation: makeUserConfirmationBitmap(c, m),
		},
	}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	for k := ppi.OperationId(0); k < ppi.OperationId(255); k++ {
		expected := ppi.OperationNotImplemented
		if v, ok := m[k]; ok {
			expected = v
		}
		status, err := pp.OperationStatus(k)
		c.Check(err, IsNil, Commentf("operation ID: %d", k))
		c.Check(status, Equals, expected, Commentf("operation ID: %d", k))
	}
}

func (s *ppiEfiSuite) TestPPIOperationStatusNoEnableDisable(c *C) {
	m := map[ppi.OperationId]ppi.OperationStatus{
		ppi.OperationEnableTPM:                    ppi.OperationNotImplemented,
		ppi.OperationDisableTPM:                   ppi.OperationNotImplemented,
		ppi.OperationClearTPM:                     ppi.OperationPPRequired,
		ppi.OperationEnableAndClearTPM:            ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForClearTPM:     ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForClearTPM:   ppi.OperationPPRequired,
		ppi.OperationSetPCRBanks:                  ppi.OperationPPRequired,
		ppi.OperationChangeEPS:                    ppi.OperationPPRequired,
		ppi.OperationClearPPRequiredForChangePCRs: ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForChangePCRs:   ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForEnableTPM:  ppi.OperationNotImplemented,
		ppi.OperationSetPPRequiredForEnableTPM:    ppi.OperationNotImplemented,
		ppi.OperationClearPPRequiredForDisableTPM: ppi.OperationNotImplemented,
		ppi.OperationSetPPRequiredForDisableTPM:   ppi.OperationNotImplemented,
		ppi.OperationClearPPRequiredForChangeEPS:  ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForChangeEPS:    ppi.OperationPPNotRequired,
	}
	v := &vars{
		pp:    new(physicalPresence),
		flags: 0x700e2,
		config: &physicalPresenceConfig{
			StructVersion:    1,
			PPIVersion:       [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			TransitionAction: 2,
			UserConfirmation: makeUserConfirmationBitmap(c, m),
		},
	}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	for k := ppi.OperationId(0); k < ppi.OperationId(255); k++ {
		expected := ppi.OperationNotImplemented
		if v, ok := m[k]; ok {
			expected = v
		}
		status, err := pp.OperationStatus(k)
		c.Check(err, IsNil, Commentf("operation ID: %d", k))
		c.Check(status, Equals, expected, Commentf("operation ID: %d", k))
	}
}

func (s *ppiEfiSuite) TestPPIOperationStatusNoConfig(c *C) {
	m := map[ppi.OperationId]ppi.OperationStatus{
		ppi.OperationEnableTPM:                    ppi.OperationPPNotRequired,
		ppi.OperationDisableTPM:                   ppi.OperationPPRequired,
		ppi.OperationClearTPM:                     ppi.OperationPPRequired,
		ppi.OperationEnableAndClearTPM:            ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForClearTPM:     ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForClearTPM:   ppi.OperationPPRequired,
		ppi.OperationSetPCRBanks:                  ppi.OperationPPRequired,
		ppi.OperationChangeEPS:                    ppi.OperationPPRequired,
		ppi.OperationClearPPRequiredForChangePCRs: ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForChangePCRs:   ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForEnableTPM:  ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForEnableTPM:    ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForDisableTPM: ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForDisableTPM:   ppi.OperationPPNotRequired,
		ppi.OperationClearPPRequiredForChangeEPS:  ppi.OperationPPRequired,
		ppi.OperationSetPPRequiredForChangeEPS:    ppi.OperationPPNotRequired,
	}
	v := &vars{
		pp:    new(physicalPresence),
		flags: 0x700e2,
	}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	for k := ppi.OperationId(0); k < ppi.OperationId(255); k++ {
		expected := ppi.OperationNotImplemented
		if v, ok := m[k]; ok {
			expected = v
		}
		status, err := pp.OperationStatus(k)
		c.Check(err, IsNil, Commentf("operation ID: %d", k))
		c.Check(status, Equals, expected, Commentf("operation ID: %d", k))
	}
}

func (s *ppiEfiSuite) TestPPIEnableTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.EnableTPM(), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 1}})
}

func (s *ppiEfiSuite) TestPPIDisableTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.DisableTPM(), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 2}})
}

func (s *ppiEfiSuite) TestPPIClearTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.ClearTPM(), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 5}})
}

func (s *ppiEfiSuite) TestPPIClearTPMWithPendingRequest(c *C) {
	v := &vars{pp: &physicalPresence{PPRequest: 23, PPRequestParameter: 6}}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.ClearTPM(), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 5}})
}

func (s *ppiEfiSuite) TestPPIClearTPMWithPendingResponse(c *C) {
	v := &vars{pp: &physicalPresence{LastPPRequest: 1}}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.ClearTPM(), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 5, LastPPRequest: 1}})
}

func (s *ppiEfiSuite) TestPPIEnableAndClearTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.EnableAndClearTPM(), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 14}})
}

func (s *ppiEfiSuite) TestPPISetPCRBanks(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.SetPCRBanks(tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 23, PPRequestParameter: 6}})
}

func (s *ppiEfiSuite) TestPPIChangeEPS(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.ChangeEPS(), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 24}})
}

func (s *ppiEfiSuite) TestPPISetPPRequiredForOperationClearTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.SetPPRequiredForOperation(ppi.OperationClearTPM), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 17}})
}

func (s *ppiEfiSuite) TestPPISetPPRequiredForOperationDisableTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.SetPPRequiredForOperation(ppi.OperationDisableTPM), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 30}})
}

func (s *ppiEfiSuite) TestPPISetPPRequiredForOperationUnsupported(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.SetPPRequiredForOperation(ppi.OperationSetPPRequiredForClearTPM), Equals, ppi.ErrOperationUnsupported)
	c.Check(v, DeepEquals, &vars{pp: new(physicalPresence)})
}

func (s *ppiEfiSuite) TestPPIClearPPRequiredForOperationClearTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.ClearPPRequiredForOperation(ppi.OperationClearTPM), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 18}})
}

func (s *ppiEfiSuite) TestPPIClearPPRequiredForOperationDisableTPM(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.ClearPPRequiredForOperation(ppi.OperationDisableTPM), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &physicalPresence{PPRequest: 29}})
}

func (s *ppiEfiSuite) TestPPIClearPPRequiredForOperationUnsupported(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	c.Check(pp.ClearPPRequiredForOperation(ppi.OperationClearPPRequiredForClearTPM), Equals, ppi.ErrOperationUnsupported)
	c.Check(v, DeepEquals, &vars{pp: new(physicalPresence)})
}

func (s *ppiEfiSuite) TestPPIOperationResponseNone(c *C) {
	v := &vars{pp: new(physicalPresence)}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	rsp, err := pp.OperationResponse()
	c.Assert(err, IsNil)
	c.Check(rsp, IsNil)
}

func (s *ppiEfiSuite) TestPPIOperationResponseGood(c *C) {
	v := &vars{pp: &physicalPresence{LastPPRequest: 5}}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	rsp, err := pp.OperationResponse()
	c.Assert(err, IsNil)
	c.Check(rsp, DeepEquals, &ppi.OperationResponse{Operation: ppi.OperationClearTPM})
}

func (s *ppiEfiSuite) TestPPIOperationResponseOpError(c *C) {
	v := &vars{pp: &physicalPresence{LastPPRequest: 14, LastPPResponse: 0xfffffff1}}
	restore := MockVars(v)
	defer restore()

	pp, err := PPI()
	c.Assert(err, IsNil)

	rsp, err := pp.OperationResponse()
	c.Assert(err, IsNil)
	c.Check(rsp, DeepEquals, &ppi.OperationResponse{Operation: ppi.OperationEnableAndClearTPM, Err: ppi.OperationError(0xfffffff1)})
}
