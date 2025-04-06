// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_efi_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"testing"

	efi "github.com/canonical/go-efilib"
	. "github.com/canonical/go-tpm2/internal/ppi_efi"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/ppi"
	"github.com/canonical/go-tpm2/testutil"
	. "gopkg.in/check.v1"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

var ppGuid = efi.MakeGUID(0xaeb9c5c1, 0x94f1, 0x4d02, 0xbfd9, [...]uint8{0x46, 0x02, 0xdb, 0x2d, 0x3c, 0x54})

type vars struct {
	pp     *PhysicalPresence
	flags  PhysicalPresenceFlags
	config *PhysicalPresenceConfig
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

var _ = Suite(&ppiEfiSuite{})

func (s *ppiEfiSuite) TestReadPhysicalPresence(c *C) {
	v := &vars{pp: new(PhysicalPresence)}
	pp, attrs, err := ReadPhysicalPresence(context.WithValue(context.Background(), efi.VarsBackendKey{}, v))
	c.Assert(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(pp, DeepEquals, v.pp)
}

func (s *ppiEfiSuite) TestReadPhysicalPresenceWithPendingRequest(c *C) {
	v := &vars{pp: &PhysicalPresence{PPRequest: 5}}
	pp, attrs, err := ReadPhysicalPresence(context.WithValue(context.Background(), efi.VarsBackendKey{}, v))
	c.Assert(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(pp, DeepEquals, v.pp)
}

func (s *ppiEfiSuite) TestReadPhysicalPresenceWithPendingRequestWithParam(c *C) {
	v := &vars{pp: &PhysicalPresence{
		PPRequest:          23,
		PPRequestParameter: 6,
	}}
	pp, attrs, err := ReadPhysicalPresence(context.WithValue(context.Background(), efi.VarsBackendKey{}, v))
	c.Assert(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(pp, DeepEquals, v.pp)
}

func (s *ppiEfiSuite) TestReadPhysicalPresenceWithPendingResponse(c *C) {
	v := &vars{pp: &PhysicalPresence{LastPPRequest: 5}}
	pp, attrs, err := ReadPhysicalPresence(context.WithValue(context.Background(), efi.VarsBackendKey{}, v))
	c.Assert(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(pp, DeepEquals, v.pp)
}

func (s *ppiEfiSuite) TestReadPhysicalPresenceWithPendingErrorResponse(c *C) {
	v := &vars{pp: &PhysicalPresence{
		LastPPRequest:  5,
		LastPPResponse: 0xfffffff0,
	}}
	pp, attrs, err := ReadPhysicalPresence(context.WithValue(context.Background(), efi.VarsBackendKey{}, v))
	c.Assert(err, IsNil)
	c.Check(attrs, Equals, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess)
	c.Check(pp, DeepEquals, v.pp)
}

func (s *ppiEfiSuite) TestPhysicalPresenceSetRequest(c *C) {
	p := new(PhysicalPresence)
	c.Check(p.SetRequest(ppi.OperationClearTPM, nil), IsNil)
	c.Check(p, DeepEquals, &PhysicalPresence{PPRequest: 5})
}

func (s *ppiEfiSuite) TestPhysicalPresenceSetRequestWithParam(c *C) {
	p := new(PhysicalPresence)
	param := uint32(6)
	c.Check(p.SetRequest(ppi.OperationSetPCRBanks, &param), IsNil)
	c.Check(p, DeepEquals, &PhysicalPresence{PPRequest: 23, PPRequestParameter: 6})
}

func (s *ppiEfiSuite) TestPhysicalPresenceSetRequestInvalidOp(c *C) {
	p := new(PhysicalPresence)
	c.Check(p.SetRequest(ppi.OperationId(256), nil), Equals, ppi.ErrOperationUnsupported)
}

func (s *ppiEfiSuite) TestPhysicalPresenceSubmit(c *C) {
	v := &vars{pp: new(PhysicalPresence)}
	p := &PhysicalPresence{PPRequest: 5}
	c.Check(p.Submit(context.WithValue(context.Background(), efi.VarsBackendKey{}, v), efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess), IsNil)
	c.Check(v.pp, DeepEquals, p)
}

func (s *ppiEfiSuite) TestPhysicalPresenceSubmitWithParam(c *C) {
	v := &vars{pp: new(PhysicalPresence)}
	p := &PhysicalPresence{PPRequest: 23, PPRequestParameter: 6}
	c.Check(p.Submit(context.WithValue(context.Background(), efi.VarsBackendKey{}, v), efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess), IsNil)
	c.Check(v.pp, DeepEquals, p)
}

func (s *ppiEfiSuite) TestPhysicalPresenceSubmitWithPendingResponse(c *C) {
	v := &vars{pp: &PhysicalPresence{LastPPRequest: 1}}
	p := &PhysicalPresence{PPRequest: 5, LastPPRequest: 1}
	c.Check(p.Submit(context.WithValue(context.Background(), efi.VarsBackendKey{}, v), efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess), IsNil)
	c.Check(v.pp, DeepEquals, p)
}

func (s *ppiEfiSuite) TestPhysicalPresenceSubmitOverridePendingRequest(c *C) {
	v := &vars{pp: &PhysicalPresence{PPRequest: 23, PPRequestParameter: 6}}
	p := &PhysicalPresence{PPRequest: 5}
	c.Check(p.Submit(context.WithValue(context.Background(), efi.VarsBackendKey{}, v), efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess), IsNil)
	c.Check(v.pp, DeepEquals, p)
}

func (s *ppiEfiSuite) TestPhysicalPresenceConfigVersion(c *C) {
	config := &PhysicalPresenceConfig{PPIVersion: [8]byte{'1', '.', '4', 0, 0, 0, 0, 0}}
	version, err := config.Version()
	c.Check(err, IsNil)
	c.Check(version.Compare(ppi.Version14), Equals, 0)
}

func (s *ppiEfiSuite) TestPhysicalPresenceConfigTransitionAction(c *C) {
	config := &PhysicalPresenceConfig{PPITransitionAction: 2}
	c.Check(config.TransitionAction(), Equals, ppi.StateTransitionRebootRequired)
}

func (s *ppiEfiSuite) TestPhysicalPresenceConfigOperationStatus(c *C) {
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
	config := &PhysicalPresenceConfig{UserConfirmation: makeUserConfirmationBitmap(c, m)}

	for k, v := range m {
		c.Check(config.OperationStatus(k), Equals, v, Commentf("operation ID: %d", k))
	}
}

func (s *ppiEfiSuite) TestPhysicalPresenceConfigOperationStatusInvalidOp(c *C) {
	config := new(PhysicalPresenceConfig)
	c.Check(config.OperationStatus(ppi.OperationId(128)), Equals, ppi.OperationNotImplemented)
}

func (s *ppiEfiSuite) TestNewBackend(c *C) {
	v := &vars{
		pp:    new(PhysicalPresence),
		flags: 0x700e2,
		config: &PhysicalPresenceConfig{
			StructVersion:       1,
			PPIVersion:          [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			PPITransitionAction: 2,
			UserConfirmation: makeUserConfirmationBitmap(c, map[ppi.OperationId]ppi.OperationStatus{
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
			}),
		},
	}

	backend, version, err := NewBackend(v)
	c.Assert(err, IsNil)
	c.Check(version.Compare(ppi.Version14), Equals, 0)
	c.Check(backend, DeepEquals, &EfiPpiImpl{
		CustomVars: v,
		Flags:      v.flags,
		Config:     v.config,
	})
}

func (s *ppiEfiSuite) TestNewBackendWithoutConfig(c *C) {
	v := &vars{
		pp:    new(PhysicalPresence),
		flags: 0x700e2,
	}

	backend, version, err := NewBackend(v)
	c.Assert(err, IsNil)
	c.Check(version.Compare(ppi.Version14), Equals, 0)
	c.Check(backend, DeepEquals, &EfiPpiImpl{
		CustomVars: v,
		Flags:      v.flags,
	})
}

func (s *ppiEfiSuite) TestNewBackendUnavailable(c *C) {
	v := new(vars)

	_, _, err := NewBackend(v)
	c.Check(err, Equals, ErrUnavailable)
}

func (s *ppiEfiSuite) TestNewBackendInvalidConfigStructVersion(c *C) {
	v := &vars{
		pp:    new(PhysicalPresence),
		flags: 0x700e2,
		config: &PhysicalPresenceConfig{
			StructVersion:       2,
			PPIVersion:          [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			PPITransitionAction: 2,
			UserConfirmation: makeUserConfirmationBitmap(c, map[ppi.OperationId]ppi.OperationStatus{
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
			}),
		},
	}

	_, _, err := NewBackend(v)
	c.Check(err, Equals, ErrUnavailable)
}

func (s *ppiEfiSuite) TestBackendSubmitOperation(c *C) {
	v := &vars{pp: new(PhysicalPresence)}
	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)
	c.Check(backend.SubmitOperation(ppi.OperationClearTPM, nil), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &PhysicalPresence{PPRequest: 5}})
}

func (s *ppiEfiSuite) TestBackendSubmitOperationWithParam(c *C) {
	v := &vars{pp: new(PhysicalPresence)}
	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)
	param := uint32(6)
	c.Check(backend.SubmitOperation(ppi.OperationSetPCRBanks, &param), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &PhysicalPresence{PPRequest: 23, PPRequestParameter: 6}})
}

func (s *ppiEfiSuite) TestBackendSubmitOperationWithPendingRequest(c *C) {
	v := &vars{pp: &PhysicalPresence{PPRequest: 23, PPRequestParameter: 6}}
	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)
	c.Check(backend.SubmitOperation(ppi.OperationClearTPM, nil), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &PhysicalPresence{PPRequest: 5}})
}

func (s *ppiEfiSuite) TestBackendSubmitOperationWithPendingResponse(c *C) {
	v := &vars{pp: &PhysicalPresence{LastPPRequest: 1}}
	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)
	c.Check(backend.SubmitOperation(ppi.OperationClearTPM, nil), IsNil)
	c.Check(v, DeepEquals, &vars{pp: &PhysicalPresence{PPRequest: 5, LastPPRequest: 1}})
}

func (s *ppiEfiSuite) TestBackendStateTransitionAction(c *C) {
	v := &vars{
		pp: new(PhysicalPresence),
		config: &PhysicalPresenceConfig{
			StructVersion:       1,
			PPIVersion:          [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			PPITransitionAction: 2,
		},
	}
	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)
	action, err := backend.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionRebootRequired)
}

func (s *ppiEfiSuite) TestBackendStateTransitionActionShutdown(c *C) {
	v := &vars{
		pp: new(PhysicalPresence),
		config: &PhysicalPresenceConfig{
			StructVersion:       1,
			PPIVersion:          [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			PPITransitionAction: 1,
		},
	}
	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)
	action, err := backend.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionShutdownRequired)
}

func (s *ppiEfiSuite) TestBackendStateTransitionActionNoConfig(c *C) {
	v := &vars{pp: new(PhysicalPresence)}
	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)
	action, err := backend.StateTransitionAction()
	c.Check(err, IsNil)
	c.Check(action, Equals, ppi.StateTransitionRebootRequired)
}

func (s *ppiEfiSuite) TestBackendOperationStatus(c *C) {
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
		pp:    new(PhysicalPresence),
		flags: 0x700e2,
		config: &PhysicalPresenceConfig{
			StructVersion:       1,
			PPIVersion:          [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			PPITransitionAction: 2,
			UserConfirmation:    makeUserConfirmationBitmap(c, m),
		},
	}

	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)

	for k := ppi.OperationId(0); k < ppi.OperationId(255); k++ {
		expected := ppi.OperationNotImplemented
		if v, ok := m[k]; ok {
			expected = v
		}
		status, err := backend.OperationStatus(k)
		c.Check(err, IsNil, Commentf("operation ID: %d", k))
		c.Check(status, Equals, expected, Commentf("operation ID: %d", k))
	}
}

func (s *ppiEfiSuite) TestBackendOperationStatusNoEnableDisable(c *C) {
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
		pp:    new(PhysicalPresence),
		flags: 0x700e2,
		config: &PhysicalPresenceConfig{
			StructVersion:       1,
			PPIVersion:          [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			PPITransitionAction: 2,
			UserConfirmation:    makeUserConfirmationBitmap(c, m),
		},
	}

	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)

	for k := ppi.OperationId(0); k < ppi.OperationId(255); k++ {
		expected := ppi.OperationNotImplemented
		if v, ok := m[k]; ok {
			expected = v
		}
		status, err := backend.OperationStatus(k)
		c.Check(err, IsNil, Commentf("operation ID: %d", k))
		c.Check(status, Equals, expected, Commentf("operation ID: %d", k))
	}
}

func (s *ppiEfiSuite) TestBackendOperationStatusNoConfig(c *C) {
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
		pp:    new(PhysicalPresence),
		flags: 0x700e2,
	}

	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)

	for k := ppi.OperationId(0); k < ppi.OperationId(255); k++ {
		expected := ppi.OperationNotImplemented
		if v, ok := m[k]; ok {
			expected = v
		}
		status, err := backend.OperationStatus(k)
		c.Check(err, IsNil, Commentf("operation ID: %d", k))
		c.Check(status, Equals, expected, Commentf("operation ID: %d", k))
	}
}

func (s *ppiEfiSuite) TestBackendOperationResponseNone(c *C) {
	v := &vars{pp: new(PhysicalPresence)}

	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)

	rsp, err := backend.OperationResponse()
	c.Assert(err, IsNil)
	c.Check(rsp, IsNil)
}

func (s *ppiEfiSuite) TestBackendOperationResponseGood(c *C) {
	v := &vars{pp: &PhysicalPresence{LastPPRequest: 5}}

	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)

	rsp, err := backend.OperationResponse()
	c.Assert(err, IsNil)
	c.Check(rsp, DeepEquals, &ppi.OperationResponse{Operation: ppi.OperationClearTPM})
}

func (s *ppiEfiSuite) TestBackendOperationResponseOpError(c *C) {
	v := &vars{pp: &PhysicalPresence{LastPPRequest: 14, LastPPResponse: 0xfffffff1}}

	backend, _, err := NewBackend(v)
	c.Assert(err, IsNil)

	rsp, err := backend.OperationResponse()
	c.Assert(err, IsNil)
	c.Check(rsp, DeepEquals, &ppi.OperationResponse{Operation: ppi.OperationEnableAndClearTPM, Err: ppi.OperationError(0xfffffff1)})
}
