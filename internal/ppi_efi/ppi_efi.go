// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_efi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	efi "github.com/canonical/go-efilib"
	internal_ppi "github.com/canonical/go-tpm2/internal/ppi"
	"github.com/canonical/go-tpm2/ppi"
)

const (
	maxOp = ppi.OperationId(127)

	physicalPresenceName       = "Tcg2PhysicalPresence"
	physicalPresenceConfigName = "Tcg2PhysicalPresenceConfig"
	physicalPresenceFlagsName  = "Tcg2PhysicalPresenceFlags"
)

// ErrUnavailable indicates that the EFI based physical presence interface
// is not available.
var ErrUnavailable = errors.New("no EFI physical presence interface available")

var physicalPresenceGuid = efi.MakeGUID(0xaeb9c5c1, 0x94f1, 0x4d02, 0xbfd9, [...]uint8{0x46, 0x02, 0xdb, 0x2d, 0x3c, 0x54})

type physicalPresence struct {
	PPRequest          uint8
	PPRequestParameter uint32
	LastPPRequest      uint8
	LastPPResponse     uint32
}

func readPhysicalPresence(ctx context.Context) (*physicalPresence, efi.VariableAttributes, error) {
	ppBytes, attrs, err := efi.ReadVariable(ctx, physicalPresenceName, physicalPresenceGuid)
	if err != nil {
		return nil, 0, err
	}

	var pp physicalPresence
	if err := binary.Read(bytes.NewReader(ppBytes), binary.LittleEndian, &pp); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, 0, fmt.Errorf("cannot decode EFI_TCG2_PHYSICAL_PRESENCE: %w", err)
	}

	return &pp, attrs, nil
}

func (p *physicalPresence) SetRequest(op ppi.OperationId, arg *uint32) error {
	if op > math.MaxUint8 {
		return ppi.ErrOperationUnsupported
	}

	p.PPRequest = uint8(op)
	p.PPRequestParameter = 0
	if arg != nil {
		p.PPRequestParameter = *arg
	}

	return nil
}

func (p *physicalPresence) Submit(ctx context.Context, attrs efi.VariableAttributes) error {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, p); err != nil {
		return err
	}

	if err := efi.WriteVariable(ctx, physicalPresenceName, physicalPresenceGuid, attrs, buf.Bytes()); err != nil {
		return ppi.ErrOperationFailed
	}

	return nil
}

type physicalPresenceFlags uint32

const (
	ppRequiredForClear      physicalPresenceFlags = (1 << 1)
	ppRequiredForTurnOn     physicalPresenceFlags = (1 << 4)
	ppRequiredForTurnOff    physicalPresenceFlags = (1 << 5)
	ppRequiredForChangeEPS  physicalPresenceFlags = (1 << 6)
	ppRequiredForChangePCRs physicalPresenceFlags = (1 << 7)
)

type physicalPresenceConfig struct {
	StructVersion       uint32
	PPICapabilities     uint32
	PPIVersion          [8]byte
	PPITransitionAction uint32
	UserConfirmation    [64]uint8
}

func (c *physicalPresenceConfig) Version() (ppi.Version, error) {
	term := bytes.IndexByte(c.PPIVersion[:], '\x00')
	if term < 0 {
		return ppi.Version{}, errors.New("invalid PPI version: not NULL terminated")
	}
	return ppi.ParseVersion(string(c.PPIVersion[:term]))
}

func (c *physicalPresenceConfig) TransitionAction() ppi.StateTransitionAction {
	return ppi.StateTransitionAction(c.PPITransitionAction)
}

func (c *physicalPresenceConfig) OperationStatus(op ppi.OperationId) ppi.OperationStatus {
	if op > maxOp {
		return ppi.OperationNotImplemented
	}
	index := 63 - int(op>>1)
	shift := 0
	if op&1 == 1 {
		shift = 4
	}
	return ppi.OperationStatus((c.UserConfirmation[index] >> shift) & 0xf)
}

func varsContext(ctx context.Context, customVars efi.VarsBackend) context.Context {
	if customVars != nil {
		return context.WithValue(ctx, efi.VarsBackendKey{}, customVars)
	}
	return efi.WithDefaultVarsBackend(ctx)
}

type efiPpiImpl struct {
	CustomVars efi.VarsBackend
	Flags      physicalPresenceFlags
	Config     *physicalPresenceConfig
}

func (p *efiPpiImpl) varsContext(ctx context.Context) context.Context {
	return varsContext(ctx, p.CustomVars)
}

func (p *efiPpiImpl) SubmitOperation(op ppi.OperationId, arg *uint32) error {
	ctx := p.varsContext(context.Background())

	pp, attrs, err := readPhysicalPresence(ctx)
	if err != nil {
		return err
	}

	if err := pp.SetRequest(op, arg); err != nil {
		return err
	}

	return pp.Submit(ctx, attrs)
}

func (p *efiPpiImpl) StateTransitionAction() (ppi.StateTransitionAction, error) {
	if p.Config == nil {
		// We can't determine what this is without Tcg2PhysicalPresenceConfig,
		// so just return the most likely (reboot).
		return ppi.StateTransitionRebootRequired, nil
	}

	action := p.Config.TransitionAction()
	if action > ppi.StateTransitionActionOSVendorSpecific {
		return 0, fmt.Errorf("invalid transition action %d", action)
	}

	return action, nil
}

func (p *efiPpiImpl) OperationStatus(op ppi.OperationId) (ppi.OperationStatus, error) {
	if p.Config == nil {
		// Without Tcg2PhysicalPresenceConfig, we return a status for each operation
		// that is based on Tcg2PhysicalPresenceFlags. This only tells us whether
		// user confirmation is required or not, and we also have to guess at the
		// mapping between operation ID and a flag bit. In this case, the result
		// may not be accurate. A consequence of this is that a caller may request
		// an operation that isn't available, but then there will be an error in
		// the response on the next boot.
		var flags physicalPresenceFlags

		switch op {
		case ppi.OperationEnableTPM:
			flags = ppRequiredForTurnOn
		case ppi.OperationDisableTPM:
			flags = ppRequiredForTurnOff
		case ppi.OperationClearTPM:
			flags = ppRequiredForClear
		case ppi.OperationEnableAndClearTPM:
			// Map this to turn on and clear
			flags = ppRequiredForTurnOn | ppRequiredForClear
		case ppi.OperationSetPPRequiredForClearTPM, ppi.OperationSetPPRequiredForChangePCRs,
			ppi.OperationSetPPRequiredForEnableTPM, ppi.OperationSetPPRequiredForDisableTPM,
			ppi.OperationSetPPRequiredForChangeEPS:
			// Setting user confirmation as required shouldn't require user confirmation.
			return ppi.OperationPPNotRequired, nil
		case ppi.OperationClearPPRequiredForClearTPM, ppi.OperationClearPPRequiredForChangePCRs,
			ppi.OperationClearPPRequiredForEnableTPM, ppi.OperationClearPPRequiredForDisableTPM,
			ppi.OperationClearPPRequiredForChangeEPS:
			// Setting user confirmation as not required should require user confirmation.
			return ppi.OperationPPRequired, nil
		case ppi.OperationSetPCRBanks:
			flags = ppRequiredForChangePCRs
		case ppi.OperationChangeEPS:
			flags = ppRequiredForChangeEPS
		default:
			return ppi.OperationNotImplemented, nil
		}

		if p.Flags&flags > 0 {
			return ppi.OperationPPRequired, nil
		}
		return ppi.OperationPPNotRequired, nil
	}

	status := p.Config.OperationStatus(op)
	if status > ppi.OperationPPNotRequired {
		return 0, fmt.Errorf("invalid operation status %d", status)
	}
	return status, nil
}

func (p *efiPpiImpl) OperationResponse() (*ppi.OperationResponse, error) {
	pp, _, err := readPhysicalPresence(p.varsContext(context.Background()))
	if err != nil {
		return nil, err
	}

	if pp.LastPPRequest == 0 {
		return nil, nil
	}

	r := &ppi.OperationResponse{Operation: ppi.OperationId(pp.LastPPRequest)}
	if pp.LastPPResponse != 0 {
		r.Err = ppi.OperationError(pp.LastPPResponse)
	}

	return r, nil
}

func (p *efiPpiImpl) SupportsConfig() bool {
	return p.Config != nil
}

type PPIBackend interface {
	internal_ppi.PPIBackend

	SupportsConfig() bool
}

// NewBackend returns a new backend and the version number of the EFI physical presence interface.
func NewBackend(customVars efi.VarsBackend) (PPIBackend, ppi.Version, error) {
	ctx := varsContext(context.Background(), customVars)

	var flags physicalPresenceFlags
	flagBytes, _, err := efi.ReadVariable(ctx, physicalPresenceFlagsName, physicalPresenceGuid)
	switch {
	case errors.Is(err, efi.ErrVarsUnavailable) || errors.Is(err, efi.ErrVarPermission) || errors.Is(err, efi.ErrVarNotExist):
		return nil, ppi.Version{}, ErrUnavailable
	case err != nil:
		return nil, ppi.Version{}, fmt.Errorf("cannot read %s variable: %w", physicalPresenceFlagsName, err)
	case len(flagBytes) < 4:
		return nil, ppi.Version{}, errors.New("cannot decode EFI_TCG2_PHYSICAL_PRESENCE_FLAGS: not enough bytes")
	default:
		flags = physicalPresenceFlags(binary.LittleEndian.Uint32(flagBytes[:]))
	}

	var config *physicalPresenceConfig
	var version ppi.Version
	configBytes, _, err := efi.ReadVariable(ctx, physicalPresenceConfigName, physicalPresenceGuid)
	switch {
	case errors.Is(err, efi.ErrVarsUnavailable) || errors.Is(err, efi.ErrVarPermission):
		return nil, ppi.Version{}, ErrUnavailable
	case errors.Is(err, efi.ErrVarNotExist):
		// EDK2 and the firmware on my (chrisccoulson's) XPS-15 9520 don't implement this.
		// The code in EDK2 pre-dates the draft v1.4 of the TCG PC Client Platform Physical
		// Presence Interface Specification.
		version = ppi.Version14
	case err != nil:
		return nil, ppi.Version{}, fmt.Errorf("cannot read %s variable: %w", physicalPresenceConfigName, err)
	default:
		r := bytes.NewReader(configBytes)
		var structVersion uint32
		if err := binary.Read(io.NewSectionReader(r, 0, 4), binary.LittleEndian, &structVersion); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, ppi.Version{}, fmt.Errorf("cannot decode EFI_TCG2_PHYSICAL_PRESENCE_CONFIG.StructVersion: %w", err)
		}

		if structVersion != 1 {
			return nil, ppi.Version{}, ErrUnavailable
		}

		config = new(physicalPresenceConfig)
		if err := binary.Read(r, binary.LittleEndian, config); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, ppi.Version{}, fmt.Errorf("cannot decode EFI_TCG2_PHYSICAL_PRESENCE_CONFIG: %w", err)
		}

		version, err = config.Version()
		if err != nil {
			return nil, ppi.Version{}, err
		}
	}

	return &efiPpiImpl{
		CustomVars: customVars,
		Flags:      flags,
		Config:     config,
	}, version, nil
}
