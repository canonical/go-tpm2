// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package ppi provides a way of interacting with the TCG PC Client Physical Presence Interface
*/
package ppi

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/canonical/go-tpm2"
)

var (
	// ErrOperationUnsupported indicates that the requested physical presence
	// operation is unsupported.
	ErrOperationUnsupported = errors.New("the requested PPI operation is unsupported")

	// ErrOperationFailed indicates that the requested physical presence
	// operation request failed.
	ErrOperationFailed = errors.New("the PPI operation request failed")
)

// OperationError represents an error associated with a PPI operation.
type OperationError uint32

func (e OperationError) Error() string {
	switch {
	case e == 0xfffffff0:
		return "user abort"
	case e == 0xfffffff1:
		return "BIOS failure"
	case e > 0 && e < 0x1000:
		return fmt.Sprintf("TPM error: %#x", e)
	case e == 0:
		return "success"
	default:
		return fmt.Sprintf("%#x", e)
	}
}

// OperationId corresponds to a physical presence operation.
type OperationId uint32

const (
	NoOperation OperationId = 0

	// OperationEnableTPM corresponds to the Enable operation.
	OperationEnableTPM OperationId = 1

	// OperationDisableTPM corresponds to the Enable operation.
	OperationDisableTPM OperationId = 2

	// OperationClearTPM corresponds to the Clear operation.
	OperationClearTPM OperationId = 5

	// OperationEnableAndClearTPM corresponds to the Enable + Clear operation for TPM2 devices, or
	// the Clear + Enable + Activate operation for TPM1.2 devices.
	OperationEnableAndClearTPM OperationId = 14

	// OperationSetPPRequiredForClearTPM corresponds to the SetPPRequiredForClear_True operation
	// for TPM2 devices, or the SetNoPPIClear_False for TPM1.2 devices.
	OperationSetPPRequiredForClearTPM OperationId = 17

	// OperationClearPPRequiredForClearTPM corresponds to the SetPPRequiredForClear_False
	// operation for TPM2 devices, or the SetNoPPIClear_True for TPM1.2 devices.
	OperationClearPPRequiredForClearTPM OperationId = 18

	// OperationSetPCRBanks corresponds to the SetPCRBanks operation for TPM2 devices.
	OperationSetPCRBanks OperationId = 23

	// OperationChangeEPS corresponds to the ChangeEPS operation for TPM2 devices.
	OperationChangeEPS OperationId = 24

	// OperationClearPPRequiredForChangePCRs corresponds to the SetPPRequiredForChangePCRs_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForChangePCRs OperationId = 25

	// OperationSetPPRequiredForChangePCRs corresponds to the SetPPRequiredForChangePCRs_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForChangePCRs OperationId = 26

	// OperationClearPPRequiredForEnableTPM corresponds to the SetPPRequiredForTurnOn_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForEnableTPM OperationId = 27

	// OperationSetPPRequiredForEnableTPM corresponds to the SetPPRequiredForTurnOn_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForEnableTPM OperationId = 28

	// OperationClearPPRequiredForDisableTPM corresponds to the SetPPRequiredForTurnOff_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForDisableTPM OperationId = 29

	// OperationSetPPRequiredForDisableTPM corresponds to the SetPPRequiredForTurnOff_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForDisableTPM OperationId = 30

	// OperationClearPPRequiredForChangeEPS corresponds to the SetPPRequiredForChangeEPS_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForChangeEPS OperationId = 31

	// OperationSetPPRequiredForChangeEPS corresponds to the SetPPRequiredForChangeEPS_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForChangeEPS OperationId = 32

	//OperationLogAllDigests                                           = 33
	//OperationDisableEndorsementEnableStorageHierarchy                = 34
	//OperationEnableBlockSIDFunc                                      = 96
	//OperationDisableBlockSIDFunc                                     = 97
	//OperationSetPPRequiredForEnableBlockSIDFuncTrue                  = 98
	//OperationSetPPRequiredForEnableBlockSIDFuncFalse                 = 99
	//OperationSetPPRequiredForDisableBlockSIDFuncTrue                 = 100
	//OperationSetPPRequiredForDisableBlockSIDFuncFalse                = 101
)

type ppControl struct {
	enable  OperationId
	disable OperationId
}

var ppControlMap = map[OperationId]ppControl{
	OperationEnableTPM: ppControl{
		enable:  OperationSetPPRequiredForEnableTPM,
		disable: OperationClearPPRequiredForEnableTPM},
	OperationDisableTPM: ppControl{
		enable:  OperationSetPPRequiredForDisableTPM,
		disable: OperationClearPPRequiredForDisableTPM},
	OperationClearTPM: ppControl{
		enable:  OperationSetPPRequiredForClearTPM,
		disable: OperationClearPPRequiredForClearTPM},
	OperationSetPCRBanks: ppControl{
		enable:  OperationSetPPRequiredForChangePCRs,
		disable: OperationClearPPRequiredForChangePCRs},
	OperationChangeEPS: ppControl{
		enable:  OperationSetPPRequiredForChangeEPS,
		disable: OperationClearPPRequiredForChangeEPS}}

// ClearPPRequiredOperationId returns the operation ID used to disable the physical presence
// requirement for this operation. If there isn't a corresponding operation for this,
// NoOperation will be returned.
func (op OperationId) ClearPPRequiredOperationId() OperationId {
	control, exists := ppControlMap[op]
	if !exists {
		return NoOperation
	}
	return control.disable
}

// SetPPRequiredOperationId returns the operation ID used to enable the physical presence
// requirement for this operation. If there isn't a corresponding operation for this,
// NoOperation will be returned.
func (op OperationId) SetPPRequiredOperationId() OperationId {
	control, exists := ppControlMap[op]
	if !exists {
		return NoOperation
	}
	return control.enable
}

// OperationStatus indicates the status of a physical presence operation.
type OperationStatus uint32

func (s OperationStatus) String() string {
	switch s {
	case OperationNotImplemented:
		return "Not implemented"
	case OperationFirmwareOnly:
		return "BIOS only"
	case OperationBlockedByFirmwareConfig:
		return "Blocked for OS by BIOS"
	case OperationPPRequired:
		return "User required"
	case OperationPPNotRequired:
		return "User not required"
	default:
		return "invalid operation status: " + strconv.Itoa(int(s))
	}
}

const (
	// OperationNotImplemented indicates that an operation is not implemented.
	OperationNotImplemented OperationStatus = 0

	// OperationFirmwareOnly indicates that an operation is supported but it
	// cannot be requested from the OS.
	OperationFirmwareOnly OperationStatus = 1

	// OperationBlockedByFirmwareConfig indicates that an operation is supported
	// but it cannot be requested from the OS because the current firmware settings
	// don't permit this.
	OperationBlockedByFirmwareConfig OperationStatus = 2

	// OperationPPRequired indicates that an operation can be requested from the
	// OS but the operation requires approval from a physically present user.
	OperationPPRequired OperationStatus = 3

	// OperationPPNotRequired indicates that an operation can be requested from
	// the OS without approval from a physically present user.
	OperationPPNotRequired OperationStatus = 4
)

// StateTransitionAction describes the action required to transition to the pre-OS
// environment in order for the pending physical presence operation request to be executed.
type StateTransitionAction uint32

func (a StateTransitionAction) String() string {
	switch a {
	case StateTransitionNoAction:
		return "None"
	case StateTransitionShutdownRequired:
		return "Shutdown"
	case StateTransitionRebootRequired:
		return "Reboot"
	case StateTransitionActionOSVendorSpecific:
		return "OS Vendor-specific"
	default:
		return "invalid state transition action: " + strconv.Itoa(int(a))
	}
}

const (
	// StateTransitionNoAction indicates that no action is required.
	StateTransitionNoAction StateTransitionAction = 0

	// StateTransitionShutdownRequired indicates that the OS must shut down
	// the machine in order to execute a pending operation.
	StateTransitionShutdownRequired StateTransitionAction = 1

	// StateTransitionRebootRequired indicates that the OS must perform a warm
	// reboot of the machine in order to execute a pending operation.
	StateTransitionRebootRequired StateTransitionAction = 2

	// StateTransitionActionOSVendorSpecific indicates that an OS-specific
	// action can take place.
	StateTransitionActionOSVendorSpecific StateTransitionAction = 3
)

// Version indicates the version of the physical presence interface.
type Version struct {
	Major, Minor uint
}

// ParseVersion parses the supplied physical presence interface version string.
func ParseVersion(str string) (Version, error) {
	var version Version
	if _, err := fmt.Sscanf(str, "%d.%d", &version.Major, &version.Minor); err != nil {
		return Version{}, err
	}
	return version, nil
}

// Compare compares the supplied version with this version. If they are both
// equal, then 0 is returned. If v < other, then -1 is returned. If v > other,
// then 1 is returned.
func (v *Version) Compare(other Version) int {
	switch {
	case *v == other:
		return 0
	case v.Major < other.Major:
		return -1
	case v.Major > other.Major:
		return 1
	case v.Minor < other.Minor:
		return -1
	case v.Minor > other.Minor:
		return 1
	}
	panic("not reached")
}

// String implements [fmt.Stringer].
func (v *Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

var (
	Version10 = Version{Major: 1, Minor: 0}
	Version11 = Version{Major: 1, Minor: 1}
	Version12 = Version{Major: 1, Minor: 2}
	Version13 = Version{Major: 1, Minor: 3}
)

// OperationResponse provides the response of the last operation executed by the pre-OS
// environment.
type OperationResponse struct {
	Operation OperationId
	Err       error // Will be set if the operation failed.
}

// HashAlgorithms is a bit field of digest algorithms.
type HashAlgorithms uint32

// MakeHashAlgorithms coverts the supplied list of digest algorithms into a bit field.
func MakeHashAlgorithms(algs ...tpm2.HashAlgorithmId) HashAlgorithms {
	var bits HashAlgorithms
	for _, alg := range algs {
		switch alg {
		case tpm2.HashAlgorithmSHA1:
			bits |= HashAlgorithmSHA1
		case tpm2.HashAlgorithmSHA256:
			bits |= HashAlgorithmSHA256
		case tpm2.HashAlgorithmSHA384:
			bits |= HashAlgorithmSHA384
		case tpm2.HashAlgorithmSHA512:
			bits |= HashAlgorithmSHA512
		case tpm2.HashAlgorithmSHA3_256:
			bits |= HashAlgorithmSHA3_256
		case tpm2.HashAlgorithmSHA3_384:
			bits |= HashAlgorithmSHA3_384
		case tpm2.HashAlgorithmSHA3_512:
			bits |= HashAlgorithmSHA3_512
		}
	}
	return bits
}

const (
	HashAlgorithmSHA1 HashAlgorithms = 1 << iota
	HashAlgorithmSHA256
	HashAlgorithmSHA384
	HashAlgorithmSHA512
	HashAlgorithmSM3_256
	HashAlgorithmSHA3_256
	HashAlgorithmSHA3_384
	HashAlgorithmSHA3_512
)

// PPI provides a way to interact with the physical presence interface associated with a TPM.
type PPI interface {
	Version() Version

	// StateTransitionAction returns the action required to transition the device to the pre-OS
	// environment in order to complete the pending physical presence operation request.
	StateTransitionAction() (StateTransitionAction, error)

	// OperationStatus returns the status of the specified operation.
	OperationStatus(op OperationId) (OperationStatus, error)

	// EnableTPM requests that the TPM be enabled by the platform firmware.
	// For TPM1.2 devices, the TPM is enabled by executing the TPM_PhysicalEnable command.
	// For TPM2 devices, the TPM is enabled by not disabling the storage and endorsement hierarchies
	// with TPM2_HierarchyControl after TPM2_Startup.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	EnableTPM() error

	// DisableTPM requests that the TPM be disabled by the platform firmware.
	// For TPM1.2 devices, the TPM is disabled by executing the TPM_PhysicalDisable command.
	// For TPM2 devices, the TPM is disabled by disabling the storage and endorsement hierarchies
	// with TPM2_HierarchyControl after TPM2_Startup.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	DisableTPM() error

	// ClearTPM requests that the TPM is cleared by the platform firmware.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	ClearTPM() error

	// EnableAndClearTPM requests that the TPM is enabled and cleared by the platform firmware.
	// For TPM1.2 devices, this also activates the device with the TPM_PhysicalSetDeactivated
	// command.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	EnableAndClearTPM() error

	// SetPCRBanks requests that the PCR banks associated with the specified algorithms are enabled
	// by the platform firmware.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	SetPCRBanks(algs ...tpm2.HashAlgorithmId) error

	// ChangeEPS requests that the TPM's endorsement primary seed is changed by the platform firmware.
	// This is only implemented for TPM2 devices.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	ChangeEPS() error

	// SetPPRequiredForOperation requests that approval from a physically present user should be
	// required for the specified operation.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	SetPPRequiredForOperation(op OperationId) error

	// ClearPPRequiredForOperation requests that approval from a physically present user should not be
	// required for the specified operation.
	// The caller needs to perform the action described by [PPI.StateTransitionAction] in
	// order to complete the request.
	ClearPPRequiredForOperation(op OperationId) error

	// OperationResponse returns the response to the previously executed operation from the pre-OS
	// environment.
	OperationResponse() (*OperationResponse, error)
}
