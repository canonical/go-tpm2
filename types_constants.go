// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/elliptic"
)

// This file contains types defined in section 6 (Contants) in
// part 2 of the library spec.

// TPMGenerated corresponds to the TPM_GENERATED type.
type TPMGenerated uint32

// AlgorithmId corresponds to the TPM_ALG_ID type.
type AlgorithmId uint16

// ECCCurve corresponds to the TPM_ECC_CURVE type.
type ECCCurve uint16

// GoCurve returns the equivalent elliptic.Curve for this ECC curve.
func (c ECCCurve) GoCurve() elliptic.Curve {
	return eccCurves[c]
}

// CommandCode corresponds to the TPM_CC type.
type CommandCode uint32

// ResponseCode corresponds to the TPM_RC type.
type ResponseCode uint32

const (
	// The lower 7-bits of format-zero error codes are the error number.
	responseCodeE0 ResponseCode = 0x7f

	// The lower 6-bits of format-one error codes are the error number.
	responseCodeE1 ResponseCode = 0x3f

	// Bit 6 of format-one errors is zero for errors associated with a handle
	// or session, or one for errors associated with a parameter.
	responseCodeP ResponseCode = 1 << 6

	// Bit 7 indicates whether the error is a format-zero (0) or format-one code (1)
	responseCodeF ResponseCode = 1 << 7

	// Bit 8 of format-zero errors is zero for TPM1.2 errors and one for TPM2 errors.
	responseCodeV ResponseCode = 1 << 8

	// Bit 10 of format-zero errors is zero for TCG defined errors and one for vendor
	// defined error.
	responseCodeT ResponseCode = 1 << 10

	// Bit 11 of format-zero errors is zero for errors and one for warnings.
	responseCodeS ResponseCode = 1 << 11

	responseCodeIndex      uint8 = 0xf
	responseCodeIndexShift uint8 = 8

	// Bits 8 to 11 of format-one errors represent the parameter number if P is set
	// or the handle or session number otherwise.
	responseCodeN ResponseCode = ResponseCode(responseCodeIndex) << responseCodeIndexShift
)

// E returns the E field of the response code, corresponding to the error number.
func (rc ResponseCode) E() uint8 {
	if rc.F() {
		return uint8(rc & responseCodeE1)
	}
	return uint8(rc & responseCodeE0)
}

// F returns the F field of the response code, corresponding to the format.
// If it is set, this is a format-one response code. If it is not set, this
// is a format-zero response code.
func (rc ResponseCode) F() bool {
	return rc&responseCodeF != 0
}

// V returns the V field of the response code. If this is set in a format-zero
// response code, then it is a TPM2 code returned when the response tag is
// TPM_ST_NO_SESSIONS. If it is not set in a format-zero response code, then it
// is a TPM1.2 code returned when the response tag is TPM_TAG_RSP_COMMAND.
func (rc ResponseCode) V() bool {
	return rc&responseCodeV != 0
}

// T returns the T field of the response code. If this is set in a format-zero
// response code, then the code is defined by the TPM vendor. If it is not set
// in a format-zero response code, then the code is defined by the TCG.
func (rc ResponseCode) T() bool {
	return rc&responseCodeT != 0
}

// S returns the S field of the response code. If this is set in a format-zero
// response code, then the code indicates a warning. If it is not set in a
// format-zero response code, then the code indicates an error.
func (rc ResponseCode) S() bool {
	return rc&responseCodeS != 0
}

// P returns the P field of the response code. If this is set in a format-one
// response code, then the code is associated with a command parameter. If it is
// not set in a format-one error code, then the code is associated with a command
// handle or session.
func (rc ResponseCode) P() bool {
	return rc&responseCodeP != 0
}

// N returns the N field of the response code. If the P field is set in a
// format-one response code, then this indicates the parameter number from 0x1
// to 0xf. If the P field is not set in a format-one response code, then the
// lower 3 bits indicate the handle or session number (0x1 to 0x7 for handles
// and 0x9 to 0xf for sessions).
func (rc ResponseCode) N() uint8 {
	return uint8(rc & responseCodeN >> responseCodeIndexShift)
}

// ArithmeticOp corresponds to the TPM_EO type.
type ArithmeticOp uint16

// StructTag corresponds to the TPM_ST type.
type StructTag uint16

// StartupType corresponds to the TPM_SU type.
type StartupType uint16

// SessionType corresponds to the TPM_SE type.
type SessionType uint8

// Capability corresponds to the TPM_CAP type.
type Capability uint32

// Property corresponds to the TPM_PT type.
type Property uint32

// PropertyPCR corresponds to the TPM_PT_PCR type.
type PropertyPCR uint32
