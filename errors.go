// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"fmt"
)

// ResourceDoesNotExistError is returned from TPMContext.WrapHandle if it is called with a handle that does not correspond to a
// resource that is loaded in to the TPM.
type ResourceDoesNotExistError struct {
	Handle Handle
}

func (e ResourceDoesNotExistError) Error() string {
	return fmt.Sprintf("a resource at handle 0x%08x does not exist on the TPM", e.Handle)
}

// InvalidResponseError is returned from any TPMContext method that executes a TPM command if the TPM's response is invalid. An
// invalid response could be one that is shorter than the response header, one with an invalid responseSize field, a payload that is
// shorter than the responseSize field indicates, a payload that unmarshals incorrectly because of an invalid union selector value,
// or an invalid response authorization. Any sessions used in the command that caused this error should be considered invalid and
// should be flushed from the TPM.
type InvalidResponseError struct {
	Command CommandCode
	msg     string
}

func (e *InvalidResponseError) Error() string {
	return fmt.Sprintf("TPM returned an invalid response for command %s: %v", e.Command, e.msg)
}

// TctiError is returned from any TPMContext method if the underlying TCTI returns an error.
type TctiError struct {
	Op  string // The operation that caused the error
	err error
}

func (e *TctiError) Error() string {
	return fmt.Sprintf("cannot complete %s operation on TCTI: %v", e.Op, e.err)
}

func (e *TctiError) Unwrap() error {
	return e.err
}

// TPM1Error is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM response code
// indicates an error from a TPM 1.2 device.
type TPM1Error struct {
	Command CommandCode  // Command code associated with this error
	Code    ResponseCode // Response code
}

func (e *TPM1Error) Error() string {
	return fmt.Sprintf("TPM returned a 1.2 error whilst executing command %s: 0x%08x", e.Command, e.Code)
}

// TPMVendorError is returned from DecodeResponseCode and and TPMContext method that executes a command on the TPM if the TPM response
// code indicates a vendor-specific error.
type TPMVendorError struct {
	Command CommandCode  // Command code associated with this error
	Code    ResponseCode // Response code
}

func (e *TPMVendorError) Error() string {
	return fmt.Sprintf("TPM returned a vendor defined error whilst executing command %s: 0x%08x", e.Command, e.Code)
}

// WarningCode represents a response from the TPM that is not necessarily an error.
type WarningCode ResponseCode

// TPMWarning is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM response
// code indicates a condition that is not necessarily an error.
type TPMWarning struct {
	Command CommandCode // Command code associated with this error
	Code    WarningCode // Warning code
}

func (e *TPMWarning) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned a warning whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := warningCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

// ErrorCode represents an error code from the TPM.
type ErrorCode ResponseCode

// TPMError is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM response
// code indicates an error that is not associated with a handle, parameter or session.
type TPMError struct {
	Command CommandCode // Command code associated with this error
	Code    ErrorCode   // Error code
}

func (e *TPMError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

// TPMParameterError is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM
// response code indicates an error that is associated with a command parameter.
type TPMParameterError struct {
	Command CommandCode // Command code associated with this error
	Code    ErrorCode   // Error code
	Index   int         // Index of the parameter associated with this error in the command parameter area, starting from 1
}

func (e *TPMParameterError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for parameter %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

// TPMSessionError is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM
// response code indicates an error that is associated with a session.
type TPMSessionError struct {
	Command CommandCode // Command code associated with this error
	Code    ErrorCode   // Error code
	Index   int         // Index of the session associated with this error in the authorization area, starting from 1
}

func (e *TPMSessionError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for session %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

// TPMHandleError is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM
// response code indicates an error that is associated with a command handle.
type TPMHandleError struct {
	Command CommandCode // Command code associated with this error
	Code    ErrorCode   // Error code

	// Index is the index of the handle associated with this error in the command handle area, starting from 1. An index of 0 corresponds
	// to an unspecified handle
	Index int
}

func (e *TPMHandleError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for handle %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

const (
	formatMask ResponseCode = 1 << 7

	fmt0ErrorCodeMask ResponseCode = 0x7f
	fmt0VersionMask   ResponseCode = 1 << 8
	fmt0VendorMask    ResponseCode = 1 << 10
	fmt0SeverityMask  ResponseCode = 1 << 11

	fmt1ErrorCodeMask            ResponseCode = 0x3f
	fmt1IndexShift               uint         = 8
	fmt1ParameterIndexMask       ResponseCode = 0xf << fmt1IndexShift
	fmt1HandleOrSessionIndexMask ResponseCode = 0x7 << fmt1IndexShift
	fmt1ParameterMask            ResponseCode = 1 << 6
	fmt1SessionMask              ResponseCode = 1 << 11
)

// DecodeResponseCode decodes the ResponseCode provided via resp. If the specified response code is Success, it returns no error,
// else it returns an error that is appropriate for the response code. The command code is used for adding context to the returned
// error.
func DecodeResponseCode(command CommandCode, resp ResponseCode) error {
	switch {
	case resp == ResponseCode(Success):
		return nil
	case resp&formatMask == 0:
		// Format 0 error codes
		switch {
		case resp&fmt0VersionMask == 0:
			return &TPM1Error{command, resp}
		case resp&fmt0VendorMask > 0:
			return &TPMVendorError{command, resp}
		case resp&fmt0SeverityMask > 0:
			return &TPMWarning{command, WarningCode(resp & fmt0ErrorCodeMask)}
		default:
			return &TPMError{command, ErrorCode(resp & fmt0ErrorCodeMask)}
		}
	default:
		// Format 1 error codes
		switch {
		case resp&fmt1ParameterMask > 0:
			return &TPMParameterError{command, ErrorCode(resp&fmt1ErrorCodeMask) + errorCode1Start, int((resp & fmt1ParameterIndexMask) >> fmt1IndexShift)}
		case resp&fmt1SessionMask > 0:
			return &TPMSessionError{command, ErrorCode(resp&fmt1ErrorCodeMask) + errorCode1Start, int((resp & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
		case resp&fmt1HandleOrSessionIndexMask > 0:
			return &TPMHandleError{command, ErrorCode(resp&fmt1ErrorCodeMask) + errorCode1Start, int((resp & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
		default:
			return &TPMError{command, ErrorCode(resp&fmt1ErrorCodeMask) + errorCode1Start}
		}

	}
}
