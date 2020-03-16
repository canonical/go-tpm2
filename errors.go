// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"fmt"

	"golang.org/x/xerrors"
)

const (
	// AnyCommandCode is used to match any command code when using {As,Is}TPMError, {As,Is}TPMHandleError, {As,Is}TPMParameterError,
	// {As,Is}TPMSessionError and {As,Is}TPMWarning.
	AnyCommandCode CommandCode = 0xc0000000

	// AnyErrorCode is used to match any error code when using {As,Is}TPMError, {As,Is}TPMHandleError, {As,Is}TPMParameterError and
	// {As,Is}TPMSessionError.
	AnyErrorCode ErrorCode = 0x100

	// AnyHandle is used to match any handle when using {As,Is}ResourceUnavailableError.
	AnyHandle Handle = 0xffffffff

	// AnyHandleIndex is used to match any handle when using {As,Is}TPMHandleError.
	AnyHandleIndex int = -1

	// AnyParameterIndex is used to match any parameter when using {As,Is}TPMParameterError.
	AnyParameterIndex int = -1

	// AnySessionIndex is used to match any session when using {As,Is}TPMSessionError.
	AnySessionIndex int = -1

	// AnyWarningCode is used to match any warning code when using {As,Is}TPMWarning.
	AnyWarningCode WarningCode = 0x80
)

// ResourceUnavailableError is returned from TPMContext.GetOrCreateResourceContext or TPMContext.GetOrCreateSessionContext if it is
// called with a handle that does not correspond to a resource that is available on the TPM. This could be because the resource
// doesn't exist on the TPM, or it lives within a hierarchy that is disabled.
type ResourceUnavailableError struct {
	Handle Handle
}

func (e ResourceUnavailableError) Error() string {
	return fmt.Sprintf("a resource at handle 0x%08x is not available on the TPM", e.Handle)
}

// InvalidResponseError is returned from any TPMContext method that executes a TPM command if the TPM's response is invalid. An
// invalid response could be one that is shorter than the response header, one with an invalid responseSize field, a payload that is
// shorter than the responseSize field indicates, a payload that unmarshals incorrectly because of an invalid union selector value,
// or an invalid response authorization.
//
// Any sessions used in the command that caused this error should be considered invalid.
//
// If any function that executes a command which allocates objects on the TPM returns this error, it is possible that these objects
// were allocated and now exist on the TPM without a corresponding HandleContext being created or any knowledge of the handle of
// the object created.
//
// If any function that executes a command which removes objects from the TPM returns this error, it is possible that these objects
// were removed from the TPM. Any associated HandleContexts should be considered stale after this error.
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
// response code indicates an error that is associated with a command parameter. It wraps a *TPMError.
type TPMParameterError struct {
	*TPMError
	Index int // Index of the parameter associated with this error in the command parameter area, starting from 1
}

func (e *TPMParameterError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for parameter %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func (e *TPMParameterError) Unwrap() error {
	return e.TPMError
}

// TPMSessionError is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM
// response code indicates an error that is associated with a session. It wraps a *TPMError.
type TPMSessionError struct {
	*TPMError
	Index int // Index of the session associated with this error in the authorization area, starting from 1
}

func (e *TPMSessionError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for session %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func (e *TPMSessionError) Unwrap() error {
	return e.TPMError
}

// TPMHandleError is returned from DecodeResponseCode and any TPMContext method that executes a command on the TPM if the TPM
// response code indicates an error that is associated with a command handle. It wraps a *TPMError.
type TPMHandleError struct {
	*TPMError
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

func (e *TPMHandleError) Unwrap() error {
	return e.TPMError
}

func AsResourceUnavailableError(err error, handle Handle, out *ResourceUnavailableError) bool {
	return xerrors.As(err, out) && (handle == AnyHandle || (*out).Handle == handle)
}

// IsResourceUnavailableError indicates whether an error is a ResourceUnavailableError with the specified handle. To test for any
// handle, use AnyHandle.
func IsResourceUnavailableError(err error, handle Handle) bool {
	var e ResourceUnavailableError
	return AsResourceUnavailableError(err, handle, &e)
}

// AsTPMError indicates whether the error or any error within its chain is a *TPMError with the specified ErrorCode and CommandCode,
// and sets out to the value of error if it is. To test for any error code, use AnyErrorCode. To test for any command code, use
// AnyCommandCode. This will panic if out is nil.
func AsTPMError(err error, code ErrorCode, command CommandCode, out **TPMError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command)
}

// IsTPMError indicates whether the error or any error within its chain is a *TPMError with the specified ErrorCode and CommandCode.
// To test for any error code, use AnyErrorCode. To test for any command code, use AnyCommandCode.
func IsTPMError(err error, code ErrorCode, command CommandCode) bool {
	var e *TPMError
	return AsTPMError(err, code, command, &e)
}

// AsTPMHandleError indicates whether the error or any error within its chain is a *TPMHandleError with the specified ErrorCode,
// CommandCode and handle index, and sets out to the value of error if it is. To test for any error code, use AnyErrorCode. To test
// for any command code, use AnyCommandCode. To test for any handle index, use AnyHandleIndex. This will panic if out is nil.
func AsTPMHandleError(err error, code ErrorCode, command CommandCode, handle int, out **TPMHandleError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command) && (handle == AnyHandleIndex || (*out).Index == handle)
}

// IsTPMHandleError indicates whether the error or any error within its chain is a *TPMHandleError with the specified ErrorCode,
// CommandCode and handle index. To test for any error code, use AnyErrorCode. To test for any command code, use AnyCommandCode. To
// test for any handle index, use AnyHandleIndex.
func IsTPMHandleError(err error, code ErrorCode, command CommandCode, handle int) bool {
	var e *TPMHandleError
	return AsTPMHandleError(err, code, command, handle, &e)
}

// AsTPMParameterError indicates whether the error or any error within its chain is a *TPMParameterError with the specified ErrorCode,
// CommandCode and parameter index, and sets out to the value of error if it is. To test for any error code, use AnyErrorCode. To test
// for any command code, use AnyCommandCode. To test for any parameter index, use AnyParameterIndex. This will panic if out is nil.
func AsTPMParameterError(err error, code ErrorCode, command CommandCode, param int, out **TPMParameterError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command) && (param == AnyParameterIndex || (*out).Index == param)
}

// IsTPMParameterError indicates whether the error or any error within its chain is a *TPMParameterError with the specified ErrorCode,
// CommandCode and parameter index. To test for any error code, use AnyErrorCode. To test for any command code, use AnyCommandCode.
// To test for any parameter index, use AnyParameterIndex.
func IsTPMParameterError(err error, code ErrorCode, command CommandCode, param int) bool {
	var e *TPMParameterError
	return AsTPMParameterError(err, code, command, param, &e)
}

// AsTPMSessionError indicates whether the error or any error within its chain is a *TPMSessionError with the specified ErrorCode,
// CommandCode and session index, and sets out to the value of error if it is. To test for any error code, use AnyErrorCode. To test
// for any command code, use AnyCommandCode. To test for any session index, use AnySessionIndex. This will panic if out is nil.
func AsTPMSessionError(err error, code ErrorCode, command CommandCode, session int, out **TPMSessionError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command) && (session == AnySessionIndex || (*out).Index == session)
}

// IsTPMSessionError indicates whether the error or any error within its chain is a *TPMSessionError with the specified ErrorCode,
// CommandCode and session index. To test for any error code, use AnyErrorCode. To test for any command code, use AnyCommandCode. To
// test for any session index, use AnySessionIndex.
func IsTPMSessionError(err error, code ErrorCode, command CommandCode, session int) bool {
	var e *TPMSessionError
	return AsTPMSessionError(err, code, command, session, &e)
}

// AsTPMWarning indicates whether the error or any error within its chain is a *TPMWarning with the specified WarningCode and
// CommandCode, and sets out to the value of error if it is. To test for any warning code, use AnyWarningCode. To test for any command
// code, use AnyCommandCode. This will panic if out is nil.
func AsTPMWarning(err error, code WarningCode, command CommandCode, out **TPMWarning) bool {
	return xerrors.As(err, out) && (code == AnyWarningCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command)
}

// IsTPMWarning indicates whether the error or any error within its chain is a *TPMWarning with the specified WarningCode and
// CommandCode. To test for any warning code, use AnyWarningCode. To test for any command code, use AnyCommandCode.
func IsTPMWarning(err error, code WarningCode, command CommandCode) bool {
	var e *TPMWarning
	return AsTPMWarning(err, code, command, &e)
}

const (
	formatMask ResponseCode = 1 << 7 // Bit 7 indicates whether the error is a format-zero or format-one code

	fmt0ErrorCodeMask ResponseCode = 0x7f    // Format-zero error numbers are 7-bits
	fmt0VersionMask   ResponseCode = 1 << 8  // Bit 8 of format-zero errors is zero for TPM1.2 errors and one for TPM2 errors
	fmt0VendorMask    ResponseCode = 1 << 10 // Bit 10 of format-zero errors is zero for TCG defined errors and one for vendor defined errors
	fmt0SeverityMask  ResponseCode = 1 << 11 // BIt 11 of format-zero errors is zero for errors and one for warnings

	fmt1ErrorCodeMask            ResponseCode = 0x3f                  // Format-one error numbers are 6-bits
	fmt1IndexShift               uint         = 8                     // Offset of the index field in format-one errors
	fmt1ParameterIndexMask       ResponseCode = 0xf << fmt1IndexShift // Parameter indices in format-one errors are 4-bits
	fmt1HandleOrSessionIndexMask ResponseCode = 0x7 << fmt1IndexShift // Handle or session indices in format-one errors are 3-bits
	// Bit 6 of format-one errors is zero for errors associated with a handle or session, and one for errors associated with a parameter
	fmt1ParameterMask ResponseCode = 1 << 6
	// Bit 11 of format-one errors associated with a handle or session (bit 3 of the index) is zero for errors associated with a handle
	// and one for errors associated with a session.
	fmt1SessionMask ResponseCode = 1 << 11
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
		err := &TPMError{command, ErrorCode(resp&fmt1ErrorCodeMask) + errorCode1Start}
		switch {
		case resp&fmt1ParameterMask > 0:
			return &TPMParameterError{err, int((resp & fmt1ParameterIndexMask) >> fmt1IndexShift)}
		case resp&fmt1SessionMask > 0:
			return &TPMSessionError{err, int((resp & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
		case resp&fmt1HandleOrSessionIndexMask > 0:
			return &TPMHandleError{err, int((resp & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
		default:
			return err
		}

	}
}
