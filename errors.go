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
	// AnyCommandCode is used to match any command code when using {As,Is}TPMError,
	// {As,Is}TPMHandleError, {As,Is}TPMParameterError, {As,Is}TPMSessionError and {As,Is}TPMWarning.
	AnyCommandCode CommandCode = 0xc0000000

	// AnyErrorCode is used to match any error code when using {As,Is}TPMError,
	// {As,Is}TPMHandleError, {As,Is}TPMParameterError and {As,Is}TPMSessionError.
	AnyErrorCode ErrorCode = 0xff

	// AnyHandle is used to match any handle when using {As,Is}ResourceUnavailableError.
	AnyHandle Handle = 0xffffffff

	// AnyHandleIndex is used to match any handle when using {As,Is}TPMHandleError.
	AnyHandleIndex int = -1

	// AnyParameterIndex is used to match any parameter when using {As,Is}TPMParameterError.
	AnyParameterIndex int = -1

	// AnySessionIndex is used to match any session when using {As,Is}TPMSessionError.
	AnySessionIndex int = -1

	// AnyWarningCode is used to match any warning code when using {As,Is}TPMWarning.
	AnyWarningCode WarningCode = 0xff
)

// ResourceUnavailableError is returned from TPMContext.CreateResourceContextFromTPM if
// it is called with a handle that does not correspond to a resource that is available
// on the TPM. This could be because the resource doesn't exist on the TPM, or it lives within
// a hierarchy that is disabled.
type ResourceUnavailableError struct {
	Handle Handle
}

func (e ResourceUnavailableError) Error() string {
	return fmt.Sprintf("a resource at handle 0x%08x is not available on the TPM", e.Handle)
}

// InvalidResponseError is returned from any TPMContext method that executes a TPM command
// if the TPM's response is invalid. An invalid response could be one that is shorter than
// the response header, one with an invalid responseSize field, a payload size that doesn't
// match what the responseSize field indicates, a payload that unmarshals incorrectly or an
// invalid response authorization.
//
// Any sessions used in the command that caused this error should be considered invalid.
//
// If any function that executes a command which allocates objects on the TPM returns this
// error, it is possible that these objects were allocated and now exist on the TPM without
// a corresponding HandleContext being created or any knowledge of the handle of the object
// created.
//
// If any function that executes a command which removes objects from the TPM returns this
// error, it is possible that these objects were removed from the TPM. Any associated
// HandleContexts should be considered stale after this error.
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

// TPM1Error is returned from DecodeResponseCode and any TPMContext method that executes a
// command on the TPM if the TPM response code indicates an error from a TPM 1.2 device.
type TPM1Error struct {
	Command CommandCode  // Command code associated with this error
	Code    ResponseCode // Response code
}

func (e *TPM1Error) Error() string {
	return fmt.Sprintf("TPM returned a 1.2 error whilst executing command %s: 0x%08x", e.Command, e.Code)
}

// TPMVendorError is returned from DecodeResponseCode and and TPMContext method that executes
// a command on the TPM if the TPM response code indicates a vendor-specific error.
type TPMVendorError struct {
	Command CommandCode  // Command code associated with this error
	Code    ResponseCode // Response code
}

func (e *TPMVendorError) Error() string {
	return fmt.Sprintf("TPM returned a vendor defined error whilst executing command %s: 0x%08x", e.Command, e.Code)
}

// WarningCode represents a response from the TPM that is not necessarily an
// error. It represents TCG defined format 0 errors that are warnings
// (represented by response codes 0x900 to 0x97f).
type WarningCode uint8

// TPMWarning is returned from DecodeResponseCode and any TPMContext method that executes
// a command on the TPM if the TPM response code indicates a condition that is not necessarily
// an error.
type TPMWarning struct {
	Command CommandCode // Command code associated with this error
	Code    WarningCode // Warning code
}

func (e *TPMWarning) ResponseCode() ResponseCode {
	return responseCodeS | responseCodeV | ResponseCode(e.Code)
}

func (e *TPMWarning) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned a warning whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := warningCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

// ErrorCode represents an error code from the TPM. This type represents
// TCG defined format 0 errors with the exception of warnings (represented
// by response codes 0x100 to 0x17f), and format 1 errors (represented by
// response codes with bit 7 set). Format 0 error numbers are 7 bits wide
// and are represented by codes 0x00 to 0x7f. Format 1 errors numbers are
// 6 bits wide and are represented by codes 0x80 to 0xbf.
type ErrorCode uint8

// TPMError is returned from DecodeResponseCode and any TPMContext method that
// executes a command on the TPM if the TPM response code indicates an error that
// is not associated with a handle, parameter or session.
type TPMError struct {
	Command CommandCode // Command code associated with this error
	Code    ErrorCode   // Error code
}

func (e *TPMError) ResponseCode() ResponseCode {
	switch {
	case e.Code == ErrorBadTag:
		return ResponseBadTag
	case e.Code >= 0x80:
		return responseCodeF | (ResponseCode(e.Code) & 0x3f)
	default:
		return responseCodeV | (ResponseCode(e.Code) & 0x7f)
	}
}

func (e *TPMError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

// TPMParameterError is returned from DecodeResponseCode and any TPMContext method
// that executes a command on the TPM if the TPM response code indicates an error
// that is associated with a command parameter. It wraps a *TPMError.
type TPMParameterError struct {
	*TPMError
	Index int // Index of the parameter associated with this error in the command parameter area, starting from 1
}

func (e *TPMParameterError) ResponseCode() ResponseCode {
	return (((0xf & ResponseCode(e.Index)) << 8) & responseCodeN) | responseCodeF | responseCodeP | ResponseCode(e.Code)
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

// TPMSessionError is returned from DecodeResponseCode and any TPMContext method
// that executes a command on the TPM if the TPM response code indicates an error
// that is associated with a session. It wraps a *TPMError.
type TPMSessionError struct {
	*TPMError
	Index int // Index of the session associated with this error in the authorization area, starting from 1
}

func (e *TPMSessionError) ResponseCode() ResponseCode {
	return (((0x8 | (0x7 & ResponseCode(e.Index))) << 8) & responseCodeN) | responseCodeF | ResponseCode(e.Code)
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

// TPMHandleError is returned from DecodeResponseCode and any TPMContext method that
// executes a command on the TPM if the TPM response code indicates an error that is
// associated with a command handle. It wraps a *TPMError.
type TPMHandleError struct {
	*TPMError
	// Index is the index of the handle associated with this error in the command handle area, starting from 1. An index of 0 corresponds
	// to an unspecified handle
	Index int
}

func (e *TPMHandleError) ResponseCode() ResponseCode {
	return (((0x7 & ResponseCode(e.Index)) << 8) & responseCodeN) | responseCodeF | ResponseCode(e.Code)
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

// IsResourceUnavailableError indicates whether an error is a ResourceUnavailableError with
// the specified handle. To test for any handle, use AnyHandle.
func IsResourceUnavailableError(err error, handle Handle) bool {
	var e ResourceUnavailableError
	return AsResourceUnavailableError(err, handle, &e)
}

// AsTPMError indicates whether the error or any error within its chain is a *TPMError with
// the specified ErrorCode and CommandCode, and sets out to the value of error if it is. To
// test for any error code, use AnyErrorCode. To test for any command code, use AnyCommandCode.
// This will panic if out is nil.
func AsTPMError(err error, code ErrorCode, command CommandCode, out **TPMError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command)
}

// IsTPMError indicates whether the error or any error within its chain is a *TPMError with
// the specified ErrorCode and CommandCode. To test for any error code, use AnyErrorCode. To
// test for any command code, use AnyCommandCode.
func IsTPMError(err error, code ErrorCode, command CommandCode) bool {
	var e *TPMError
	return AsTPMError(err, code, command, &e)
}

// AsTPMHandleError indicates whether the error or any error within its chain is a
// *TPMHandleError with the specified ErrorCode, CommandCode and handle index, and sets out
// to the value of error if it is. To test for any error code, use AnyErrorCode. To test
// for any command code, use AnyCommandCode. To test for any handle index, use AnyHandleIndex.
// This will panic if out is nil.
func AsTPMHandleError(err error, code ErrorCode, command CommandCode, handle int, out **TPMHandleError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command) && (handle == AnyHandleIndex || (*out).Index == handle)
}

// IsTPMHandleError indicates whether the error or any error within its chain is a
// *TPMHandleError with the specified ErrorCode, CommandCode and handle index. To test for
// any error code, use AnyErrorCode. To test for any command code, use AnyCommandCode. To
// test for any handle index, use AnyHandleIndex.
func IsTPMHandleError(err error, code ErrorCode, command CommandCode, handle int) bool {
	var e *TPMHandleError
	return AsTPMHandleError(err, code, command, handle, &e)
}

// AsTPMParameterError indicates whether the error or any error within its chain is a
// *TPMParameterError with the specified ErrorCode, CommandCode and parameter index, and sets
// out to the value of error if it is. To test for any error code, use AnyErrorCode. To test
// for any command code, use AnyCommandCode. To test for any parameter index, use
// AnyParameterIndex. This will panic if out is nil.
func AsTPMParameterError(err error, code ErrorCode, command CommandCode, param int, out **TPMParameterError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command) && (param == AnyParameterIndex || (*out).Index == param)
}

// IsTPMParameterError indicates whether the error or any error within its chain is a
// *TPMParameterError with the specified ErrorCode, CommandCode and parameter index. To test
// for any error code, use AnyErrorCode. To test for any command code, use AnyCommandCode.
// To test for any parameter index, use AnyParameterIndex.
func IsTPMParameterError(err error, code ErrorCode, command CommandCode, param int) bool {
	var e *TPMParameterError
	return AsTPMParameterError(err, code, command, param, &e)
}

// AsTPMSessionError indicates whether the error or any error within its chain is a
// *TPMSessionError with the specified ErrorCode, CommandCode and session index, and sets out
// to the value of error if it is. To test for any error code, use AnyErrorCode. To test
// for any command code, use AnyCommandCode. To test for any session index, use AnySessionIndex.
// This will panic if out is nil.
func AsTPMSessionError(err error, code ErrorCode, command CommandCode, session int, out **TPMSessionError) bool {
	return xerrors.As(err, out) && (code == AnyErrorCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command) && (session == AnySessionIndex || (*out).Index == session)
}

// IsTPMSessionError indicates whether the error or any error within its chain is a
// *TPMSessionError with the specified ErrorCode, CommandCode and session index. To test for any
// error code, use AnyErrorCode. To test for any command code, use AnyCommandCode. To test for
// any session index, use AnySessionIndex.
func IsTPMSessionError(err error, code ErrorCode, command CommandCode, session int) bool {
	var e *TPMSessionError
	return AsTPMSessionError(err, code, command, session, &e)
}

// AsTPMWarning indicates whether the error or any error within its chain is a *TPMWarning with
// the specified WarningCode and CommandCode, and sets out to the value of error if it is. To test
// for any warning code, use AnyWarningCode. To test for any command code, use AnyCommandCode. This
// will panic if out is nil.
func AsTPMWarning(err error, code WarningCode, command CommandCode, out **TPMWarning) bool {
	return xerrors.As(err, out) && (code == AnyWarningCode || (*out).Code == code) && (command == AnyCommandCode || (*out).Command == command)
}

// IsTPMWarning indicates whether the error or any error within its chain is a *TPMWarning with the
// specified WarningCode and CommandCode. To test for any warning code, use AnyWarningCode. To test
// for any command code, use AnyCommandCode.
func IsTPMWarning(err error, code WarningCode, command CommandCode) bool {
	var e *TPMWarning
	return AsTPMWarning(err, code, command, &e)
}

type InvalidResponseCodeError ResponseCode

func (e InvalidResponseCodeError) Error() string {
	return fmt.Sprintf("invalid response code 0x%08x", ResponseCode(e))
}

// DecodeResponseCode decodes the ResponseCode provided via resp. If the specified response code is
// Success, it returns no error, else it returns an error that is appropriate for the response code.
// The command code is used for adding context to the returned error.
//
// If the response code is invalid, an InvalidResponseCodeError error will be returned.
func DecodeResponseCode(command CommandCode, resp ResponseCode) error {
	switch {
	case resp == ResponseSuccess:
		return nil
	case resp == ResponseBadTag:
		return &TPMError{Command: command, Code: ErrorBadTag}
	case resp.F():
		// Format-one error codes
		err := &TPMError{Command: command, Code: ErrorCode(resp.E()) + errorCode1Start}
		switch {
		case resp.P():
			// Associated with a parameter
			return &TPMParameterError{TPMError: err, Index: int(resp.N())}
		case resp.N()&0x8 != 0:
			// Associated with a session
			return &TPMSessionError{TPMError: err, Index: int(resp.N() & 0x7)}
		case resp.N() != 0:
			// Associated with a handle
			return &TPMHandleError{TPMError: err, Index: int(resp.N())}
		default:
			// Not associated with a specific parameter, session or handle
			return err
		}
	default:
		// Format-zero error codes
		switch {
		case !resp.V():
			// A TPM1.2 error
			return InvalidResponseCodeError(resp)
		case resp.T():
			// An error defined by the TPM vendor
			return &TPMVendorError{Command: command, Code: resp}
		case resp.S():
			// A warning
			return &TPMWarning{Command: command, Code: WarningCode(resp.E())}
		default:
			return &TPMError{Command: command, Code: ErrorCode(resp.E())}
		}
	}
}
