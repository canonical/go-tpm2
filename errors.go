// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
	"strings"
)

type UnmarshallingError struct {
	Command CommandCode
	context string
	err     error
}

func (e UnmarshallingError) Error() string {
	return fmt.Sprintf("cannot unmarshal %s for command %s: %v", e.context, e.Command, e.err)
}

type InvalidAuthResponseError struct {
	Command CommandCode
	msg     string
}

func (e InvalidAuthResponseError) Error() string {
	return fmt.Sprintf("TPM returned an invalid auth response for command %s: %s", e.Command, e.msg)
}

type TPMReadError struct {
	Command CommandCode
	Err     error
}

func (e TPMReadError) Error() string {
	return fmt.Sprintf("cannot read response to command %s from TPM: %v", e.Command, e.Err)
}

type TPMWriteError struct {
	Command CommandCode
	Err     error
}

func (e TPMWriteError) Error() string {
	return fmt.Sprintf("cannot write command %s to TPM: %v", e.Command, e.Err)
}

const (
	formatMask ResponseCode = 1 << 7

	fmt0ErrorCodeMask ResponseCode = 0x7f
	fmt0VersionMask   ResponseCode = 1 << 8
	fmt0VendorMask    ResponseCode = 1 << 10
	fmt0SeverityMask  ResponseCode = 1 << 11

	fmt1ErrorCodeMask            ResponseCode = 0x3f
	fmt1ParameterIndexMask       ResponseCode = 0xf00
	fmt1HandleOrSessionIndexMask ResponseCode = 0x700
	fmt1ParameterMask            ResponseCode = 1 << 6
	fmt1SessionMask              ResponseCode = 1 << 11

	fmt1IndexShift uint = 8
)

type TPM1Error struct {
	Command CommandCode
	Code    ResponseCode
}

func (e TPM1Error) Error() string {
	return fmt.Sprintf("TPM returned a 1.2 error whilst executing command %s: 0x%08x", e.Command, e.Code)
}

type TPMVendorError struct {
	Command CommandCode
	Code    ResponseCode
}

func (e TPMVendorError) Error() string {
	return fmt.Sprintf("TPM returned a vendor defined error whilst executing command %s: 0x%08x", e.Command,
		e.Code)
}

type WarningCode ResponseCode

type TPMWarning struct {
	Command CommandCode
	Code    WarningCode
}

func (e TPMWarning) Error() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "TPM returned a warning whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := warningCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

type ErrorCode0 ResponseCode

type TPMError struct {
	Command CommandCode
	Code    ErrorCode0
}

func (e TPMError) Error() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "TPM returned an error whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := errorCode0Descriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

type ErrorCode1 ResponseCode

type TPMParameterError struct {
	Command CommandCode
	Code    ErrorCode1
	Index   int
}

func (e TPMParameterError) Error() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "TPM returned an error for parameter %d whilst executing command %s: %s",
		e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCode1Descriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

type TPMSessionError struct {
	Command CommandCode
	Code    ErrorCode1
	Index   int
}

func (e TPMSessionError) Error() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "TPM returned an error for session %d whilst executing command %s: %s",
		e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCode1Descriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

type TPMHandleError struct {
	Command CommandCode
	Code    ErrorCode1
	Index   int
}

func (e TPMHandleError) Error() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "TPM returned an error for handle %d whilst executing command %s: %s",
		e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCode1Descriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func DecodeResponseCode(command CommandCode, resp ResponseCode) error {
	if resp == ResponseCode(Success) {
		return nil
	}

	if resp&formatMask == 0 {
		if resp&fmt0VersionMask == 0 {
			return TPM1Error{command, resp}
		}

		if resp&fmt0VendorMask > 0 {
			return TPMVendorError{command, resp}
		}

		if resp&fmt0SeverityMask > 0 {
			return TPMWarning{command, WarningCode(resp & fmt0ErrorCodeMask)}
		}

		return TPMError{command, ErrorCode0(resp & fmt0ErrorCodeMask)}
	}

	if resp&fmt1ParameterMask > 0 {
		return TPMParameterError{command, ErrorCode1(resp & fmt1ErrorCodeMask),
			int((resp & fmt1ParameterIndexMask) >> fmt1IndexShift)}
	}

	if resp&fmt1SessionMask > 0 {
		return TPMSessionError{command, ErrorCode1(resp & fmt1ErrorCodeMask),
			int((resp & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
	}

	return TPMHandleError{command, ErrorCode1(resp & fmt1ErrorCodeMask),
		int((resp & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
}
