package tpm2

import (
	"fmt"
)

type MarshallingError struct {
	err error
}

func (e MarshallingError) Error() string {
	return fmt.Sprintf("error whilst marshalling command parameters: %v", e.err)
}

type UnmarshallingError struct {
	err error
}

func (e UnmarshallingError) Error() string {
	return fmt.Sprintf("error whilst unmarshalling response parameters: %v", e.err)
}

type InvalidParamError struct {
	msg string
}

func (e InvalidParamError) Error() string {
	return fmt.Sprintf("invalid function parameter supplied: %s", e.msg)
}

type InvalidResourceParamError struct {
	msg string
}

func (e InvalidResourceParamError) Error() string {
	return fmt.Sprintf("invalid resource object supplied: %s", e.msg)
}

type InvalidAuthParamError struct {
	msg string
}

func (e InvalidAuthParamError) Error() string {
	return fmt.Sprintf("invalid auth parameter supplied: %s", e.msg)
}

type InvalidResponseError struct {
	msg string
}

func (e InvalidResponseError) Error() string {
	return fmt.Sprintf("invalid response from TPM: %s", e.msg)
}

type TPMReadError struct {
	IOError error
}

func (e TPMReadError) Error() string {
	return fmt.Sprintf("error whilst reading from TPM: %v", e.IOError)
}

type TPMWriteError struct {
	IOError error
}

func (e TPMWriteError) Error() string {
	return fmt.Sprintf("error whilst writing to TPM: %v", e.IOError)
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
	Code ResponseCode
}

func (e TPM1Error) Error() string {
	return fmt.Sprintf("TPM returned a 1.2 error: 0x%04x", e.Code)
}

type VendorError struct {
	Code ResponseCode
}

func (e VendorError) Error() string {
	return fmt.Sprintf("TPM returned vendor defined error: 0x%04x", e.Code)
}

type Warning struct {
	Code ErrorCode
}

func (e Warning) Error() string {
	return fmt.Sprintf("TPM returned warning code: 0x%x", e.Code)
}

type Error struct {
	Code ErrorCode
}

func (e Error) Error() string {
	return fmt.Sprintf("TPM returned error code: 0x%x", e.Code)
}

type ParameterError struct {
	Code  ErrorCode
	Index int
}

func (e ParameterError) Error() string {
	return fmt.Sprintf("TPM returned a parameter error (code: %v, index: %d)", e.Code, e.Index)
}

type SessionError struct {
	Code  ErrorCode
	Index int
}

func (e SessionError) Error() string {
	return fmt.Sprintf("TPM returned a session error (code: %v, index: %d)", e.Code, e.Index)
}

type HandleError struct {
	Code  ErrorCode
	Index int
}

func (e HandleError) Error() string {
	return fmt.Sprintf("TPM returned a handle error (code: %v, index: %d)", e.Code, e.Index)
}

func DecodeResponseCode(code ResponseCode) error {
	if code == ResponseCode(Success) {
		return nil
	}

	if code&formatMask == 0 {
		if code&fmt0VersionMask == 0 {
			return TPM1Error{code}
		}

		if code&fmt0VendorMask > 0 {
			return VendorError{code}
		}

		if code&fmt0SeverityMask > 0 {
			return Warning{ErrorCode(code & fmt0ErrorCodeMask)}
		}

		return Error{ErrorCode(code & fmt0ErrorCodeMask)}
	}

	if code&fmt1ParameterMask > 0 {
		return ParameterError{ErrorCode(code & fmt1ErrorCodeMask),
			int((code & fmt1ParameterIndexMask) >> fmt1IndexShift)}
	}

	if code&fmt1SessionMask > 0 {
		return SessionError{ErrorCode(code & fmt1ErrorCodeMask),
			int((code & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
	}

	return HandleError{ErrorCode(code & fmt1ErrorCodeMask),
		int((code & fmt1HandleOrSessionIndexMask) >> fmt1IndexShift)}
}
