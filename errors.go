// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"errors"
	"fmt"
	"math"
)

const (
	// AnyCommandCode is used to match any command code when using IsTPMError,
	// IsTPMHandleError, IsTPMParameterError, IsTPMSessionError and IsTPMWarning,
	// or to match any property when using IsMissingPropertyError with the
	// CommandCode type parameter.
	//
	// As this value sets the 2 MSB reserved bits which should always be zero, this
	// can always be distringuished from a valid command code.
	AnyCommandCode CommandCode = 0xc0000000

	// AnyErrorCode is used to match any error code when using IsTPMError,
	// IsTPMHandleError, IsTPMParameterError and IsTPMSessionError. As this
	// is beyond the range of valid format-one error codes, it can always be
	// distinguished from a valid error code.
	AnyErrorCode ErrorCode = 0xff

	// AnyHandle is used to match any handle when using IsResourceUnavailableError,
	// or to match any property when using IsMissingPropertyError with the Handle
	// type parameter.
	AnyHandle Handle = 0xffffffff

	// AnyHandleIndex is used to match any handle when using IsTPMHandleError.
	AnyHandleIndex int = -1

	// AnyParameterIndex is used to match any parameter when using IsTPMParameterError.
	AnyParameterIndex int = -1

	// AnySessionIndex is used to match any session when using IsTPMSessionError.
	AnySessionIndex int = -1

	// AnyWarningCode is used to match any warning code when using IsTPMWarning. As this
	// is beyond the range of any valid warning code, it can always be distinguished from
	// a valid warning code.
	AnyWarningCode WarningCode = 0xff

	// AnyVendorResponseCode is used to match any response code when using IsTPMVendorError.
	// As bit 10 is clear, this is always an invalid vendor code so can be distinguished from
	// a valid vendor code.
	AnyVendorResponseCode ResponseCode = 0x900

	// AnyCapability is used to match any capability when using IsMissingPropertyError.
	AnyCapability Capability = 0xffffffff

	// AnyProperty is used to match any property when using IsMissingPropertyError with
	// the Property type parameter.
	AnyProperty Property = 0xffffffff

	// AnyAlgorithmId is used to match any property when using IsMissingPropertyError
	// with the AlgorithmId type parameter.
	AnyAlgorithmId AlgorithmId = 0xffff
)

// ErrCapabilityValueOutOfRange may be returned wrapped in *[InvalidResponseError]
// from any TPM2_GetCapability utility function that checks the returned value.
var ErrCapabilityValueOutOfRange = errors.New("the requested value is out of range")

func (a AlgorithmId) isMissingPropertyErrorAnyValue() bool {
	return a == AnyAlgorithmId
}

func (c CommandCode) isMissingPropertyErrorAnyValue() bool {
	return c == AnyCommandCode
}

func (p Property) isMissingPropertyErrorAnyValue() bool {
	return p == AnyProperty
}

func (h Handle) isMissingPropertyErrorAnyValue() bool {
	return h == AnyHandle
}

type MissingPropertyErrorType interface {
	AlgorithmId | CommandCode | Property | Handle
	isMissingPropertyErrorAnyValue() bool
}

// MissingPropertyError may be returned by some TPM2_GetCapability utility functions
// that are used to fetch a single property if they determine that the returned
// property doesn't match the requested one.
type MissingPropertyError[T MissingPropertyErrorType] struct {
	Capability Capability
	Property   T
}

func (e *MissingPropertyError[T]) Error() string {
	return fmt.Sprintf("property %v of type %T for capability %v does not exist", e.Property, e.Property, e.Capability)
}

func (e *MissingPropertyError[T]) Is(target error) bool {
	t, ok := target.(*MissingPropertyError[T])
	if !ok {
		return false
	}
	return (t.Capability == AnyCapability || t.Capability == e.Capability) && (t.Property.isMissingPropertyErrorAnyValue() || t.Property == e.Property)
}

// IsMissingPropertyError determines if the supplied error is a *[MissingPropertyError] with the specified
// capability and property.
func IsMissingPropertyError[T MissingPropertyErrorType](err error, capability Capability, property T) bool {
	return errors.Is(err, &MissingPropertyError[T]{Capability: capability, Property: property})
}

// ResourceUnavailableError is returned from [TPMContext.NewResourceContext] if it is called with
// a handle that does not correspond to a resource that is available on the TPM. This could be
// because the resource doesn't exist on the TPM, or it lives within a hierarchy that is disabled.
type ResourceUnavailableError struct {
	Handle Handle
	err    error
}

func (e *ResourceUnavailableError) Error() string {
	return fmt.Sprintf("a resource at handle %#08x is not available on the TPM", e.Handle)
}

func (e *ResourceUnavailableError) Unwrap() error {
	return e.err
}

func (e *ResourceUnavailableError) Is(target error) bool {
	t, ok := target.(*ResourceUnavailableError)
	if !ok {
		return false
	}
	return t.Handle == AnyHandle || t.Handle == e.Handle
}

// InvalidResponseError is returned from any [TPMContext] method that executes a TPM command if the
// TPM's response is invalid. Some examples of invalid responses that would result in this error
// are:
//
//   - The response packet was too large.
//   - The response packet could not be unmarshalled.
//   - The size field in the response header doesn't match the actual size.
//   - The response code and response tag were inconsistent.
//   - An error occurred whilst unmarshalling the response auth area or parameters.
//   - The response auth area or parameter area have unused bytes after unmarshalling.
//   - There were an unexpected number of response auths.
//   - A response auth was invalid.
//
// Any session contexts associated with the command that caused this error should be considered
// invalid.
//
// It is possible that the TPM command completed successfully.
//
// If any function that executes a command which allocates objects on the TPM returns this error,
// it is possible that these objects were allocated and now exist on the TPM.
//
// If any function that executes a command which makes persistent changes to the TPM returns this
// error, it is possible that the persistent changes were completed.
type InvalidResponseError struct {
	Command CommandCode
	err     error
}

func (e *InvalidResponseError) Unwrap() error {
	return e.err
}

func (e *InvalidResponseError) Error() string {
	return fmt.Sprintf("TPM returned an invalid response for command %s: %v", e.Command, e.err.Error())
}

// InvalidAuthResponseError is returned from any [TPMContext] method that executes a TPM command if
// one of the response auth HMACs is invalid. If this error occurs, session contexts associated
// with the command that caused this error should be considered invalid.
type InvalidAuthResponseError struct {
	Index int // Index of the session responsible for this error, starting from 1
	msg   string
}

func (e *InvalidAuthResponseError) Error() string {
	return fmt.Sprintf("encountered an error whilst processing the auth response for session %d: %s", e.Index, e.msg)
}

// TctiError is returned from any [TPMContext] method if the underlying [Transport] returns an error.
// If this error occurs, the underlying connection will generally be unusable for subsequent
// commands.
//
// Deprecated: Use [TransportError].
type TctiError = TransportError

// TransportError is returned from any [TPMContext] method if the underlying [Transport] returns an error.
// If this error occurs, the underlying connection will generally be unusable for subsequent commands, as
// the TPM and host-side state can become inconsistent. It should be considered a fatal error, requiring
// the existing connection to be closed and all host-side state to be discarded before re-opening a new
// connection.
type TransportError struct {
	Op  string // The operation that caused the error
	err error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("cannot complete %s operation on Transport: %v", e.Op, e.err)
}

func (e *TransportError) Unwrap() error {
	return e.err
}

// TPMVendorError represents a TPM response that indicates a vendor-specific error
// (where rc & 0x580 == 0x500).
type TPMVendorError struct {
	Command CommandCode  // Command code associated with this error
	Code    ResponseCode // Response code
}

// CommandCode returns the command code that generated this error.
func (e *TPMVendorError) CommandCode() CommandCode {
	return e.Command
}

// ResponseCode returns a TPM response code for this error.
// It will panic if the [ResponseCode] field is not a valid vendor error response
// code, ie, the F bit (7) is set, or the V bit (8) is clear, or the T bit (10)
// is clear.
func (e *TPMVendorError) ResponseCode() ResponseCode {
	if e.Code.F() || !e.Code.V() || !e.Code.T() {
		panic(fmt.Errorf("%w (response code is not format-0, TPM2, and vendor defined)", InvalidResponseCodeError(e.Code)))
	}
	return e.Code
}

func (e *TPMVendorError) Error() string {
	return fmt.Sprintf("TPM returned a vendor defined error whilst executing command %s: %#08x", e.Command, responseCodeFormatter(e))
}

func (e *TPMVendorError) Is(target error) bool {
	t, ok := target.(*TPMVendorError)
	if !ok {
		return false
	}
	return (t.Code == AnyVendorResponseCode || t.Code == e.Code) && (t.Command == AnyCommandCode || t.Command == e.Command)
}

// WarningCode represents a TPM warning. These are TCG defined format 0 response codes with the
// severity bit set (response codes 0x900 to 0x97f).
type WarningCode uint8

const (
	WarningContextGap     WarningCode = WarningCode(ResponseContextGap - rcWarn)     // TPM_RC_CONTEXT_GAP
	WarningObjectMemory   WarningCode = WarningCode(ResponseObjectMemory - rcWarn)   // TPM_RC_OBJECT_MEMORY
	WarningSessionMemory  WarningCode = WarningCode(ResponseSessionMemory - rcWarn)  // TPM_RC_SESSION_MEMORY
	WarningMemory         WarningCode = WarningCode(ResponseMemory - rcWarn)         // TPM_RC_MEMORY
	WarningSessionHandles WarningCode = WarningCode(ResponseSessionHandles - rcWarn) // TPM_RC_SESSION_HANDLES
	WarningObjectHandles  WarningCode = WarningCode(ResponseObjectHandles - rcWarn)  // TPM_RC_OBJECT_HANDLES

	// WarningLocality corresponds to TPM_RC_LOCALITY and is returned for a command if a policy
	// session is used for authorization and the session includes a TPM2_PolicyLocality assertion, but
	// the command isn't executed with the authorized locality.
	WarningLocality WarningCode = WarningCode(ResponseLocality - rcWarn)

	// WarningYielded corresponds to TPM_RC_YIELDED and is returned for any command that is suspended
	// as a hint that the command can be retried. This is handled automatically when executing
	// commands using CommandContext by resubmitting the command.
	WarningYielded WarningCode = WarningCode(ResponseYielded - rcWarn)

	// WarningCanceled corresponds to TPM_RC_CANCELED and is returned for any command that is canceled
	// before being able to complete.
	WarningCanceled WarningCode = WarningCode(ResponseCanceled - rcWarn)

	WarningTesting     WarningCode = WarningCode(ResponseTesting - rcWarn)     // TPM_RC_TESTING
	WarningReferenceH0 WarningCode = WarningCode(ResponseReferenceH0 - rcWarn) // TPM_RC_REFERENCE_H0
	WarningReferenceH1 WarningCode = WarningCode(ResponseReferenceH1 - rcWarn) // TPM_RC_REFERENCE_H1
	WarningReferenceH2 WarningCode = WarningCode(ResponseReferenceH2 - rcWarn) // TPM_RC_REFERENCE_H2
	WarningReferenceH3 WarningCode = WarningCode(ResponseReferenceH3 - rcWarn) // TPM_RC_REFERENCE_H3
	WarningReferenceH4 WarningCode = WarningCode(ResponseReferenceH4 - rcWarn) // TPM_RC_REFERENCE_H4
	WarningReferenceH5 WarningCode = WarningCode(ResponseReferenceH5 - rcWarn) // TPM_RC_REFERENCE_H5
	WarningReferenceH6 WarningCode = WarningCode(ResponseReferenceH6 - rcWarn) // TPM_RC_REFERENCE_H6
	WarningReferenceS0 WarningCode = WarningCode(ResponseReferenceS0 - rcWarn) // TPM_RC_REFERENCE_S0
	WarningReferenceS1 WarningCode = WarningCode(ResponseReferenceS1 - rcWarn) // TPM_RC_REFERENCE_S1
	WarningReferenceS2 WarningCode = WarningCode(ResponseReferenceS2 - rcWarn) // TPM_RC_REFERENCE_S2
	WarningReferenceS3 WarningCode = WarningCode(ResponseReferenceS3 - rcWarn) // TPM_RC_REFERENCE_S3
	WarningReferenceS4 WarningCode = WarningCode(ResponseReferenceS4 - rcWarn) // TPM_RC_REFERENCE_S4
	WarningReferenceS5 WarningCode = WarningCode(ResponseReferenceS5 - rcWarn) // TPM_RC_REFERENCE_S5
	WarningReferenceS6 WarningCode = WarningCode(ResponseReferenceS6 - rcWarn) // TPM_RC_REFERENCE_S6

	// WarningNVRate corresponds to TPM_RC_NV_RATE and is returned for any command that requires NV
	// access if NV access is currently rate limited to prevent the NV memory from wearing out.
	WarningNVRate WarningCode = WarningCode(ResponseNVRate - rcWarn)

	// WarningLockout corresponds to TPM_RC_LOCKOUT and is returned for any command that requires
	// authorization for an entity that is subject to dictionary attack protection, and the TPM is in
	// dictionary attack lockout mode.
	WarningLockout WarningCode = WarningCode(ResponseLockout - rcWarn)

	// WarningRetry corresponds to TPM_RC_RETRY and is returned for any command if the TPM was not
	// able to start the command. This is handled automatically when executing comands using
	// CommandContext by resubmitting the command.
	WarningRetry WarningCode = WarningCode(ResponseRetry - rcWarn)

	// WarningNVUnavailable corresponds to TPM_RC_NV_UNAVAILABLE and is returned for any command that
	// requires NV access but NV memory is currently not available.
	WarningNVUnavailable WarningCode = WarningCode(ResponseNVUnavailable - rcWarn)
)

// ResponseCode returns a TPM response code for this warning code.
// It will panic if it cannot be converted to a valid response code.
func (c WarningCode) ResponseCode() ResponseCode {
	rc := rcWarn + ResponseCode(c)
	if rc.F() {
		// The result overflowed into bit 7.
		panic(fmt.Errorf("%w (warning code results in a response code that overflows into bit 7)", InvalidResponseCodeError(rc)))
	}
	return rc
}

// TPMWarning represents a TPM response that indicates a warning,
// where 0x900 < rc <= 0x97f.
type TPMWarning struct {
	Command CommandCode // Command code associated with this error
	Code    WarningCode // Warning code
}

// CommandCode returns the command code that generated this error.
func (e *TPMWarning) CommandCode() CommandCode {
	return e.Command
}

// ResponseCode returns a TPM response code for this warning.
// It will panic if it cannot be converted to a valid response code.
func (e *TPMWarning) ResponseCode() ResponseCode {
	return e.Code.ResponseCode()
}

func (e *TPMWarning) Error() string {
	return fmt.Sprintf("TPM returned a warning whilst executing command %s: %+s", e.Command, responseCodeFormatter(e))
}

func (e *TPMWarning) Is(target error) bool {
	t, ok := target.(*TPMWarning)
	if !ok {
		return false
	}
	return (t.Code == AnyWarningCode || t.Code == e.Code) && (t.Command == AnyCommandCode || t.Command == e.Command)
}

// ErrorCode represents a TPM error. This type represents TCG defined format 0 response codes
// without the severity bit set (response codes 0x100 to 0x17f), and format 1 response codes
// (response codes 0x080 to 0x0bf).
//
// Format 0 error numbers are 7 bits wide and are represented by codes 0x00 to 0x7f. Format 1
// error numbers are 6 bits wide and are represented by codes 0x80 to 0xbf.
type ErrorCode uint8

const (
	// ErrorInitialize corresponds to TPM_RC_INITIALIZE and is returned for any command executed
	// between a _TPM_Init event and a TPM2_Startup command.
	ErrorInitialize ErrorCode = ErrorCode(ResponseInitialize - rcVer1)

	// ErrorFailure corresponds to TPM_RC_FAILURE and is returned for any command if the TPM is in
	// failure mode.
	ErrorFailure ErrorCode = ErrorCode(ResponseFailure - rcVer1)

	ErrorSequence  ErrorCode = ErrorCode(ResponseSequence - rcVer1)  // TPM_RC_SEQUENCE
	ErrorDisabled  ErrorCode = ErrorCode(ResponseDisabled - rcVer1)  // TPM_RC_DISABLED
	ErrorExclusive ErrorCode = ErrorCode(ResponseExclusive - rcVer1) // TPM_RC_EXCLUSIVE

	// ErrorAuthType corresponds to TPM_RC_AUTH_TYPE and is returned for a command where an
	// authorization is required and the authorization type is expected to be a policy session, but
	// another authorization type has been provided.
	ErrorAuthType ErrorCode = ErrorCode(ResponseAuthType - rcVer1)

	// ErrorAuthMissing corresponds to TPM_RC_AUTH_MISSING and is returned for a command that accepts
	// a ResourceContext argument that requires authorization, but no authorization session has been
	// provided in the command payload.
	ErrorAuthMissing ErrorCode = ErrorCode(ResponseAuthType - rcVer1)

	ErrorPolicy ErrorCode = ErrorCode(ResponsePolicy - rcVer1) // TPM_RC_POLICY
	ErrorPCR    ErrorCode = ErrorCode(ResponsePCR - rcVer1)    // TPM_RC_PCR

	// ErrorPCRChanged corresponds to TPM_RC_PCR_CHANGED and is returned for a command where a policy
	// session is used for authorization and the PCR contents have been updated since the last time
	// that they were checked in the session with a TPM2_PolicyPCR assertion.
	ErrorPCRChanged ErrorCode = ErrorCode(ResponsePCRChanged - rcVer1)

	// ErrorUpgrade corresponds to TPM_RC_UPGRADE and is returned for any command that isn't
	// TPM2_FieldUpgradeData if the TPM is in field upgrade mode.
	ErrorUpgrade ErrorCode = ErrorCode(ResponseUpgrade - rcVer1)

	ErrorTooManyContexts ErrorCode = ErrorCode(ResponseTooManyContexts - rcVer1) // TPM_RC_TOO_MANY_CONTEXTS

	// ErrorAuthUnavailable corresponds to TPM_RC_AUTH_UNAVAILABLE and is returned for a command where
	// the provided authorization requires the use of the authorization value for an entity, but the
	// authorization value cannot be used. For example, if the entity is an object and the command
	// requires the user auth role but the object does not have the AttrUserWithAuth attribute.
	ErrorAuthUnavailable ErrorCode = ErrorCode(ResponseAuthUnavailable - rcVer1)

	// ErrorReboot corresponds to TPM_RC_REBOOT and is returned for any command if the TPM requires a
	// _TPM_Init event before it will execute any more commands.
	ErrorReboot ErrorCode = ErrorCode(ResponseReboot - rcVer1)

	ErrorUnbalanced ErrorCode = ErrorCode(ResponseUnbalanced - rcVer1) // TPM_RC_UNBALANCED

	// ErrorCommandSize corresponds to TPM_RC_COMMAND_SIZE and indicates that the value of the
	// commandSize field in the command header does not match the size of the command packet
	// transmitted to the TPM.
	ErrorCommandSize ErrorCode = ErrorCode(ResponseCommandSize - rcVer1)

	// ErrorCommandCode corresponds to TPM_RC_COMMAND_CODE and is returned for any command that is not
	// implemented by the TPM.
	ErrorCommandCode ErrorCode = ErrorCode(ResponseCommandCode - rcVer1)

	ErrorAuthsize ErrorCode = ErrorCode(ResponseAuthsize - rcVer1) // TPM_RC_AUTHSIZE

	// ErrorAuthContext corresponds to TPM_RC_AUTH_CONTEXT and is returned for any command that does
	// not accept any sessions if sessions have been provided in the command payload.
	ErrorAuthContext ErrorCode = ErrorCode(ResponseAuthContext - rcVer1)

	ErrorNVRange         ErrorCode = ErrorCode(ResponseNVRange - rcVer1)         // TPM_RC_NV_RANGE
	ErrorNVSize          ErrorCode = ErrorCode(ResponseNVSize - rcVer1)          // TPM_RC_NV_SIZE
	ErrorNVLocked        ErrorCode = ErrorCode(ResponseNVLocked - rcVer1)        // TPM_RC_NV_LOCKED
	ErrorNVAuthorization ErrorCode = ErrorCode(ResponseNVAuthorization - rcVer1) // TPM_RC_NV_AUTHORIZATION
	ErrorNVUninitialized ErrorCode = ErrorCode(ResponseNVUninitialized - rcVer1) // TPM_RC_NV_UNINITIALIZED
	ErrorNVSpace         ErrorCode = ErrorCode(ResponseNVSpace - rcVer1)         // TPM_RC_NV_SPACE
	ErrorNVDefined       ErrorCode = ErrorCode(ResponseNVDefined - rcVer1)       // TPM_RC_NV_DEFINED
	ErrorBadContext      ErrorCode = ErrorCode(ResponseBadContext - rcVer1)      // TPM_RC_BAD_CONTEXT
	ErrorCpHash          ErrorCode = ErrorCode(ResponseCpHash - rcVer1)          // TPM_RC_CPHASH
	ErrorParent          ErrorCode = ErrorCode(ResponseParent - rcVer1)          // TPM_RC_PARENT
	ErrorNeedsTest       ErrorCode = ErrorCode(ResponseNeedsTest - rcVer1)       // TPM_RC_NEEDS_TEST

	// ErrorNoResult corresponds to TPM_RC_NO_RESULT and is returned for any command if the TPM
	// cannot process a request due to an unspecified problem.
	ErrorNoResult ErrorCode = ErrorCode(ResponseNoResult - rcVer1)

	ErrorSensitive ErrorCode = ErrorCode(ResponseSensitive - rcVer1) // TPM_RC_SENSITIVE

	errorCode1Start ErrorCode = ErrorCode(rcFmt1)

	ErrorAsymmetric ErrorCode = ErrorCode(ResponseAsymmetric) // TPM_RC_ASYMMETRIC

	// ErrorAttributes corresponds to TPM_RC_ATTRIBUTES and is returned as a *TPMSessionError for a
	// command in the following circumstances:
	// * More than one SessionContext instance with the AttrCommandEncrypt attribute has been provided.
	// * More than one SessionContext instance with the AttrResponseEncrypt attribute has been provided.
	// * A SessionContext instance referencing a trial session has been provided for authorization.
	ErrorAttributes ErrorCode = ErrorCode(ResponseAttributes)

	// ErrorHash corresponds to TPM_RC_HASH and is returned as a *TPMParameterError error for any
	// command that accepts a HashAlgorithmId parameter if the parameter value is not a valid digest
	// algorithm.
	ErrorHash ErrorCode = ErrorCode(ResponseHash)

	// ErrorValue corresponds to TPM_RC_VALUE and is returned as a *TPMParameterError or
	// *TPMHandleError for any command where an argument value is incorrect or out of range for the
	// command.
	ErrorValue ErrorCode = ErrorCode(ResponseValue) // TPM_RC_VALUE

	// ErrorHierarchy corresponds to TPM_RC_HIERARCHY and is returned as a *TPMHandleError error for
	// any command that accepts a ResourceContext or Handle argument if that argument corresponds to
	// a hierarchy on the TPM that has been disabled.
	ErrorHierarchy ErrorCode = ErrorCode(ResponseHierarchy)

	ErrorKeySize ErrorCode = ErrorCode(ResponseKeySize) // TPM_RC_KEY_SIZE
	ErrorMGF     ErrorCode = ErrorCode(ResponseMGF)     // TPM_RC_MGF

	// ErrorMode corresponds to TPM_RC_MODE and is returned as a *TPMParameterError error for any
	// command that accepts a SymModeId parameter if the parameter value is not a valid symmetric
	// mode.
	ErrorMode ErrorCode = ErrorCode(ResponseMode)

	// ErrorType corresponds to TPM_RC_TYPE and is returned as a *TPMParameterError error for any
	// command that accepts a ObjectTypeId parameter if the parameter value is not a valid public
	// type.
	ErrorType ErrorCode = ErrorCode(ResponseType)

	ErrorHandle ErrorCode = ErrorCode(ResponseHandle) // TPM_RC_HANDLE

	// ErrorKDF corresponds to TPM_RC_KDF and is returned as a *TPMParameterError error for any
	// command that accepts a KDFAlgorithmId parameter if the parameter value is not a valid key
	// derivation function.
	ErrorKDF ErrorCode = ErrorCode(ResponseKDF)

	ErrorRange ErrorCode = ErrorCode(ResponseRange) // TPM_RC_RANGE

	// ErrorAuthFail corresponds to TPM_RC_AUTH_FAIL and is returned as a *TPMSessionError error for
	// a command if an authorization check fails. The dictionary attack counter is incremented when
	// this error is returned.
	ErrorAuthFail ErrorCode = ErrorCode(ResponseAuthFail)

	// ErrorNonce corresponds to TPM_RC_NONCE and is returned as a *TPMSessionError error for any
	// command where a password authorization has been provided and the authorization session in the
	// command payload contains a non-zero sized nonce field.
	ErrorNonce ErrorCode = ErrorCode(ResponseNonce)

	// ErrorPP corresponds to TPM_RC_PP and is returned as a *TPMSessionError for a command in the
	// following circumstances:
	// * Authorization of the platform hierarchy is provided and the command requires an assertion of
	//   physical presence that hasn't been provided.
	// * Authorization is provided with a policy session that includes the TPM2_PolicyPhysicalPresence
	//   assertion, and an assertion of physical presence hasn't been provided.
	ErrorPP ErrorCode = ErrorCode(ResponsePP)

	// ErrorScheme corresponds to TPM_RC_SCHEME and is returned as a *TPMParameterError error for any
	// command that accepts a SigSchemeId or ECCSchemeId parameter if the parameter value is not valid.
	ErrorScheme ErrorCode = ErrorCode(ResponseScheme)

	// ErrorSize corresponds to TPM_RC_SIZE and is returned for a command in the following circumstances:
	// * As a *TPMParameterError if the command accepts a parameter type corresponding to TPM2B or
	//   TPML prefixed types and the size or length field has an invalid value.
	// * As a *TPMError if the TPM's parameter unmarshalling doesn't consume all of the bytes in the
	//   input buffer.
	// * As a *TPMError if the size field of the command's authorization area is an invalid value.
	// * As a *TPMSessionError if the authorization area for a command payload contains more than 3
	//   sessions.
	ErrorSize ErrorCode = ErrorCode(ResponseSize)

	// ErrorSymmetric corresponds to TPM_RC_SYMMETRIC and is returned for a command in the following
	// circumstances:
	// * As a *TPMParameterError if the command accepts a SymAlgorithmId parameter if the parameter
	//   value is not a valid symmetric algorithm.
	// * As a *TPMSessionError if a SessionContext instance is provided with the AttrCommandEncrypt
	//   attribute set but the session has no symmetric algorithm.
	// * As a *TPMSessionError if a SessionContext instance is provided with the AttrResponseEncrypt
	//   attribute set but the session has no symmetric algorithm.
	ErrorSymmetric ErrorCode = ErrorCode(ResponseSymmetric)

	// ErrorTag corresponds to TPM_RC_TAG and is returned as a *TPMParameterError error for a command
	// that accepts a StructTag parameter if the parameter value is not the correct value.
	ErrorTag ErrorCode = ErrorCode(ResponseTag)

	// ErrorSelector corresponds to TPM_RC_SELECTOR and is returned as a *TPMParameterError error for
	// a command that accepts a parameter type corresponding to a TPMU prefixed type if the value of
	// the selector field in the surrounding TPMT prefixed type is incorrect.
	ErrorSelector ErrorCode = ErrorCode(ResponseSelector)

	// ErrorInsufficient corresponds to TPM_RC_INSUFFICIENT and is returned as a *TPMParameterError
	// for a command if there is insufficient data in the TPM's input buffer to complete unmarshalling
	// of the command parameters.
	ErrorInsufficient ErrorCode = ErrorCode(ResponseInsufficient)

	ErrorSignature ErrorCode = ErrorCode(ResponseSignature) // TPM_RC_SIGNATURE
	ErrorKey       ErrorCode = ErrorCode(ResponseKey)       // TPM_RC_KEY

	// ErrorPolicyFail corresponds to TPM_RC_POLICY_FAIL and is returned as a *TPMSessionError error
	// for a command in the following circumstances:
	// * A policy session is used for authorization and the policy session digest does not match the
	//   authorization policy digest for the entity being authorized.
	// * A policy session is used for authorization and the digest algorithm of the session does not
	//   match the name algorithm of the entity being authorized.
	// * A policy session is used for authorization but the authorization is for the admin or DUP role
	//   and the policy session does not include a TPM2_PolicyCommandCode assertion.
	// * A policy session is used for authorization and the policy session includes a
	//   TPM2_PolicyNvWritten assertion but the entity being authorized is not a NV index.
	// * A policy session is used for authorization, the policy session includes the
	//   TPM2_PolicyNvWritten assertion, but the NV index being authorized does not have the
	//   AttrNVWritten attribute set.
	ErrorPolicyFail ErrorCode = ErrorCode(ResponsePolicyFail)

	ErrorIntegrity ErrorCode = ErrorCode(ResponseIntegrity) // TPM_RC_INTEGRITY
	ErrorTicket    ErrorCode = ErrorCode(ResponseTicket)    // TPM_RC_TICKET

	// ErroReservedBits corresponds to TPM_RC_RESERVED_BITS and is returned as a *TPMParameterError
	// error for a command that accepts a parameter type corresponding to a TPMA prefixed type if the
	// parameter value has reserved bits set.
	ErrorReservedBits ErrorCode = ErrorCode(ResponseReservedBits)

	// ErrorBadAuth corresponds to TPM_RC_BAD_AUTH and is returned as a *TPMSessionError error for a
	// command if an authorization check fails and the authorized entity is exempt from dictionary
	// attack protections.
	ErrorBadAuth ErrorCode = ErrorCode(ResponseBadAuth)

	// ErrorExpired corresponds to TPM_RC_EXPIRED and is returned as a *TPMSessionError error for a
	// command if a policy session is used for authorization, and the session has expired.
	ErrorExpired ErrorCode = ErrorCode(ResponseExpired)

	// ErrorPolicyCC corresponds to TPM_RC_POLICY_CC and is returned as a *TPMSessionError error for
	// a command if a policy session is used for authorization, the session includes a
	// TPM2_PolicyCommandCode assertion, but the command code doesn't match the command for which the
	// authorization is being used for.
	ErrorPolicyCC ErrorCode = ErrorCode(ResponsePolicyCC)

	ErrorBinding ErrorCode = ErrorCode(ResponseBinding) // TPM_RC_BINDING

	// ErrorCurve corresponds to TPM_RC_CURVE and is returned as a *TPMParameterError for a command
	// that accepts a ECCCurve parameter if the parameter value is incorrect.
	ErrorCurve ErrorCode = ErrorCode(ResponseCurve)

	ErrorECCPoint ErrorCode = ErrorCode(ResponseECCPoint) // TPM_RC_ECC_POINT

	ErrorFWLimited ErrorCode = ErrorCode(ResponseFWLimited) // TPM_RC_FW_LIMITED

	ErrorSVNLimited ErrorCode = ErrorCode(ResponseSVNLimited) // TPM_RC_SVN_LIMITED
)

// ResponseCode returns a TPM response code for this error code.
// It will panic if it cannot be converted to a valid response code.
func (c ErrorCode) ResponseCode() ResponseCode {
	if c >= errorCode1Start {
		// Format-one
		rc := ResponseCode(c)
		if rc.P() {
			panic(fmt.Errorf("%w (error code results in a format-1 response code that overflows into bit 6)", InvalidResponseCodeError(rc)))
		}
		return rc
	}

	// Format-zero
	return rcVer1 + ResponseCode(c)
}

// TPMErrorBadTag represents a TPM response that indicates that the tag field of the command header
// was invalid (rc == [ResponseBadTag]). This error will occur when trying to execute a TPM2
// command on a TPM1.2 device (along with a response tag == [TagRspCommand]).
type TPMErrorBadTag struct {
	Command CommandCode
}

// CommandCode returns the command code that generated this error.
func (e *TPMErrorBadTag) CommandCode() CommandCode {
	return e.Command
}

// ResponseCode returns a TPM response code for this error.
func (TPMErrorBadTag) ResponseCode() ResponseCode {
	return ResponseBadTag
}

func (e *TPMErrorBadTag) Error() string {
	return fmt.Sprintf("TPM returned an error whilst executing command %s: %+s", e.Command, ResponseBadTag)
}

// TPMError represents a TPM response that indicates an error that is not associated with a
// specific handle, parameter or session (format-zero errors, 0x100 <= rc <= 0x17f), or as a
// base for errors that are associated with a specific handle, parameter or session
// (format-one errors, 0x080 < rc <= 0x0bf).
type TPMError struct {
	Command CommandCode // Command code associated with this error
	Code    ErrorCode   // Error code
}

// CommandCode returns the command code that generated this error.
func (e *TPMError) CommandCode() CommandCode {
	return e.Command
}

// ResponseCode returns a TPM response code for this error. If the error is associated
// with a format-one response, the returned response code will be the base response code.
// It will panic if it cannot be converted to a valid response code.
func (e *TPMError) ResponseCode() ResponseCode {
	return e.Code.ResponseCode()
}

func (e *TPMError) Error() (err string) {
	return fmt.Sprintf("TPM returned an error whilst executing command %s: %+s", e.Command, responseCodeFormatter(e))
}

func (e *TPMError) Is(target error) bool {
	t, ok := target.(*TPMError)
	if !ok {
		return false
	}
	return (t.Code == AnyErrorCode || t.Code == e.Code) && (t.Command == AnyCommandCode || t.Command == e.Command)
}

// TPMParameterError represents a TPM response that indicates an error that is associated with a
// command parameter (format-one errors 0x080 < rc <= 0x0bf).
type TPMParameterError struct {
	*TPMError
	Index int // Index of the parameter associated with this error in the command parameter area, starting from 1
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid parameter error response code.
func (e *TPMParameterError) ResponseCode() ResponseCode {
	if e.Index < 0 || e.Index > math.MaxUint8 {
		panic("parameter index out of range")
	}
	return e.TPMError.ResponseCode().SetParameterIndex(uint8(e.Index))
}

func (e *TPMParameterError) Error() string {
	return fmt.Sprintf("TPM returned an error for parameter %d whilst executing command %s: %+s", e.Index, e.Command, responseCodeFormatter(e))
}

func (e *TPMParameterError) Is(target error) bool {
	t, ok := target.(*TPMParameterError)
	if !ok {
		return false
	}
	return e.TPMError.Is(t.TPMError) && (t.Index == AnyParameterIndex || t.Index == e.Index)
}

func (e *TPMParameterError) Unwrap() error {
	return e.TPMError
}

// TPMSessionError represents a TPM response that indicates an error that is associated with a
// session (format-one errors 0x080 < rc <= 0x0bf).
type TPMSessionError struct {
	*TPMError
	Index int // Index of the session associated with this error in the authorization area, starting from 1
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid session error response code.
func (e *TPMSessionError) ResponseCode() ResponseCode {
	if e.Index < 0 || e.Index > math.MaxUint8 {
		panic("session index out of range")
	}
	return e.TPMError.ResponseCode().SetSessionIndex(uint8(e.Index))
}

func (e *TPMSessionError) Error() string {
	return fmt.Sprintf("TPM returned an error for session %d whilst executing command %s: %+s", e.Index, e.Command, responseCodeFormatter(e))
}

func (e *TPMSessionError) Is(target error) bool {
	t, ok := target.(*TPMSessionError)
	if !ok {
		return false
	}
	return e.TPMError.Is(t.TPMError) && (t.Index == AnySessionIndex || t.Index == e.Index)
}

func (e *TPMSessionError) Unwrap() error {
	return e.TPMError
}

// TPMHandleError represents a TPM response that indicates an error that is associated with a
// command handle (format-one errors 0x080 < rc <= 0x0bf).
type TPMHandleError struct {
	*TPMError
	// Index is the index of the handle associated with this error in the command handle area, starting from 1. An index of 0 corresponds
	// to an unspecified handle
	Index int
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid handle error response code.
func (e *TPMHandleError) ResponseCode() ResponseCode {
	if e.Index < 0 || e.Index > math.MaxUint8 {
		panic("handle index out of range")
	}
	return e.TPMError.ResponseCode().SetHandleIndex(uint8(e.Index))
}

func (e *TPMHandleError) Error() string {
	return fmt.Sprintf("TPM returned an error for handle %d whilst executing command %s: %+s", e.Index, e.Command, responseCodeFormatter(e))
}

func (e *TPMHandleError) Is(target error) bool {
	t, ok := target.(*TPMHandleError)
	if !ok {
		return false
	}
	return e.TPMError.Is(t.TPMError) && (t.Index == AnyHandleIndex || t.Index == e.Index)
}

func (e *TPMHandleError) Unwrap() error {
	return e.TPMError
}

// IsResourceUnavailableError indicates whether an error is a [ResourceUnavailableError] with the
// specified handle. To test for any handle, use [AnyHandle].
func IsResourceUnavailableError(err error, handle Handle) bool {
	return errors.Is(err, &ResourceUnavailableError{Handle: handle})
}

// IsTPMError indicates whether the error or any error within its chain is a *[TPMError] with the
// specified [ErrorCode] and [CommandCode]. To test for any error code, use [AnyErrorCode]. To test
// for any command code, use [AnyCommandCode].
func IsTPMError(err error, code ErrorCode, command CommandCode) bool {
	return errors.Is(err, &TPMError{Command: command, Code: code})
}

// AsTPMError returns a TPMError if the supplied error is one or any within its chain is.
// It will only return a TPMError if the supplied parameters match - see IsTPMError for
// how this works.
func AsTPMError(err error, code ErrorCode, command CommandCode) *TPMError {
	var outErr *TPMError
	if errors.As(err, &outErr) {
		if IsTPMError(outErr, code, command) {
			return outErr
		}
	}
	return nil
}

// IsTPMHandleError indicates whether the error or any error within its chain is a
// *[TPMHandleError] with the specified [ErrorCode], [CommandCode] and handle index. To test for
// any error code, use [AnyErrorCode]. To test for any command code, use [AnyCommandCode]. To test
// for any handle index, use [AnyHandleIndex].
func IsTPMHandleError(err error, code ErrorCode, command CommandCode, handle int) bool {
	return errors.Is(err, &TPMHandleError{TPMError: &TPMError{Command: command, Code: code}, Index: handle})
}

// AsTPMHandleError returns a TPMHandleError if the supplied error is one or any within its
// chain is. It will only return a TPMHandleError if the supplied parameters match - see
// IsTPMHandleError for how this works.
func AsTPMHandleError(err error, code ErrorCode, command CommandCode, handle int) *TPMHandleError {
	var outErr *TPMHandleError
	if errors.As(err, &outErr) {
		if IsTPMHandleError(outErr, code, command, handle) {
			return outErr
		}
	}
	return nil
}

// IsTPMParameterError indicates whether the error or any error within its chain is a
// *[TPMParameterError] with the specified [ErrorCode], [CommandCode] and parameter index. To test
// for any error code, use [AnyErrorCode]. To test for any command code, use [AnyCommandCode]. To
// test for any parameter index, use [AnyParameterIndex].
func IsTPMParameterError(err error, code ErrorCode, command CommandCode, param int) bool {
	return errors.Is(err, &TPMParameterError{TPMError: &TPMError{Command: command, Code: code}, Index: param})
}

// AsTPMParameterError returns a TPMParameterError if the supplied error is one or any within its
// chain is. It will only return a TPMParameterError if the supplied parameters match - see
// IsTPMParameterError for how this works.
func AsTPMParameterError(err error, code ErrorCode, command CommandCode, handle int) *TPMParameterError {
	var outErr *TPMParameterError
	if errors.As(err, &outErr) {
		if IsTPMParameterError(outErr, code, command, handle) {
			return outErr
		}
	}
	return nil
}

// IsTPMSessionError indicates whether the error or any error within its chain is a
// *[TPMSessionError] with the specified [ErrorCode], [CommandCode] and session index. To test for
// any error code, use [AnyErrorCode]. To test for any command code, use [AnyCommandCode]. To test
// for any session index, use [AnySessionIndex].
func IsTPMSessionError(err error, code ErrorCode, command CommandCode, session int) bool {
	return errors.Is(err, &TPMSessionError{TPMError: &TPMError{Command: command, Code: code}, Index: session})
}

// AsTPMSessionError returns a TPMSessionError if the supplied error is one or any within its
// chain is. It will only return a TPMSessionError if the supplied parameters match - see
// IsTPMSessionError for how this works.
func AsTPMSessionError(err error, code ErrorCode, command CommandCode, handle int) *TPMSessionError {
	var outErr *TPMSessionError
	if errors.As(err, &outErr) {
		if IsTPMSessionError(outErr, code, command, handle) {
			return outErr
		}
	}
	return nil
}

// IsTPMWarning indicates whether the error or any error within its chain is a *[TPMWarning] with
// the specified [WarningCode] and [CommandCode]. To test for any warning code, use
// [AnyWarningCode]. To test for any command code, use [AnyCommandCode].
func IsTPMWarning(err error, code WarningCode, command CommandCode) bool {
	return errors.Is(err, &TPMWarning{Command: command, Code: code})
}

// AsTPMWarningError returns a TPMWarning if the supplied error is one or any within its
// chain is. It will only return a TPMWarning if the supplied parameters match - see
// IsTPMWarning for how this works.
func AsTPMWarning(err error, code WarningCode, command CommandCode) *TPMWarning {
	var outErr *TPMWarning
	if errors.As(err, &outErr) {
		if IsTPMWarning(outErr, code, command) {
			return outErr
		}
	}
	return nil
}

// IsTPMVendorError indicates whether the error or any error within its chain is a
// *[TPMVendorError] with the specified [ResponseCode] and [CommandCode]. To test for
// any response code, use [AnyVendorResponseCode]. To test for any command code, use
// [AnyCommandCode].
func IsTPMVendorError(err error, rc ResponseCode, command CommandCode) bool {
	return errors.Is(err, &TPMVendorError{Command: command, Code: rc})
}

// AsTPMVendorError returns a TPMVendorError if the supplied error is one or any within
// its chainis. It wil only return a TPMVendorError if the supplied parameters match - see
// IsTPMVendorError for how this works.
func AsTPMVendorError(err error, rc ResponseCode, command CommandCode) *TPMVendorError {
	var outErr *TPMVendorError
	if errors.As(err, &outErr) {
		if IsTPMVendorError(outErr, rc, command) {
			return outErr
		}
	}
	return nil
}

// InvalidResponseCode is returned from [DecodeResponseCode] and any [TPMContext] method that
// executes a command on the TPM if the TPM response code is invalid.
type InvalidResponseCodeError ResponseCode

func (e InvalidResponseCodeError) Error() string {
	return fmt.Sprintf("invalid response code %#08x", ResponseCode(e))
}

// DecodeResponseCode decodes the ResponseCode provided via resp. If the specified response code is
// [ResponseSuccess], it returns no error, else it returns an error that is appropriate for the
// response code. The command code is used for adding context to the returned error.
//
// If the response code is invalid, an [InvalidResponseCodeError] error will be returned.
func DecodeResponseCode(command CommandCode, resp ResponseCode) error {
	switch {
	case resp == ResponseSuccess:
		return nil
	case resp == ResponseBadTag:
		return &TPMErrorBadTag{Command: command}
	case resp.F():
		// Format-one error codes
		err := &TPMError{Command: command, Code: ErrorCode(resp.E()) + errorCode1Start}
		switch {
		case resp.P():
			// Associated with a parameter
			if resp.N() == 0 {
				return InvalidResponseCodeError(resp)
			}
			return &TPMParameterError{TPMError: err, Index: int(resp.N())}
		case resp.N()&uint8(ResponseS>>rcNShift) != 0:
			// Associated with a session
			index := resp.N() &^ uint8(ResponseS>>rcNShift)
			if index == 0 {
				return InvalidResponseCodeError(resp)
			}
			return &TPMSessionError{TPMError: err, Index: int(index)}
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
			// A TPM1.2 error that isn't TPM_RC_BAD_TAG
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
