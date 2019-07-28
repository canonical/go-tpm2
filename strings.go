// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
	"strings"
)

func makeDefaultFormatter(s fmt.State, f rune) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%%")
	for _, flag := range [...]int{'+', '-', '#', ' ', '0'} {
		if s.Flag(flag) {
			fmt.Fprintf(&builder, "%c", flag)
		}
	}
	if width, ok := s.Width(); ok {
		fmt.Fprintf(&builder, "%d", width)
	}
	if prec, ok := s.Precision(); ok {
		fmt.Fprintf(&builder, ".%d", prec)
	}
	fmt.Fprintf(&builder, "%c", f)
	return builder.String()
}

func (c CommandCode) String() string {
	switch c {
	case CommandEvictControl:
		return "TPM_CC_EvictControl"
	case CommandClear:
		return "TPM_CC_Clear"
	case CommandClearControl:
		return "TPM_CC_ClearControl"
	case CommandHierarchyChangeAuth:
		return "TPM_CC_HierarchyChangeAuth"
	case CommandCreatePrimary:
		return "TPM_CC_CreatePrimary"
	case CommandDictionaryAttackLockReset:
		return "TPM_CC_DictionaryAttackLockReset"
	case CommandDictionaryAttackParameters:
		return "TPM_CC_DictionaryAttackParameters"
	case CommandPCREvent:
		return "TPM_CC_PCR_Event"
	case CommandIncrementalSelfTest:
		return "TPM_CC_IncrementalSelfTest"
	case CommandSelfTest:
		return "TPM_CC_SelfTest"
	case CommandStartup:
		return "TPM_CC_Startup"
	case CommandShutdown:
		return "TPM_CC_Shutdown"
	case CommandCertifyCreation:
		return "TPM_CC_CertifyCreation"
	case CommandObjectChangeAuth:
		return "TPM_CC_ObjectChangeAuth"
	case CommandPolicySecret:
		return "TPM_CC_PolicySecret"
	case CommandCreate:
		return "TPM_CC_Create"
	case CommandLoad:
		return "TPM_CC_Load"
	case CommandUnseal:
		return "TPM_CC_Unseal"
	case CommandContextLoad:
		return "TPM_CC_ContextLoad"
	case CommandContextSave:
		return "TPM_CC_ContextSave"
	case CommandFlushContext:
		return "TPM_CC_FlushContext"
	case CommandLoadExternal:
		return "TPM_CC_LoadExternal"
	case CommandNVReadPublic:
		return "TPM_CC_NV_ReadPublic"
	case CommandPolicyAuthValue:
		return "TPM_CC_PolicyAuthValue"
	case CommandPolicyOR:
		return "TPM_CC_PolicyOR"
	case CommandReadPublic:
		return "TPM_CC_ReadPublic"
	case CommandStartAuthSession:
		return "TPM_CC_StartAuthSession"
	case CommandGetCapability:
		return "TPM_CC_GetCapability"
	case CommandGetTestResult:
		return "TPM_CC_GetTestResult"
	case CommandPCRRead:
		return "TPM_CC_PCR_Read"
	case CommandPolicyPCR:
		return "TPM_CC_PolicyPCR"
	case CommandPolicyRestart:
		return "TPM_CC_PolicyRestart"
	case CommandPCRExtend:
		return "TPM_CC_PCR_Extend"
	case CommandPolicyGetDigest:
		return "TPM_CC_PolicyGetDigest"
	case CommandPolicyPassword:
		return "TPM_CC_PolicyPassword"
	case CommandCreateLoaded:
		return "TPM_CC_CreateLoaded"
	default:
		return fmt.Sprintf("0x%08x", uint32(c))
	}
}

func (c CommandCode) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", c.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint32(c))
	}
}

func (e ErrorCode0) String() string {
	switch e {
	case ErrorInitialize:
		return "TPM_RC_INITIALIZE"
	case ErrorFailure:
		return "TPM_RC_FAILURE"
	case ErrorSequence:
		return "TPM_RC_SEQUENCE"
	case ErrorDisabled:
		return "TPM_RC_DISABLED"
	case ErrorExclusive:
		return "TPM_RC_EXCLUSIVE"
	case ErrorAuthType:
		return "TPM_RC_AUTH_TYPE"
	case ErrorAuthMissing:
		return "TPM_RC_AUTH_MISSING"
	case ErrorPolicy:
		return "TPM_RC_POLICY"
	case ErrorPCR:
		return "TPM_RC_PCR"
	case ErrorPCRChanged:
		return "TPM_RC_PCR_CHANGED"
	case ErrorUpgrade:
		return "TPM_RC_UPGRADE"
	case ErrorTooManyContexts:
		return "TPM_RC_TOO_MANY_CONTEXTS"
	case ErrorAuthUnavailable:
		return "TPM_RC_AUTH_UNAVAILABLE"
	case ErrorReboot:
		return "TPM_RC_REBOOT"
	case ErrorUnbalanced:
		return "TPM_RC_UNBALANCED"
	case ErrorCommandSize:
		return "TPM_RC_COMMAND_SIZE"
	case ErrorCommandCode:
		return "TPM_RC_COMMAND_CODE"
	case ErrorAuthsize:
		return "TPM_RC_AUTHSIZE"
	case ErrorAuthContext:
		return "TPM_RC_AUTH_CONTEXT"
	case ErrorNVRange:
		return "TPM_RC_NV_RANGE"
	case ErrorNVSize:
		return "TPM_RC_NV_SIZE"
	case ErrorNVLocked:
		return "TPM_RC_NV_LOCKED"
	case ErrorNVAuthorization:
		return "TPM_RC_NV_AUTHORIZATION"
	case ErrorNVUninitialized:
		return "TPM_RC_NV_UNINITIALIZED"
	case ErrorNVSpace:
		return "TPM_RC_NV_SPACE"
	case ErrorNVDefined:
		return "TPM_RC_NV_DEFINED"
	case ErrorBadContext:
		return "TPM_RC_BAD_CONTEXT"
	case ErrorCpHash:
		return "TPM_RC_CPHASH"
	case ErrorParent:
		return "TPM_RC_PARENT"
	case ErrorNeedsTest:
		return "TPM_RC_NEEDS_TEST"
	case ErrorNoResult:
		return "TPM_RC_NO_RESULT"
	case ErrorSensitive:
		return "TPM_RC_SENSITIVE"
	default:
		return fmt.Sprintf("0x%02x", uint8(e))
	}
}

func (e ErrorCode0) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", e.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint8(e))
	}
}

func (e ErrorCode1) String() string {
	switch e {
	case ErrorAsymmetric:
		return "TPM_RC_ASYMMETRIC"
	case ErrorAttributes:
		return "TPM_RC_ATTRIBUTES"
	case ErrorHash:
		return "TPM_RC_HASH"
	case ErrorValue:
		return "TPM_RC_VALUE"
	case ErrorHierarchy:
		return "TPM_RC_HIERARCHY"
	case ErrorKeySize:
		return "TPM_RC_KEY_SIZE"
	case ErrorMGF:
		return "TPM_RC_MGF"
	case ErrorMode:
		return "TPM_RC_MODE"
	case ErrorType:
		return "TPM_RC_TYPE"
	case ErrorHandle:
		return "TPM_RC_HANDLE"
	case ErrorKDF:
		return "TPM_RC_KDF"
	case ErrorRange:
		return "TPM_RC_RANGE"
	case ErrorAuthFail:
		return "TPM_RC_AUTH_FAIL"
	case ErrorNonce:
		return "TPM_RC"
	case ErrorPP:
		return "TPM_RC_PP"
	case ErrorScheme:
		return "TPM_RC_SCHEME"
	case ErrorSize:
		return "TPM_RC_SIZE"
	case ErrorSymmetric:
		return "TPM_RC_SYMMETRIC"
	case ErrorTag:
		return "TPM_RC_TAG"
	case ErrorSelector:
		return "TPM_RC_SELECTOR"
	case ErrorInsufficient:
		return "TPM_RC_INSUFFICIENT"
	case ErrorSignature:
		return "TPM_RC_SIGNATURE"
	case ErrorKey:
		return "TPM_RC_KEY"
	case ErrorPolicyFail:
		return "TPM_RC_POLICY_FAIL"
	case ErrorIntegrity:
		return "TPM_RC_INTEGRITY"
	case ErrorTicket:
		return "TPM_RC_TICKET"
	case ErrorReservedBits:
		return "TPM_RC_RESERVED_BITS"
	case ErrorBadAuth:
		return "TPM_RC_BAD_AUTH"
	case ErrorExpired:
		return "TPM_RC_EXPIRED"
	case ErrorPolicyCC:
		return "TPM_RC_POLICY_CC"
	case ErrorBinding:
		return "TPM_RC_BINDING"
	case ErrorCurve:
		return "TPM_RC_CURVE"
	case ErrorECCPoint:
		return "TPM_RC_ECC_POINT"
	default:
		return fmt.Sprintf("0x%02x", uint8(e))
	}
}

func (e ErrorCode1) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", e.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint8(e))
	}
}

func (e WarningCode) String() string {
	switch e {
	case WarningContextGap:
		return "TPM_RC_CONTEXT_GAP"
	case WarningObjectMemory:
		return "TPM_RC_OBJECT_MEMORY"
	case WarningSessionMemory:
		return "TPM_RC_SESSION_MEMORY"
	case WarningMemory:
		return "TPM_RC_MEMORY"
	case WarningSessionHandles:
		return "TPM_RC_SESSION_HANDLES"
	case WarningObjectHandles:
		return "TPM_RC_OBJECT_HANDLES"
	case WarningLocality:
		return "TPM_RC_LOCALITY"
	case WarningYielded:
		return "TPM_RC_YIELDED"
	case WarningCanceled:
		return "TPM_RC_CANCELED"
	case WarningTesting:
		return "TPM_RC_TESTING"
	case WarningReferenceH0:
		return "TPM_RC_REFERENCE_H0"
	case WarningReferenceH1:
		return "TPM_RC_REFERENCE_H1"
	case WarningReferenceH2:
		return "TPM_RC_REFERENCE_H2"
	case WarningReferenceH3:
		return "TPM_RC_REFERENCE_H3"
	case WarningReferenceH4:
		return "TPM_RC_REFERENCE_H4"
	case WarningReferenceH5:
		return "TPM_RC_REFERENCE_H5"
	case WarningReferenceH6:
		return "TPM_RC_REFERENCE_H6"
	case WarningReferenceS0:
		return "TPM_RC_REFERENCE_S0"
	case WarningReferenceS1:
		return "TPM_RC_REFERENCE_S1"
	case WarningReferenceS2:
		return "TPM_RC_REFERENCE_S2"
	case WarningReferenceS3:
		return "TPM_RC_REFERENCE_S3"
	case WarningReferenceS4:
		return "TPM_RC_REFERENCE_S4"
	case WarningReferenceS5:
		return "TPM_RC_REFERENCE_S5"
	case WarningReferenceS6:
		return "TPM_RC_REFERENCE_S6"
	case WarningNVRate:
		return "TPM_RC_NV_RATE"
	case WarningLockout:
		return "TPM_RC_LOCKOUT"
	case WarningRetry:
		return "TPM_RC_RETRY"
	case WarningNVUnavailable:
		return "TPM_RC_NV_UNAVAILABLE"
	default:
		return fmt.Sprintf("0x%02x", uint8(e))
	}
}

func (e WarningCode) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", e.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint8(e))
	}
}

func (a AlgorithmId) String() string {
	switch a {
	case AlgorithmRSA:
		return "TPM_ALG_RSA"
	case AlgorithmSHA1:
		return "TPM_ALG_SHA1"
	case AlgorithmHMAC:
		return "TPM_ALG_HMAC"
	case AlgorithmAES:
		return "TPM_ALG_AES"
	case AlgorithmMGF1:
		return "TPM_ALG_MGF1"
	case AlgorithmKeyedHash:
		return "TPM_ALG_KEYEDHASH"
	case AlgorithmXOR:
		return "TPM_ALG_XOR"
	case AlgorithmSHA256:
		return "TPM_ALG_SHA256"
	case AlgorithmSHA384:
		return "TPM_ALG_SHA384"
	case AlgorithmSHA512:
		return "TPM_ALG_SHA512"
	case AlgorithmNull:
		return "TPM_ALG_NULL"
	case AlgorithmSM3_256:
		return "TPM_ALG_SM3_256"
	case AlgorithmSM4:
		return "TPM_ALG_SM4"
	case AlgorithmRSASSA:
		return "TPM_ALG_RSASSA"
	case AlgorithmRSAES:
		return "TPM_ALG_RSAES"
	case AlgorithmRSAPSS:
		return "TPM_ALG_RSAPSS"
	case AlgorithmOAEP:
		return "TPM_ALG_OAEP"
	case AlgorithmECDSA:
		return "TPM_ALG_ECDSA"
	case AlgorithmECDH:
		return "TPM_ALG_ECDH"
	case AlgorithmECDAA:
		return "TPM_ALG_ECDAA"
	case AlgorithmSM2:
		return "TPM_ALG_SM2"
	case AlgorithmECSCHNORR:
		return "TPM_ALG_ECSCHNORR"
	case AlgorithmECMQV:
		return "TPM_ALG_ECMQV"
	case AlgorithmKDF1_SP800_56A:
		return "TPM_ALG_KDF1_SP800_56A"
	case AlgorithmKDF2:
		return "TPM_ALG_KDF2"
	case AlgorithmKDF1_SP800_108:
		return "TPM_ALG_KDF1_SP800_108"
	case AlgorithmECC:
		return "TPM_ALG_ECC"
	case AlgorithmSymCipher:
		return "TPM_ALG_SYMCIPHER"
	case AlgorithmCamellia:
		return "TPM_ALG_CAMELLIA"
	case AlgorithmCTR:
		return "TPM_ALG_CTR"
	case AlgorithmOFB:
		return "TPM_ALG_OFB"
	case AlgorithmCBC:
		return "TPM_ALG_CBC"
	case AlgorithmCFB:
		return "TPM_ALG_CFB"
	case AlgorithmECB:
		return "TPM_ALG_ECB"
	default:
		return fmt.Sprintf("0x%04x", uint16(a))
	}
}

func (a AlgorithmId) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", a.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint16(a))
	}
}

func (c Capability) String() string {
	switch c {
	case CapabilityAlgs:
		return "TPM_CAP_ALGS"
	case CapabilityHandles:
		return "TPM_CAP_HANDLES"
	case CapabilityCommands:
		return "TPM_CAP_COMMANDS"
	case CapabilityPPCommands:
		return "TPM_CAP_PP_COMMANDS"
	case CapabilityAuditCommands:
		return "TPM_CAP_AUDIT_COMMANDS"
	case CapabilityPCRs:
		return "TPM_CAP_PCRS"
	case CapabilityTPMProperties:
		return "TPM_CAP_TPM_PROPERTIES"
	case CapabilityPCRProperties:
		return "TPM_CAP_PCR_PROPERTIES"
	case CapabilityECCCurves:
		return "TPM_CAP_ECC_CURVES"
	case CapabilityAuthPolicies:
		return "TPM_CAP_AUTH_POLICIES"
	default:
		return fmt.Sprintf("0x%08x", uint32(c))
	}
}

func (c Capability) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", c.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint32(c))
	}
}

var (
	errorCode0Descriptions = map[ErrorCode0]string{
		ErrorInitialize:      "TPM not initialized by TPM2_Startup or already initialized",
		ErrorFailure:         "commands not being accepted because of a TPM failure",
		ErrorSequence:        "improper use of a sequence handle",
		ErrorDisabled:        "the command is disabled",
		ErrorExclusive:       "command failed because audit sequence required exclusivity",
		ErrorAuthType:        "authorization handle is not correct for command",
		ErrorAuthMissing:     "command requires an authorization session for handle and it is not present",
		ErrorPolicy:          "policy failure in math operation or an invalid authPolicy value",
		ErrorPCR:             "PCR check fail",
		ErrorPCRChanged:      "PCR have changed since checked",
		ErrorTooManyContexts: "context ID counter is at maximum",
		ErrorAuthUnavailable: "authValue or authPolicy is not available for selected entity",
		ErrorReboot: "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume " +
			"operation",
		ErrorUnbalanced: "the protection algorithms (hash and symmetric) are not reasonably balanced. " +
			"The digest size of the hash must be larger than the key size of the symmetric algorithm",
		ErrorCommandSize: "command commandSize value is inconsistent with contents of the command " +
			"buffer; either the size is not the same as the octets loaded by the hardware " +
			"interface layer or the value is not large enough to hold a command header",
		ErrorCommandCode: "command code not supported",
		ErrorAuthsize: "the value of authorizationSize is out of range or the number of octets in the " +
			"Authorization Area is greater than required",
		ErrorAuthContext: "use of an authorization session with a context command or another command " +
			"that cannot have an authorization session",
		ErrorNVRange:  "NV offset+size is out of range",
		ErrorNVSize:   "Requested allocation size is larger than allowed",
		ErrorNVLocked: "NV access locked",
		ErrorNVAuthorization: "NV access authorization fails in command actions (this failure does " +
			"not affect lockout.action)",
		ErrorNVUninitialized: "an NV Index is used before being initialized or the state saved by " +
			"TPM2_Shutdown(STATE) could not be restored",
		ErrorNVSpace:    "insufficient space for NV allocation",
		ErrorNVDefined:  "NV Index or persistent object already defined",
		ErrorBadContext: "context in TPM2_ContextLoad() is not valid",
		ErrorCpHash:     "cpHash value already set or not correct for use",
		ErrorParent:     "handle for parent is not a valid parent",
		ErrorNeedsTest:  "some function needs testing",
		ErrorNoResult: "returned when an internal function cannot process a request due to an " +
			"unspecified problem. This code is usually related to invalid parameters that are not " +
			"properly filtered by the input unmarshaling code",
		ErrorSensitive: "the sensitive area did not unmarshal correctly after decryption"}

	errorCode1Descriptions = map[ErrorCode1]string{
		ErrorAsymmetric: "asymmetric algorithm not supported or not correct",
		ErrorAttributes: "inconsistent attributes",
		ErrorHash:       "hash algorithm not supported or not appropriate",
		ErrorValue:      "value is out of range or is not correct for the context",
		ErrorHierarchy:  "hierarchy is not enabled or is not correct for the use",
		ErrorKeySize:    "key size is not supported",
		ErrorMGF:        "mask generation function not supported",
		ErrorMode:       "mode of operation not supported",
		ErrorType:       "the type of the value is not appropriate for the use",
		ErrorHandle:     "the handle is not correct for the use",
		ErrorKDF:        "unsupported key derivation function or function not appropriate for use",
		ErrorRange:      "value was out of allowed range",
		ErrorAuthFail:   "the authorization HMAC check failed and DA counter incremented",
		ErrorNonce:      "invalid nonce size or nonce value mismatch",
		ErrorPP:         "authorization requires assertion of PP",
		ErrorScheme:     "unsupported or incompatible scheme",
		ErrorSize:       "structure is the wrong size",
		ErrorSymmetric:  "unsupported symmetric algorithm or key size, or not appropriate for instance",
		ErrorTag:        "incorrect structure tag",
		ErrorSelector:   "union selector is incorrect",
		ErrorInsufficient: "the TPM was unable to unmarshal a value because there were not enough " +
			"octets in the input buffer",
		ErrorSignature:    "the signature is not valid",
		ErrorKey:          "key fields are not compatible with the selected use",
		ErrorPolicyFail:   "a policy check failed",
		ErrorIntegrity:    "integrity check failed",
		ErrorTicket:       "invalid ticket",
		ErrorReservedBits: "reserved bits not set to zero as required",
		ErrorBadAuth:      "authorization failure without DA implications",
		ErrorExpired:      "the policy has expired",
		ErrorPolicyCC: "the commandCode in the policy is not the commandCode of the command or the " +
			"command code in a policy command references a command that is not implemented",
		ErrorBinding:  "public and sensitive portions of an object are not cryptographically bound",
		ErrorCurve:    "curve not supported",
		ErrorECCPoint: "point is not on the required curve"}

	warningCodeDescriptions = map[WarningCode]string{
		WarningContextGap:    "gap for context ID is too large",
		WarningObjectMemory:  "out of memory for object contexts",
		WarningSessionMemory: "out of memory for session contexts",
		WarningMemory:        "out of shared object/session memory or need space for internal operations",
		WarningSessionHandles: "out of session handles – a session must be flushed before a new " +
			"session may be created",
		WarningObjectHandles: "out of object handles – the handle space for objects is depleted and " +
			"a reboot is required",
		WarningLocality: "bad locality",
		WarningYielded: "the TPM has suspended operation on the command; forward progress was made " +
			"and the command may be retried",
		WarningCanceled: "the command was canceled",
		WarningTesting:  "TPM is performing self-tests",
		WarningReferenceH0: "the 1st handle in the handle area references a transient object or " +
			"session that is not loaded",
		WarningReferenceH1: "the 2nd handle in the handle area references a transient object or " +
			"session that is not loaded",
		WarningReferenceH2: "the 3rd handle in the handle area references a transient object or " +
			"session that is not loaded",
		WarningReferenceH3: "the 4th handle in the handle area references a transient object or " +
			"session that is not loaded",
		WarningReferenceH4: "the 5th handle in the handle area references a transient object or " +
			"session that is not loaded",
		WarningReferenceH5: "the 6th handle in the handle area references a transient object or " +
			"session that is not loaded",
		WarningReferenceH6: "the 7th handle in the handle area references a transient object or " +
			"session that is not loaded",
		WarningReferenceS0: "the 1st authorization session handle references a session that is not " +
			"loaded",
		WarningReferenceS1: "the 2nd authorization session handle references a session that is not " +
			"loaded",
		WarningReferenceS2: "the 3rd authorization session handle references a session that is not " +
			"loaded",
		WarningReferenceS3: "the 4th authorization session handle references a session that is not " +
			"loaded",
		WarningReferenceS4: "the 5th authorization session handle references a session that is not " +
			"loaded",
		WarningReferenceS5: "the 6th authorization session handle references a session that is not " +
			"loaded",
		WarningReferenceS6: "the 7th authorization session handle references a session that is not " +
			"loaded",
		WarningNVRate: "the TPM is rate-limiting accesses to prevent wearout of NV",
		WarningLockout: "authorizations for objects subject to DA protection are not allowed at this " +
			"time because the TPM is in DA lockout mode",
		WarningRetry:         "the TPM was not able to start the command",
		WarningNVUnavailable: "the command may require writing of NV and NV is not current accessible"}
)
