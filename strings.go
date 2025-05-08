// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"fmt"
)

func makeDefaultFormatter(s fmt.State, f rune) string {
	var builder bytes.Buffer
	builder.WriteString("%")
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
	builder.WriteRune(f)
	return builder.String()
}

func (m TPMManufacturer) String() string {
	switch m {
	case TPMManufacturerAMD:
		return "AMD"
	case TPMManufacturerATML:
		return "Atmel"
	case TPMManufacturerBRCM:
		return "Broadcom"
	case TPMManufacturerHPE:
		return "HPE"
	case TPMManufacturerIBM:
		return "IBM"
	case TPMManufacturerIFX:
		return "Infineon"
	case TPMManufacturerINTC:
		return "Intel"
	case TPMManufacturerLEN:
		return "Lenovo"
	case TPMManufacturerMSFT:
		return "Microsoft"
	case TPMManufacturerNSM:
		return "National Semiconductor"
	case TPMManufacturerNTZ:
		return "Nationz"
	case TPMManufacturerNTC:
		return "Nuvoton Technology"
	case TPMManufacturerQCOM:
		return "Qualcomm"
	case TPMManufacturerSMSC:
		return "SMSC"
	case TPMManufacturerSTM:
		return "ST Microelectronics"
	case TPMManufacturerSMSN:
		return "Samsung"
	case TPMManufacturerSNS:
		return "Sinosun"
	case TPMManufacturerTXN:
		return "Texas Instruments"
	case TPMManufacturerWEC:
		return "Winbond"
	case TPMManufacturerROCC:
		return "Fuzhou Rockchip"
	case TPMManufacturerGOOG:
		return "Google"
	default:
		return fmt.Sprintf("0x%08x", uint32(m))
	}
}

func (m TPMManufacturer) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", m.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint32(m))
	}
}

func (c CommandCode) String() string {
	switch c {
	case CommandNVUndefineSpaceSpecial:
		return "TPM_CC_NV_UndefineSpaceSpecial"
	case CommandEvictControl:
		return "TPM_CC_EvictControl"
	case CommandHierarchyControl:
		return "TPM_CC_HierarchyControl"
	case CommandNVUndefineSpace:
		return "TPM_CC_NV_UndefineSpace"
	case CommandClear:
		return "TPM_CC_Clear"
	case CommandClearControl:
		return "TPM_CC_ClearControl"
	case CommandClockSet:
		return "TPM_CC_ClockSet"
	case CommandHierarchyChangeAuth:
		return "TPM_CC_HierarchyChangeAuth"
	case CommandNVDefineSpace:
		return "TPM_CC_NV_DefineSpace"
	case CommandPCRAllocate:
		return "TPM_CC_PCR_Allocate"
	case CommandSetPrimaryPolicy:
		return "TPM_CC_SetPrimaryPolicy"
	case CommandClockRateAdjust:
		return "TPM_CC_ClockRateAdjust"
	case CommandCreatePrimary:
		return "TPM_CC_CreatePrimary"
	case CommandNVGlobalWriteLock:
		return "TPM_CC_NV_GlobalWriteLock"
	case CommandGetCommandAuditDigest:
		return "TPM_CC_GetCommandAuditDigest"
	case CommandNVIncrement:
		return "TPM_CC_NV_Increment"
	case CommandNVSetBits:
		return "TPM_CC_NV_SetBits"
	case CommandNVExtend:
		return "TPM_CC_NV_Extend"
	case CommandNVWrite:
		return "TPM_CC_NV_Write"
	case CommandNVWriteLock:
		return "TPM_CC_NV_WriteLock"
	case CommandDictionaryAttackLockReset:
		return "TPM_CC_DictionaryAttackLockReset"
	case CommandDictionaryAttackParameters:
		return "TPM_CC_DictionaryAttackParameters"
	case CommandNVChangeAuth:
		return "TPM_CC_NV_ChangeAuth"
	case CommandPCREvent:
		return "TPM_CC_PCR_Event"
	case CommandPCRReset:
		return "TPM_CC_PCR_Reset"
	case CommandSequenceComplete:
		return "TPM_CC_SequenceComplete"
	case CommandSetCommandCodeAuditStatus:
		return "TPM_CC_SetCommandCodeAuditStatus"
	case CommandIncrementalSelfTest:
		return "TPM_CC_IncrementalSelfTest"
	case CommandSelfTest:
		return "TPM_CC_SelfTest"
	case CommandStartup:
		return "TPM_CC_Startup"
	case CommandShutdown:
		return "TPM_CC_Shutdown"
	case CommandStirRandom:
		return "TPM_CC_StirRandom"
	case CommandActivateCredential:
		return "TPM_CC_ActivateCredential"
	case CommandCertify:
		return "TPM_CC_Certify"
	case CommandPolicyNV:
		return "TPM_CC_PolicyNV"
	case CommandCertifyCreation:
		return "TPM_CC_CertifyCreation"
	case CommandDuplicate:
		return "TPM_CC_Duplicate"
	case CommandGetTime:
		return "TPM_CC_GetTime"
	case CommandGetSessionAuditDigest:
		return "TPM_CC_GetSessionAuditDigest"
	case CommandNVRead:
		return "TPM_CC_NV_Read"
	case CommandNVReadLock:
		return "TPM_CC_NV_ReadLock"
	case CommandObjectChangeAuth:
		return "TPM_CC_ObjectChangeAuth"
	case CommandPolicySecret:
		return "TPM_CC_PolicySecret"
	case CommandCreate:
		return "TPM_CC_Create"
	case CommandECDHZGen:
		return "TPM_CC_ECDH_ZGen"
	case CommandHMAC:
		return "TPM_CC_HMAC"
	case CommandImport:
		return "TPM_CC_Import"
	case CommandLoad:
		return "TPM_CC_Load"
	case CommandQuote:
		return "TPM_CC_Quote"
	case CommandRSADecrypt:
		return "TPM_CC_RSA_Decrypt"
	case CommandHMACStart:
		return "TPM_CC_HMAC_Start"
	case CommandSequenceUpdate:
		return "TPM_CC_SequenceUpdate"
	case CommandSign:
		return "TPM_CC_Sign"
	case CommandUnseal:
		return "TPM_CC_Unseal"
	case CommandPolicySigned:
		return "TPM_CC_PolicySigned"
	case CommandContextLoad:
		return "TPM_CC_ContextLoad"
	case CommandContextSave:
		return "TPM_CC_ContextSave"
	case CommandECDHKeyGen:
		return "TPM_CC_ECDH_KeyGen"
	case CommandFlushContext:
		return "TPM_CC_FlushContext"
	case CommandLoadExternal:
		return "TPM_CC_LoadExternal"
	case CommandMakeCredential:
		return "TPM_CC_MakeCredential"
	case CommandNVReadPublic:
		return "TPM_CC_NV_ReadPublic"
	case CommandPolicyAuthorize:
		return "TPM_CC_PolicyAuthorize"
	case CommandPolicyAuthValue:
		return "TPM_CC_PolicyAuthValue"
	case CommandPolicyCommandCode:
		return "TPM_CC_PolicyCommandCode"
	case CommandPolicyCounterTimer:
		return "TPM_CC_PolicyCounterTimer"
	case CommandPolicyCpHash:
		return "TPM_CC_PolicyCpHash"
	case CommandPolicyLocality:
		return "TPM_CC_PolicyLocality"
	case CommandPolicyNameHash:
		return "TPM_CC_PolicyNameHash"
	case CommandPolicyOR:
		return "TPM_CC_PolicyOR"
	case CommandPolicyTicket:
		return "TPM_CC_PolicyTicket"
	case CommandReadPublic:
		return "TPM_CC_ReadPublic"
	case CommandRSAEncrypt:
		return "TPM_CC_RSA_Encrypt"
	case CommandStartAuthSession:
		return "TPM_CC_StartAuthSession"
	case CommandVerifySignature:
		return "TPM_CC_VerifySignature"
	case CommandECCParameters:
		return "TPM_CC_ECC_Parameters"
	case CommandGetCapability:
		return "TPM_CC_GetCapability"
	case CommandGetRandom:
		return "TPM_CC_GetRandom"
	case CommandGetTestResult:
		return "TPM_CC_GetTestResult"
	case CommandHash:
		return "TPM_CC_Hash"
	case CommandPCRRead:
		return "TPM_CC_PCR_Read"
	case CommandPolicyPCR:
		return "TPM_CC_PolicyPCR"
	case CommandPolicyRestart:
		return "TPM_CC_PolicyRestart"
	case CommandReadClock:
		return "TPM_CC_ReadClock"
	case CommandPCRExtend:
		return "TPM_CC_PCR_Extend"
	case CommandNVCertify:
		return "TPM_CC_NV_Certify"
	case CommandEventSequenceComplete:
		return "TPM_CC_EventSequenceComplete"
	case CommandHashSequenceStart:
		return "TPM_CC_HashSequenceStart"
	case CommandPolicyDuplicationSelect:
		return "TPM_CC_PolicyDuplicationSelect"
	case CommandPolicyGetDigest:
		return "TPM_CC_PolicyGetDigest"
	case CommandTestParms:
		return "TPM_CC_TestParms"
	case CommandCommit:
		return "TPM_CC_Commit"
	case CommandPolicyPassword:
		return "TPM_CC_PolicyPassword"
	case CommandPolicyNvWritten:
		return "TPM_CC_PolicyNvWritten"
	case CommandPolicyTemplate:
		return "TPM_CC_PolicyTemplate"
	case CommandCreateLoaded:
		return "TPM_CC_CreateLoaded"
	case CommandPolicyAuthorizeNV:
		return "TPM_CC_PolicyAuthorizeNV"
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

// String implements [fmt.Stringer].
func (rc ResponseCode) String() string {
	var str string

	switch rc.Base() {
	case ResponseSuccess:
		return "TPM_RC_SUCCESS"
	case ResponseBadTag:
		return "TPM_RC_BAD_TAG"
	// TCG defined TPM2 format-zero error codes start here
	case ResponseInitialize:
		return "TPM_RC_INITIALIZE"
	case ResponseFailure:
		return "TPM_RC_FAILURE"
	case ResponseSequence:
		return "TPM_RC_SEQUENCE"
	case ResponseDisabled:
		return "TPM_RC_DISABLED"
	case ResponseExclusive:
		return "TPM_RC_EXCLUSIVE"
	case ResponseAuthType:
		return "TPM_RC_AUTH_TYPE"
	case ResponseAuthMissing:
		return "TPM_RC_AUTH_MISSING"
	case ResponsePolicy:
		return "TPM_RC_POLICY"
	case ResponsePCR:
		return "TPM_RC_PCR"
	case ResponsePCRChanged:
		return "TPM_RC_PCR_CHANGED"
	case ResponseUpgrade:
		return "TPM_RC_UPGRADE"
	case ResponseTooManyContexts:
		return "TPM_RC_TOO_MANY_CONTEXTS"
	case ResponseAuthUnavailable:
		return "TPM_RC_AUTH_UNAVAILABLE"
	case ResponseReboot:
		return "TPM_RC_REBOOT"
	case ResponseUnbalanced:
		return "TPM_RC_UNBALANCED"
	case ResponseCommandSize:
		return "TPM_RC_COMMAND_SIZE"
	case ResponseCommandCode:
		return "TPM_RC_COMMAND_CODE"
	case ResponseAuthsize:
		return "TPM_RC_AUTHSIZE"
	case ResponseAuthContext:
		return "TPM_RC_AUTH_CONTEXT"
	case ResponseNVRange:
		return "TPM_RC_NV_RANGE"
	case ResponseNVSize:
		return "TPM_RC_NV_SIZE"
	case ResponseNVLocked:
		return "TPM_RC_NV_LOCKED"
	case ResponseNVAuthorization:
		return "TPM_RC_NV_AUTHORIZATION"
	case ResponseNVUninitialized:
		return "TPM_RC_NV_UNINITIALIZED"
	case ResponseNVSpace:
		return "TPM_RC_NV_SPACE"
	case ResponseNVDefined:
		return "TPM_RC_NV_DEFINED"
	case ResponseBadContext:
		return "TPM_RC_BAD_CONTEXT"
	case ResponseCpHash:
		return "TPM_RC_CPHASH"
	case ResponseParent:
		return "TPM_RC_PARENT"
	case ResponseNeedsTest:
		return "TPM_RC_NEEDS_TEST"
	case ResponseNoResult:
		return "TPM_RC_NO_RESULT"
	case ResponseSensitive:
		return "TPM_RC_SENSITIVE"
	// Format 1 error codes start here
	case ResponseAsymmetric:
		str = "TPM_RC_ASYMMETRIC"
	case ResponseAttributes:
		str = "TPM_RC_ATTRIBUTES"
	case ResponseHash:
		str = "TPM_RC_HASH"
	case ResponseValue:
		str = "TPM_RC_VALUE"
	case ResponseHierarchy:
		str = "TPM_RC_HIERARCHY"
	case ResponseKeySize:
		str = "TPM_RC_KEY_SIZE"
	case ResponseMGF:
		str = "TPM_RC_MGF"
	case ResponseMode:
		str = "TPM_RC_MODE"
	case ResponseType:
		str = "TPM_RC_TYPE"
	case ResponseHandle:
		str = "TPM_RC_HANDLE"
	case ResponseKDF:
		str = "TPM_RC_KDF"
	case ResponseRange:
		str = "TPM_RC_RANGE"
	case ResponseAuthFail:
		str = "TPM_RC_AUTH_FAIL"
	case ResponseNonce:
		str = "TPM_RC_NONCE"
	case ResponsePP:
		str = "TPM_RC_PP"
	case ResponseScheme:
		str = "TPM_RC_SCHEME"
	case ResponseSize:
		str = "TPM_RC_SIZE"
	case ResponseSymmetric:
		str = "TPM_RC_SYMMETRIC"
	case ResponseTag:
		str = "TPM_RC_TAG"
	case ResponseSelector:
		str = "TPM_RC_SELECTOR"
	case ResponseInsufficient:
		str = "TPM_RC_INSUFFICIENT"
	case ResponseSignature:
		str = "TPM_RC_SIGNATURE"
	case ResponseKey:
		str = "TPM_RC_KEY"
	case ResponsePolicyFail:
		str = "TPM_RC_POLICY_FAIL"
	case ResponseIntegrity:
		str = "TPM_RC_INTEGRITY"
	case ResponseTicket:
		str = "TPM_RC_TICKET"
	case ResponseReservedBits:
		str = "TPM_RC_RESERVED_BITS"
	case ResponseBadAuth:
		str = "TPM_RC_BAD_AUTH"
	case ResponseExpired:
		str = "TPM_RC_EXPIRED"
	case ResponsePolicyCC:
		str = "TPM_RC_POLICY_CC"
	case ResponseBinding:
		str = "TPM_RC_BINDING"
	case ResponseCurve:
		str = "TPM_RC_CURVE"
	case ResponseECCPoint:
		str = "TPM_RC_ECC_POINT"
	// TCG defined TPM2 format-zero warning codes start here
	case ResponseContextGap:
		return "TPM_RC_CONTEXT_GAP"
	case ResponseObjectMemory:
		return "TPM_RC_OBJECT_MEMORY"
	case ResponseSessionMemory:
		return "TPM_RC_SESSION_MEMORY"
	case ResponseMemory:
		return "TPM_RC_MEMORY"
	case ResponseSessionHandles:
		return "TPM_RC_SESSION_HANDLES"
	case ResponseObjectHandles:
		return "TPM_RC_OBJECT_HANDLES"
	case ResponseLocality:
		return "TPM_RC_LOCALITY"
	case ResponseYielded:
		return "TPM_RC_YIELDED"
	case ResponseCanceled:
		return "TPM_RC_CANCELED"
	case ResponseTesting:
		return "TPM_RC_TESTING"
	case ResponseReferenceH0:
		return "TPM_RC_REFERENCE_H0"
	case ResponseReferenceH1:
		return "TPM_RC_REFERENCE_H1"
	case ResponseReferenceH2:
		return "TPM_RC_REFERENCE_H2"
	case ResponseReferenceH3:
		return "TPM_RC_REFERENCE_H3"
	case ResponseReferenceH4:
		return "TPM_RC_REFERENCE_H4"
	case ResponseReferenceH5:
		return "TPM_RC_REFERENCE_H5"
	case ResponseReferenceH6:
		return "TPM_RC_REFERENCE_H6"
	case ResponseReferenceS0:
		return "TPM_RC_REFERENCE_S0"
	case ResponseReferenceS1:
		return "TPM_RC_REFERENCE_S1"
	case ResponseReferenceS2:
		return "TPM_RC_REFERENCE_S2"
	case ResponseReferenceS3:
		return "TPM_RC_REFERENCE_S3"
	case ResponseReferenceS4:
		return "TPM_RC_REFERENCE_S4"
	case ResponseReferenceS5:
		return "TPM_RC_REFERENCE_S5"
	case ResponseReferenceS6:
		return "TPM_RC_REFERENCE_S6"
	case ResponseNVRate:
		return "TPM_RC_NV_RATE"
	case ResponseLockout:
		return "TPM_RC_LOCKOUT"
	case ResponseRetry:
		return "TPM_RC_RETRY"
	case ResponseNVUnavailable:
		return "TPM_RC_NV_UNAVAILABLE"
	default:
		str = fmt.Sprintf("%#08x", uint32(rc))
		if !rc.F() {
			return str
		}
	}

	// For format-one response codes, add the parameter, session or handle indicator.
	switch {
	case rc.P():
		str += " + TPM_RC_P"
	case rc.N()&uint8(rcNSessionIndicator>>rcNShift) != 0:
		str += " + TPM_RC_S"
	default:
		str += " + TPM_RC_H"
	}

	// For format-one response codes, add the parameter, session or handle index.
	var n uint8
	switch {
	case rc.N() == 0:
		// No associated parameter, session, or handle index.
		return str
	case rc.P():
		// There is an associated parameter index - use the full 4 bits of N.
		n = rc.N()
	default:
		// There is an associated session or handle index, depending on the
		// MSB of N. Use the lower 3 bits of N.
		n = rc.N() &^ uint8(rcNSessionIndicator>>rcNShift)
	}

	switch {
	case n <= 0xf:
		return fmt.Sprintf("%s + TPM_RC_%X", str, n)
	default:
		return fmt.Sprintf("%s + %#02x", str, n)
	}
}

// Format implements [fmt.Formatter]. The '+' flag for the 's' or 'v' verb will
// append a description of the response code if one exists.
func (rc ResponseCode) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", rc.String())
		if s.Flag('+') {
			desc, hasDesc := rcDescriptions[rc.Base()]
			if hasDesc {
				fmt.Fprintf(s, " (%s)", desc)
			}
		}
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint32(rc))
	}
}

type responseCoder interface {
	ResponseCode() ResponseCode
}

type responseCodeFormatterImpl[RC responseCoder] struct {
	rc RC
}

func (formatter responseCodeFormatterImpl[RC]) String() string {
	return formatter.rc.ResponseCode().String()
}

func (formatter responseCodeFormatterImpl[RC]) Format(s fmt.State, f rune) {
	formatter.rc.ResponseCode().Format(s, f)
}

func responseCodeFormatter[RC responseCoder](rc RC) responseCodeFormatterImpl[RC] {
	return responseCodeFormatterImpl[RC]{rc: rc}
}

// String implements [fmt.Stringer].
func (e ErrorCode) String() string {
	// An invalid error code may generate a panic, but this is caught
	// by the fmt package.
	return responseCodeFormatter(e).String()
}

// Format implements [fmt.Formatter].
func (e ErrorCode) Format(s fmt.State, f rune) {
	// An invalid error code may generate a panic, but this is caught
	// by the fmt package.
	responseCodeFormatter(e).Format(s, f)
}

// String implements [fmt.Stringer].
func (e WarningCode) String() string {
	// An invalid warning code may generate a panic, but this is caught
	// by the fmt package.
	return responseCodeFormatter(e).String()
}

// Format implements [fmt.Formatter].
func (e WarningCode) Format(s fmt.State, f rune) {
	// An invalid warning code may generate a panic, but this is caught
	// by the fmt package.
	responseCodeFormatter(e).Format(s, f)
}

func (h Handle) String() string {
	switch h {
	case HandleOwner:
		return "TPM_RH_OWNER"
	case HandleNull:
		return "TPM_RH_NULL"
	case HandleUnassigned:
		return "TPM_RH_UNASSIGNED"
	case HandlePW:
		return "TPM_RS_PW"
	case HandleLockout:
		return "TPM_RH_LOCKOUT"
	case HandleEndorsement:
		return "TPM_RH_ENDORSEMENT"
	case HandlePlatform:
		return "TPM_RH_PLATFORM"
	case HandlePlatformNV:
		return "TPM_RH_PLATFORM_NV"
	case HandleFWOwner:
		return "TPM_RH_FW_OWNER"
	case HandleFWEndorsement:
		return "TPM_RH_FW_ENDORSEMENT"
	case HandleFWPlatform:
		return "TPM_RH_FW_PLATFORM"
	case HandleFWNull:
		return "TPM_RH_FW_NULL"
	case HandleSVNOwnerBase:
		return "TPM_RH_SVN_OWNER_BASE"
	case HandleSVNEndorsementBase:
		return "TPM_RH_SVN_ENDORSEMENT_BASE"
	case HandleSVNPlatformBase:
		return "TPM_RH_SVN_PLATFORM_BASE"
	case HandleSVNNullBase:
		return "TPM_RH_SVN_NULL_BASE"
	default:
		return fmt.Sprintf("0x%08x", uint32(h))
	}
}

func (h Handle) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", h.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint32(h))
	}
}

func (a AlgorithmId) String() string {
	switch a {
	case AlgorithmRSA:
		return "TPM_ALG_RSA"
	case AlgorithmTDES:
		return "TPM_ALG_TDES"
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
	case AlgorithmSHA256_192:
		return "TPM_ALG_SHA256_192"
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
	case AlgorithmECSchnorr:
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
	case AlgorithmSHA3_256:
		return "TPM_ALG_SHA3_256"
	case AlgorithmSHA3_384:
		return "TPM_ALG_SHA3_384"
	case AlgorithmSHA3_512:
		return "TPM_ALG_SHA3_512"
	case AlgorithmSHAKE128:
		return "TPM_ALG_SHAKE128"
	case AlgorithmSHAKE256:
		return "TPM_ALG_SHAKE256"
	case AlgorithmSHAKE256_192:
		return "TPM_ALG_SHAKE256_192"
	case AlgorithmSHAKE256_256:
		return "TPM_ALG_SHAKE256_256"
	case AlgorithmSHAKE256_512:
		return "TPM_ALG_SHAKE256_512"
	case AlgorithmCMAC:
		return "TPM_ALG_CMAC"
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
	case AlgorithmCCM:
		return "TPM_ALG_CCM"
	case AlgorithmGCM:
		return "TPM_ALG_GCM"
	case AlgorithmKW:
		return "TPM_ALG_KW"
	case AlgorithmKWP:
		return "TPM_ALG_KWP"
	case AlgorithmEAX:
		return "TPM_ALG_EAX"
	case AlgorithmEDDSA:
		return "TPM_ALG_EDDSA"
	case AlgorithmEDDSA_PH:
		return "TPM_ALG_EDDSA_PH"
	case AlgorithmLMS:
		return "TPM_ALG_LMS"
	case AlgorithmXMSS:
		return "TPM_ALG_XMSS"
	case AlgorithmKeyedXOF:
		return "TPM_ALG_KEYEDXOF"
	case AlgorithmKMACXOF128:
		return "TPM_ALG_KMACXOF128"
	case AlgorithmKMACXOF256:
		return "TPM_ALG_KMACXOF256"
	case AlgorithmKMAC128:
		return "TPM_ALG_KMAC128"
	case AlgorithmKMAC256:
		return "TPM_ALG_KMAC256"
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

func (a HashAlgorithmId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a SymAlgorithmId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a SymObjectAlgorithmId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a SymModeId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a KDFAlgorithmId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a SigSchemeId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a KeyedHashSchemeId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a AsymSchemeId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a RSASchemeId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a ECCSchemeId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
}

func (a ObjectTypeId) Format(s fmt.State, f rune) {
	AlgorithmId(a).Format(s, f)
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

func (o ArithmeticOp) String() string {
	switch o {
	case OpEq:
		return "TPM_EO_EQ"
	case OpNeq:
		return "TPM_OP_NEQ"
	case OpSignedGT:
		return "TPM_EO_SIGNED_GT"
	case OpUnsignedGT:
		return "TPM_EO_UNSIGNED_GT"
	case OpSignedLT:
		return "TPM_EO_SIGNED_LT"
	case OpUnsignedLT:
		return "TPM_EO_UNSIGNED_LT"
	case OpSignedGE:
		return "TPM_EO_SIGNED_GE"
	case OpUnsignedGE:
		return "TPM_EO_UNSIGNED_GE"
	case OpSignedLE:
		return "TPM_EO_SIGNED_LE"
	case OpUnsignedLE:
		return "TPM_EO_UNSIGNED_LE"
	case OpBitset:
		return "TPM_EO_BITSET"
	case OpBitclear:
		return "TPM_EO_BITCLEAR"
	default:
		return fmt.Sprintf("0x%08x", uint16(o))
	}
}

func (o ArithmeticOp) Format(s fmt.State, f rune) {
	switch f {
	case 's', 'v':
		fmt.Fprintf(s, "%s", o.String())
	default:
		fmt.Fprintf(s, makeDefaultFormatter(s, f), uint16(o))
	}
}

var (
	rcDescriptions = map[ResponseCode]string{
		ResponseBadTag:          "defined for compatibility with TPM 1.2",
		ResponseInitialize:      "TPM not initialized by TPM2_Startup or already initialized",
		ResponseFailure:         "commands not being accepted because of a TPM failure",
		ResponseSequence:        "improper use of a sequence handle",
		ResponseDisabled:        "the command is disabled",
		ResponseExclusive:       "command failed because audit sequence required exclusivity",
		ResponseAuthType:        "authorization handle is not correct for command",
		ResponseAuthMissing:     "command requires an authorization session for handle and it is not present",
		ResponsePolicy:          "policy failure in math operation or an invalid authPolicy value",
		ResponsePCR:             "PCR check fail",
		ResponsePCRChanged:      "PCR have changed since checked",
		ResponseTooManyContexts: "context ID counter is at maximum",
		ResponseAuthUnavailable: "authValue or authPolicy is not available for selected entity",
		ResponseReboot:          "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation",
		ResponseUnbalanced: "the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be " +
			"larger than the key size of the symmetric algorithm",
		ResponseCommandSize: "command commandSize value is inconsistent with contents of the command buffer; either the size is not the same " +
			"as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header",
		ResponseCommandCode: "command code not supported",
		ResponseAuthsize: "the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than " +
			"required",
		ResponseAuthContext: "use of an authorization session with a context command or another command that cannot have an authorization " +
			"session",
		ResponseNVRange:         "NV offset+size is out of range",
		ResponseNVSize:          "Requested allocation size is larger than allowed",
		ResponseNVLocked:        "NV access locked",
		ResponseNVAuthorization: "NV access authorization fails in command actions (this failure does not affect lockout.action)",
		ResponseNVUninitialized: "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be " +
			"restored",
		ResponseNVSpace:    "insufficient space for NV allocation",
		ResponseNVDefined:  "NV Index or persistent object already defined",
		ResponseBadContext: "context in TPM2_ContextLoad() is not valid",
		ResponseCpHash:     "cpHash value already set or not correct for use",
		ResponseParent:     "handle for parent is not a valid parent",
		ResponseNeedsTest:  "some function needs testing",
		ResponseNoResult: "returned when an internal function cannot process a request due to an unspecified problem. This code is usually " +
			"related to invalid parameters that are not properly filtered by the input unmarshaling code",
		ResponseSensitive:    "the sensitive area did not unmarshal correctly after decryption",
		ResponseAsymmetric:   "asymmetric algorithm not supported or not correct",
		ResponseAttributes:   "inconsistent attributes",
		ResponseHash:         "hash algorithm not supported or not appropriate",
		ResponseValue:        "value is out of range or is not correct for the context",
		ResponseHierarchy:    "hierarchy is not enabled or is not correct for the use",
		ResponseKeySize:      "key size is not supported",
		ResponseMGF:          "mask generation function not supported",
		ResponseMode:         "mode of operation not supported",
		ResponseType:         "the type of the value is not appropriate for the use",
		ResponseHandle:       "the handle is not correct for the use",
		ResponseKDF:          "unsupported key derivation function or function not appropriate for use",
		ResponseRange:        "value was out of allowed range",
		ResponseAuthFail:     "the authorization HMAC check failed and DA counter incremented",
		ResponseNonce:        "invalid nonce size or nonce value mismatch",
		ResponsePP:           "authorization requires assertion of PP",
		ResponseScheme:       "unsupported or incompatible scheme",
		ResponseSize:         "structure is the wrong size",
		ResponseSymmetric:    "unsupported symmetric algorithm or key size, or not appropriate for instance",
		ResponseTag:          "incorrect structure tag",
		ResponseSelector:     "union selector is incorrect",
		ResponseInsufficient: "the TPM was unable to unmarshal a value because there were not enough octets in the input buffer",
		ResponseSignature:    "the signature is not valid",
		ResponseKey:          "key fields are not compatible with the selected use",
		ResponsePolicyFail:   "a policy check failed",
		ResponseIntegrity:    "integrity check failed",
		ResponseTicket:       "invalid ticket",
		ResponseReservedBits: "reserved bits not set to zero as required",
		ResponseBadAuth:      "authorization failure without DA implications",
		ResponseExpired:      "the policy has expired",
		ResponsePolicyCC: "the commandCode in the policy is not the commandCode of the command or the command code in a policy command " +
			"references a command that is not implemented",
		ResponseBinding:        "public and sensitive portions of an object are not cryptographically bound",
		ResponseCurve:          "curve not supported",
		ResponseECCPoint:       "point is not on the required curve",
		ResponseFWLimited:      "the hierarchy is firmware-limited but the Firmware Secret is unavailable",
		ResponseSVNLimited:     "the hierarchy is SVN-limited but the Firmware SVN Secret associated with the given SVN is unavailable",
		ResponseContextGap:     "gap for context ID is too large",
		ResponseObjectMemory:   "out of memory for object contexts",
		ResponseSessionMemory:  "out of memory for session contexts",
		ResponseMemory:         "out of shared object/session memory or need space for internal operations",
		ResponseSessionHandles: "out of session handles – a session must be flushed before a new session may be created",
		ResponseObjectHandles:  "out of object handles – the handle space for objects is depleted and a reboot is required",
		ResponseLocality:       "bad locality",
		ResponseYielded:        "the TPM has suspended operation on the command; forward progress was made and the command may be retried",
		ResponseCanceled:       "the command was canceled",
		ResponseTesting:        "TPM is performing self-tests",
		ResponseReferenceH0:    "the 1st handle in the handle area references a transient object or session that is not loaded",
		ResponseReferenceH1:    "the 2nd handle in the handle area references a transient object or session that is not loaded",
		ResponseReferenceH2:    "the 3rd handle in the handle area references a transient object or session that is not loaded",
		ResponseReferenceH3:    "the 4th handle in the handle area references a transient object or session that is not loaded",
		ResponseReferenceH4:    "the 5th handle in the handle area references a transient object or session that is not loaded",
		ResponseReferenceH5:    "the 6th handle in the handle area references a transient object or session that is not loaded",
		ResponseReferenceH6:    "the 7th handle in the handle area references a transient object or session that is not loaded",
		ResponseReferenceS0:    "the 1st authorization session handle references a session that is not loaded",
		ResponseReferenceS1:    "the 2nd authorization session handle references a session that is not loaded",
		ResponseReferenceS2:    "the 3rd authorization session handle references a session that is not loaded",
		ResponseReferenceS3:    "the 4th authorization session handle references a session that is not loaded",
		ResponseReferenceS4:    "the 5th authorization session handle references a session that is not loaded",
		ResponseReferenceS5:    "the 6th authorization session handle references a session that is not loaded",
		ResponseReferenceS6:    "the 7th authorization session handle references a session that is not loaded",
		ResponseNVRate:         "the TPM is rate-limiting accesses to prevent wearout of NV",
		ResponseLockout: "authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA " +
			"lockout mode",
		ResponseRetry:         "the TPM was not able to start the command",
		ResponseNVUnavailable: "the command may require writing of NV and NV is not current accessible",
	}
)
