// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/elliptic"
	"fmt"
)

// This file contains types defined in section 6 (Contants) in
// part 2 of the library spec.

// TPMGenerated corresponds to the TPM_GENERATED type.
type TPMGenerated uint32

const (
	TPMGeneratedValue TPMGenerated = 0xff544347 // TPM_GENERATED_VALUE
)

// AlgorithmId corresponds to the TPM_ALG_ID type.
type AlgorithmId uint16

const (
	AlgorithmError          AlgorithmId = 0x0000 // TPM_ALG_ERROR
	AlgorithmRSA            AlgorithmId = 0x0001 // TPM_ALG_RSA
	AlgorithmTDES           AlgorithmId = 0x0003 // TPM_ALG_TDES
	AlgorithmSHA1           AlgorithmId = 0x0004 // TPM_ALG_SHA1
	AlgorithmHMAC           AlgorithmId = 0x0005 // TPM_ALG_HMAC
	AlgorithmAES            AlgorithmId = 0x0006 // TPM_ALG_AES
	AlgorithmMGF1           AlgorithmId = 0x0007 // TPM_ALG_MGF1
	AlgorithmKeyedHash      AlgorithmId = 0x0008 // TPM_ALG_KEYEDHASH
	AlgorithmXOR            AlgorithmId = 0x000a // TPM_ALG_XOR
	AlgorithmSHA256         AlgorithmId = 0x000b // TPM_ALG_SHA256
	AlgorithmSHA384         AlgorithmId = 0x000c // TPM_ALG_SHA384
	AlgorithmSHA512         AlgorithmId = 0x000d // TPM_ALG_SHA512
	AlgorithmSHA256_192     AlgorithmId = 0x000e // TPM_ALG_SHA256_192
	AlgorithmNull           AlgorithmId = 0x0010 // TPM_ALG_NULL
	AlgorithmSM3_256        AlgorithmId = 0x0012 // TPM_ALG_SM3_256
	AlgorithmSM4            AlgorithmId = 0x0013 // TPM_ALG_SM4
	AlgorithmRSASSA         AlgorithmId = 0x0014 // TPM_ALG_RSASSA
	AlgorithmRSAES          AlgorithmId = 0x0015 // TPM_ALG_RSAES
	AlgorithmRSAPSS         AlgorithmId = 0x0016 // TPM_ALG_RSAPSS
	AlgorithmOAEP           AlgorithmId = 0x0017 // TPM_ALG_OAEP
	AlgorithmECDSA          AlgorithmId = 0x0018 // TPM_ALG_ECDSA
	AlgorithmECDH           AlgorithmId = 0x0019 // TPM_ALG_ECDH
	AlgorithmECDAA          AlgorithmId = 0x001a // TPM_ALG_ECDAA
	AlgorithmSM2            AlgorithmId = 0x001b // TPM_ALG_SM2
	AlgorithmECSchnorr      AlgorithmId = 0x001c // TPM_ALG_ECSCHNORR
	AlgorithmECMQV          AlgorithmId = 0x001d // TPM_ALG_ECMQV
	AlgorithmKDF1_SP800_56A AlgorithmId = 0x0020 // TPM_ALG_KDF1_SP800_56A
	AlgorithmKDF2           AlgorithmId = 0x0021 // TPM_ALG_KDF2
	AlgorithmKDF1_SP800_108 AlgorithmId = 0x0022 // TPM_ALG_KDF1_SP800_108
	AlgorithmECC            AlgorithmId = 0x0023 // TPM_ALG_ECC
	AlgorithmSymCipher      AlgorithmId = 0x0025 // TPM_ALG_SYMCIPHER
	AlgorithmCamellia       AlgorithmId = 0x0026 // TPM_ALG_CAMELLIA
	AlgorithmSHA3_256       AlgorithmId = 0x0027 // TPM_ALG_SHA3_256
	AlgorithmSHA3_384       AlgorithmId = 0x0028 // TPM_ALG_SHA3_384
	AlgorithmSHA3_512       AlgorithmId = 0x0029 // TPM_ALG_SHA3_512
	AlgorithmSHAKE128       AlgorithmId = 0x002a // TPM_ALG_SHAKE128
	AlgorithmSHAKE256       AlgorithmId = 0x002b // TPM_ALG_SHAKE256
	AlgorithmSHAKE256_192   AlgorithmId = 0x002c // TPM_ALG_SHAKE256_192
	AlgorithmSHAKE256_256   AlgorithmId = 0x002d // TPM_ALG_SHAKE256_256
	AlgorithmSHAKE256_512   AlgorithmId = 0x002e // TPM_ALG_SHAKE256_512
	AlgorithmCMAC           AlgorithmId = 0x003f // TPM_ALG_CMAC
	AlgorithmCTR            AlgorithmId = 0x0040 // TPM_ALG_CTR
	AlgorithmOFB            AlgorithmId = 0x0041 // TPM_ALG_OFB
	AlgorithmCBC            AlgorithmId = 0x0042 // TPM_ALG_CBC
	AlgorithmCFB            AlgorithmId = 0x0043 // TPM_ALG_CFB
	AlgorithmECB            AlgorithmId = 0x0044 // TPM_ALG_ECB
	AlgorithmCCM            AlgorithmId = 0x0050 // TPM_ALG_CCM
	AlgorithmGCM            AlgorithmId = 0x0051 // TPM_ALG_GCM
	AlgorithmKW             AlgorithmId = 0x0052 // TPM_ALG_KW
	AlgorithmKWP            AlgorithmId = 0x0053 // TPM_ALG_KWP
	AlgorithmEAX            AlgorithmId = 0x0054 // TPM_ALG_EAX
	AlgorithmEDDSA          AlgorithmId = 0x0060 // TPM_ALG_EDDSA
	AlgorithmEDDSA_PH       AlgorithmId = 0x0061 // TPM_ALG_EDDSA_PH
	AlgorithmLMS            AlgorithmId = 0x0070 // TPM_ALG_LMS
	AlgorithmXMSS           AlgorithmId = 0x0071 // TPM_ALG_XMSS
	AlgorithmKeyedXOF       AlgorithmId = 0x0080 // TPM_ALG_KEYEDXOF
	AlgorithmKMACXOF128     AlgorithmId = 0x0081 // TPM_ALG_KMACXOF128
	AlgorithmKMACXOF256     AlgorithmId = 0x0082 // TPM_ALG_KMACXOF256
	AlgorithmKMAC128        AlgorithmId = 0x0090 // TPM_ALG_KMAC128
	AlgorithmKMAC256        AlgorithmId = 0x0091 // TPM_ALG_KMAC256

	AlgorithmFirst AlgorithmId = AlgorithmRSA
)

// ECCCurve corresponds to the TPM_ECC_CURVE type.
type ECCCurve uint16

// GoCurve returns the equivalent elliptic.Curve for this ECC curve.
func (c ECCCurve) GoCurve() elliptic.Curve {
	return eccCurves[c]
}

const (
	ECCCurveNIST_P192  ECCCurve = 0x0001 // TPM_ECC_NIST_P192
	ECCCurveNIST_P224  ECCCurve = 0x0002 // TPM_ECC_NIST_P224
	ECCCurveNIST_P256  ECCCurve = 0x0003 // TPM_ECC_NIST_P256
	ECCCurveNIST_P384  ECCCurve = 0x0004 // TPM_ECC_NIST_P384
	ECCCurveNIST_P521  ECCCurve = 0x0005 // TPM_ECC_NIST_P521
	ECCCurveBN_P256    ECCCurve = 0x0010 // TPM_ECC_BN_P256
	ECCCurveBN_P638    ECCCurve = 0x0011 // TPM_ECC_BN_P638
	ECCCurveSM2_P256   ECCCurve = 0x0020 // TPM_ECC_SM2_P256
	ECCCurveBP_P256_R1 ECCCurve = 0x0030 // TPM_ECC_BP_P256_R1
	ECCCurveBP_P384_R1 ECCCurve = 0x0031 // TPM_ECC_BP_P384_R1
	ECCCurveBP_P512_R1 ECCCurve = 0x0032 // TPM_ECC_BP_P512_R1
	ECCCurve25519      ECCCurve = 0x0040 // TPM_ECC_CURVE_25519
	ECCCurve448        ECCCurve = 0x0041 // TPM_ECC_CURVE_448

	ECCCurveFirst ECCCurve = ECCCurveNIST_P192
)

// CommandCode corresponds to the TPM_CC type.
type CommandCode uint32

const (
	CommandFirst CommandCode = 0x0000011A

	CommandNVUndefineSpaceSpecial     CommandCode = 0x0000011F // TPM_CC_NV_UndefineSpaceSpecial
	CommandEvictControl               CommandCode = 0x00000120 // TPM_CC_EvictControl
	CommandHierarchyControl           CommandCode = 0x00000121 // TPM_CC_HierarchyControl
	CommandNVUndefineSpace            CommandCode = 0x00000122 // TPM_CC_NV_UndefineSpace
	CommandClear                      CommandCode = 0x00000126 // TPM_CC_Clear
	CommandClearControl               CommandCode = 0x00000127 // TPM_CC_ClearControl
	CommandClockSet                   CommandCode = 0x00000128 // TPM_CC_ClockSet
	CommandHierarchyChangeAuth        CommandCode = 0x00000129 // TPM_CC_HierarchyChangeAuth
	CommandNVDefineSpace              CommandCode = 0x0000012A // TPM_CC_NV_DefineSpace
	CommandPCRAllocate                CommandCode = 0x0000012B // TPM_CC_PCR_Allocate
	CommandSetPrimaryPolicy           CommandCode = 0x0000012E // TPM_CC_SetPrimaryPolicy
	CommandClockRateAdjust            CommandCode = 0x00000130 // TPM_CC_ClockRateAdjust
	CommandCreatePrimary              CommandCode = 0x00000131 // TPM_CC_CreatePrimary
	CommandNVGlobalWriteLock          CommandCode = 0x00000132 // TPM_CC_NV_GlobalWriteLock
	CommandGetCommandAuditDigest      CommandCode = 0x00000133 // TPM_CC_GetCommandAuditDigest
	CommandNVIncrement                CommandCode = 0x00000134 // TPM_CC_NV_Increment
	CommandNVSetBits                  CommandCode = 0x00000135 // TPM_CC_NV_SetBits
	CommandNVExtend                   CommandCode = 0x00000136 // TPM_CC_NV_Extend
	CommandNVWrite                    CommandCode = 0x00000137 // TPM_CC_NV_Write
	CommandNVWriteLock                CommandCode = 0x00000138 // TPM_CC_NV_WriteLock
	CommandDictionaryAttackLockReset  CommandCode = 0x00000139 // TPM_CC_DictionaryAttackLockReset
	CommandDictionaryAttackParameters CommandCode = 0x0000013A // TPM_CC_DictionaryAttackParameters
	CommandNVChangeAuth               CommandCode = 0x0000013B // TPM_CC_NV_ChangeAuth
	CommandPCREvent                   CommandCode = 0x0000013C // TPM_CC_PCR_Event
	CommandPCRReset                   CommandCode = 0x0000013D // TPM_CC_PCR_Reset
	CommandSequenceComplete           CommandCode = 0x0000013E // TPM_CC_SequenceComplete
	CommandSetCommandCodeAuditStatus  CommandCode = 0x00000140 // TPM_CC_SetCommandCodeAuditStatus
	CommandIncrementalSelfTest        CommandCode = 0x00000142 // TPM_CC_IncrementalSelfTest
	CommandSelfTest                   CommandCode = 0x00000143 // TPM_CC_SelfTest
	CommandStartup                    CommandCode = 0x00000144 // TPM_CC_Startup
	CommandShutdown                   CommandCode = 0x00000145 // TPM_CC_Shutdown
	CommandStirRandom                 CommandCode = 0x00000146 // TPM_CC_StirRandom
	CommandActivateCredential         CommandCode = 0x00000147 // TPM_CC_ActivateCredential
	CommandCertify                    CommandCode = 0x00000148 // TPM_CC_Certify
	CommandPolicyNV                   CommandCode = 0x00000149 // TPM_CC_PolicyNV
	CommandCertifyCreation            CommandCode = 0x0000014A // TPM_CC_CertifyCreation
	CommandDuplicate                  CommandCode = 0x0000014B // TPM_CC_Duplicate
	CommandGetTime                    CommandCode = 0x0000014C // TPM_CC_GetTime
	CommandGetSessionAuditDigest      CommandCode = 0x0000014D // TPM_CC_GetSessionAuditDigest
	CommandNVRead                     CommandCode = 0x0000014E // TPM_CC_NV_Read
	CommandNVReadLock                 CommandCode = 0x0000014F // TPM_CC_NV_ReadLock
	CommandObjectChangeAuth           CommandCode = 0x00000150 // TPM_CC_ObjectChangeAuth
	CommandPolicySecret               CommandCode = 0x00000151 // TPM_CC_PolicySecret
	CommandCreate                     CommandCode = 0x00000153 // TPM_CC_Create
	CommandECDHZGen                   CommandCode = 0x00000154 // TPM_CC_ECDH_ZGen
	CommandHMAC                       CommandCode = 0x00000155 // TPM_CC_HMAC
	CommandImport                     CommandCode = 0x00000156 // TPM_CC_Import
	CommandLoad                       CommandCode = 0x00000157 // TPM_CC_Load
	CommandQuote                      CommandCode = 0x00000158 // TPM_CC_Quote
	CommandRSADecrypt                 CommandCode = 0x00000159 // TPM_CC_RSA_Decrypt
	CommandHMACStart                  CommandCode = 0x0000015B // TPM_CC_HMAC_Start
	CommandSequenceUpdate             CommandCode = 0x0000015C // TPM_CC_SequenceUpdate
	CommandSign                       CommandCode = 0x0000015D // TPM_CC_Sign
	CommandUnseal                     CommandCode = 0x0000015E // TPM_CC_Unseal
	CommandPolicySigned               CommandCode = 0x00000160 // TPM_CC_PolicySigned
	CommandContextLoad                CommandCode = 0x00000161 // TPM_CC_ContextLoad
	CommandContextSave                CommandCode = 0x00000162 // TPM_CC_ContextSave
	CommandECDHKeyGen                 CommandCode = 0x00000163 // TPM_CC_ECDH_KeyGen
	CommandFlushContext               CommandCode = 0x00000165 // TPM_CC_FlushContext
	CommandLoadExternal               CommandCode = 0x00000167 // TPM_CC_LoadExternal
	CommandMakeCredential             CommandCode = 0x00000168 // TPM_CC_MakeCredential
	CommandNVReadPublic               CommandCode = 0x00000169 // TPM_CC_NV_ReadPublic
	CommandPolicyAuthorize            CommandCode = 0x0000016A // TPM_CC_PolicyAuthorize
	CommandPolicyAuthValue            CommandCode = 0x0000016B // TPM_CC_PolicyAuthValue
	CommandPolicyCommandCode          CommandCode = 0x0000016C // TPM_CC_PolicyCommandCode
	CommandPolicyCounterTimer         CommandCode = 0x0000016D // TPM_CC_PolicyCounterTimer
	CommandPolicyCpHash               CommandCode = 0x0000016E // TPM_CC_PolicyCpHash
	CommandPolicyLocality             CommandCode = 0x0000016F // TPM_CC_PolicyLocality
	CommandPolicyNameHash             CommandCode = 0x00000170 // TPM_CC_PolicyNameHash
	CommandPolicyOR                   CommandCode = 0x00000171 // TPM_CC_PolicyOR
	CommandPolicyTicket               CommandCode = 0x00000172 // TPM_CC_PolicyTicket
	CommandReadPublic                 CommandCode = 0x00000173 // TPM_CC_ReadPublic
	CommandRSAEncrypt                 CommandCode = 0x00000174 // TPM_CC_RSA_Encrypt
	CommandStartAuthSession           CommandCode = 0x00000176 // TPM_CC_StartAuthSession
	CommandVerifySignature            CommandCode = 0x00000177 // TPM_CC_VerifySignature
	CommandECCParameters              CommandCode = 0x00000178 // TPM_CC_ECC_Parameters
	CommandGetCapability              CommandCode = 0x0000017A // TPM_CC_GetCapability
	CommandGetRandom                  CommandCode = 0x0000017B // TPM_CC_GetRandom
	CommandGetTestResult              CommandCode = 0x0000017C // TPM_CC_GetTestResult
	CommandHash                       CommandCode = 0x0000017D // TPM_CC_Hash
	CommandPCRRead                    CommandCode = 0x0000017E // TPM_CC_PCR_Read
	CommandPolicyPCR                  CommandCode = 0x0000017F // TPM_CC_PolicyPCR
	CommandPolicyRestart              CommandCode = 0x00000180 // TPM_CC_PolicyRestart
	CommandReadClock                  CommandCode = 0x00000181 // TPM_CC_ReadClock
	CommandPCRExtend                  CommandCode = 0x00000182 // TPM_CC_PCR_Extend
	CommandNVCertify                  CommandCode = 0x00000184 // TPM_CC_NV_Certify
	CommandEventSequenceComplete      CommandCode = 0x00000185 // TPM_CC_EventSequenceComplete
	CommandHashSequenceStart          CommandCode = 0x00000186 // TPM_CC_HashSequenceStart
	CommandPolicyDuplicationSelect    CommandCode = 0x00000188 // TPM_CC_PolicyDuplicationSelect
	CommandPolicyGetDigest            CommandCode = 0x00000189 // TPM_CC_PolicyGetDigest
	CommandTestParms                  CommandCode = 0x0000018A // TPM_CC_TestParms
	CommandCommit                     CommandCode = 0x0000018B // TPM_CC_Commit
	CommandPolicyPassword             CommandCode = 0x0000018C // TPM_CC_PolicyPassword
	CommandPolicyNvWritten            CommandCode = 0x0000018F // TPM_CC_PolicyNvWritten
	CommandPolicyTemplate             CommandCode = 0x00000190 // TPM_CC_PolicyTemplate
	CommandCreateLoaded               CommandCode = 0x00000191 // TPM_CC_CreateLoaded
	CommandPolicyAuthorizeNV          CommandCode = 0x00000192 // TPM_CC_PolicyAuthorizeNV
)

// ResponseCode corresponds to the TPM_RC type.
type ResponseCode uint32

const (
	// ResponseSuccess corresponds to TPM_RC_SUCCESS and indicates success.
	ResponseSuccess ResponseCode = 0x000

	// ResponseBadTag corresponds to TPM_RC_BAD_TAG and is returned from
	// TPM1.2 devices which don't recognise the TPM2 command tags
	// (TPM_ST_NO_SESSIONS and TPM_ST_SESSIONS).
	ResponseBadTag ResponseCode = 0x01e // TPM_RC_BAD_TAG

	// rcVer1 corresponds to RC_VER1 and is the base of all TCG defined
	// format-zero TPM2 error codes.
	rcVer1 ResponseCode = 0x100

	ResponseInitialize      ResponseCode = rcVer1 + 0x000 // TPM_RC_INITIALIZE
	ResponseFailure         ResponseCode = rcVer1 + 0x001 // TPM_RC_FAILURE
	ResponseSequence        ResponseCode = rcVer1 + 0x003 // TPM_RC_SEQUENCE
	ResponseDisabled        ResponseCode = rcVer1 + 0x020 // TPM_RC_DISABLED
	ResponseExclusive       ResponseCode = rcVer1 + 0x021 // TPM_RC_EXCLUSIVE
	ResponseAuthType        ResponseCode = rcVer1 + 0x024 // TPM_RC_AUTH_TYPE
	ResponseAuthMissing     ResponseCode = rcVer1 + 0x025 // TPM_RC_AUTH_MISSING
	ResponsePolicy          ResponseCode = rcVer1 + 0x026 // TPM_RC_POLICY
	ResponsePCR             ResponseCode = rcVer1 + 0x027 // TPM_RC_PCR
	ResponsePCRChanged      ResponseCode = rcVer1 + 0x028 // TPM_RC_PCR_CHANGED
	ResponseUpgrade         ResponseCode = rcVer1 + 0x02d // TPM_RC_UPGRADE
	ResponseTooManyContexts ResponseCode = rcVer1 + 0x02e // TPM_RC_TOO_MANY_CONTEXTS
	ResponseAuthUnavailable ResponseCode = rcVer1 + 0x02f // TPM_RC_AUTH_UNAVAILABLE
	ResponseReboot          ResponseCode = rcVer1 + 0x030 // TPM_RC_REBOOT
	ResponseUnbalanced      ResponseCode = rcVer1 + 0x031 // TPM_RC_UNBALANCED
	ResponseCommandSize     ResponseCode = rcVer1 + 0x042 // TPM_RC_COMMAND_SIZE
	ResponseCommandCode     ResponseCode = rcVer1 + 0x043 // TPM_RC_COMMAND_CODE
	ResponseAuthsize        ResponseCode = rcVer1 + 0x044 // TPM_RC_AUTHSIZE
	ResponseAuthContext     ResponseCode = rcVer1 + 0x045 // TPM_RC_AUTH_CONTEXT
	ResponseNVRange         ResponseCode = rcVer1 + 0x046 // TPM_RC_NV_RANGE
	ResponseNVSize          ResponseCode = rcVer1 + 0x047 // TPM_RC_NV_SIZE
	ResponseNVLocked        ResponseCode = rcVer1 + 0x048 // TPM_RC_NV_LOCKED
	ResponseNVAuthorization ResponseCode = rcVer1 + 0x049 // TPM_RC_NV_AUTHORIZATION
	ResponseNVUninitialized ResponseCode = rcVer1 + 0x04a // TPM_RC_NV_UNINITIALIZED
	ResponseNVSpace         ResponseCode = rcVer1 + 0x04b // TPM_RC_NV_SPACE
	ResponseNVDefined       ResponseCode = rcVer1 + 0x04c // TPM_RC_NV_DEFINED
	ResponseBadContext      ResponseCode = rcVer1 + 0x050 // TPM_RC_BAD_CONTEXT
	ResponseCpHash          ResponseCode = rcVer1 + 0x051 // TPM_RC_CPHASH
	ResponseParent          ResponseCode = rcVer1 + 0x052 // TPM_RC_PARENT
	ResponseNeedsTest       ResponseCode = rcVer1 + 0x053 // TPM_RC_NEEDS_TEST
	ResponseNoResult        ResponseCode = rcVer1 + 0x054 // TPM_RC_NO_RESULT
	ResponseSensitive       ResponseCode = rcVer1 + 0x055 // TPM_RC_SENSITIVE

	// rcMaxFM0 corresponds to RC_MAX_FM0 and is the maxmimum TCG defined format-zero
	// TPM2 error.
	rcMaxFM0 ResponseCode = rcVer1 + 0x07f

	// rcFmt1 corresponds to RC_FMT1 and is the base of all format-one errors.
	rcFmt1 ResponseCode = 0x080

	ResponseAsymmetric   ResponseCode = rcFmt1 + 0x001 // TPM_RC_ASYMMETRIC
	ResponseAttributes   ResponseCode = rcFmt1 + 0x002 // TPM_RC_ATTRIBUTES
	ResponseHash         ResponseCode = rcFmt1 + 0x003 // TPM_RC_HASH
	ResponseValue        ResponseCode = rcFmt1 + 0x004 // TPM_RC_VALUE
	ResponseHierarchy    ResponseCode = rcFmt1 + 0x005 // TPM_RC_HIERARCHY
	ResponseKeySize      ResponseCode = rcFmt1 + 0x007 // TPM_RC_KEY_SIZE
	ResponseMGF          ResponseCode = rcFmt1 + 0x008 // TPM_RC_MGF
	ResponseMode         ResponseCode = rcFmt1 + 0x009 // TPM_RC_MODE
	ResponseType         ResponseCode = rcFmt1 + 0x00a // TPM_RC_TYPE
	ResponseHandle       ResponseCode = rcFmt1 + 0x00b // TPM_RC_HANDLE
	ResponseKDF          ResponseCode = rcFmt1 + 0x00c // TPM_RC_KDF
	ResponseRange        ResponseCode = rcFmt1 + 0x00d // TPM_RC_RANGE
	ResponseAuthFail     ResponseCode = rcFmt1 + 0x00e // TPM_RC_AUTH_FAIL
	ResponseNonce        ResponseCode = rcFmt1 + 0x00f // TPM_RC_NONCE
	ResponsePP           ResponseCode = rcFmt1 + 0x010 // TPM_RC_PP
	ResponseScheme       ResponseCode = rcFmt1 + 0x012 // TPM_RC_SCHEME
	ResponseSize         ResponseCode = rcFmt1 + 0x015 // TPM_RC_SIZE
	ResponseSymmetric    ResponseCode = rcFmt1 + 0x016 // TPM_RC_SYMMETRIC
	ResponseTag          ResponseCode = rcFmt1 + 0x017 // TPM_RC_TAG
	ResponseSelector     ResponseCode = rcFmt1 + 0x018 // TPM_RC_SELECTOR
	ResponseInsufficient ResponseCode = rcFmt1 + 0x01a // TPM_RC_INSUFFICIENT
	ResponseSignature    ResponseCode = rcFmt1 + 0x01b // TPM_RC_SIGNATURE
	ResponseKey          ResponseCode = rcFmt1 + 0x01c // TPM_RC_KEY
	ResponsePolicyFail   ResponseCode = rcFmt1 + 0x01d // TPM_RC_POLICY_FAIL
	ResponseIntegrity    ResponseCode = rcFmt1 + 0x01f // TPM_RC_INTEGRITY
	ResponseTicket       ResponseCode = rcFmt1 + 0x020 // TPM_RC_TICKET
	ResponseReservedBits ResponseCode = rcFmt1 + 0x021 // TPM_RC_RESERVED_BITS
	ResponseBadAuth      ResponseCode = rcFmt1 + 0x022 // TPM_RC_BAD_AUTH
	ResponseExpired      ResponseCode = rcFmt1 + 0x023 // TPM_RC_EXPIRED
	ResponsePolicyCC     ResponseCode = rcFmt1 + 0x024 // TPM_RC_POLICY_CC
	ResponseBinding      ResponseCode = rcFmt1 + 0x025 // TPM_RC_BINDING
	ResponseCurve        ResponseCode = rcFmt1 + 0x026 // TPM_RC_CURVE
	ResponseECCPoint     ResponseCode = rcFmt1 + 0x027 // TPM_RC_ECC_POINT
	ResponseFWLimited    ResponseCode = rcFmt1 + 0x028 // TPM_RC_FW_LIMITED
	ResponseSVNLimited   ResponseCode = rcFmt1 + 0x029 // TPM_RC_SVN_LIMITED

	// rcWarn corresponds to RC_WARN and is the base of all TCG defined
	// format-zero TPM2 warning codes.
	rcWarn ResponseCode = 0x900

	ResponseContextGap     ResponseCode = rcWarn + 0x001 // TPM_RC_CONTEXT_GAP
	ResponseObjectMemory   ResponseCode = rcWarn + 0x002 // TPM_RC_OBJECT_MEMORY
	ResponseSessionMemory  ResponseCode = rcWarn + 0x003 // TPM_RC_SESSION_MEMORY
	ResponseMemory         ResponseCode = rcWarn + 0x004 // TPM_RC_MEMORY
	ResponseSessionHandles ResponseCode = rcWarn + 0x005 // TPM_RC_SESSION_HANDLES
	ResponseObjectHandles  ResponseCode = rcWarn + 0x006 // TPM_RC_OBJECT_HANDLES
	ResponseLocality       ResponseCode = rcWarn + 0x007 // TPM_RC_LOCALITY
	ResponseYielded        ResponseCode = rcWarn + 0x008 // TPM_RC_YIELDED
	ResponseCanceled       ResponseCode = rcWarn + 0x009 // TPM_RC_CANCELED
	ResponseTesting        ResponseCode = rcWarn + 0x00a // TPM_RC_TESTING
	ResponseReferenceH0    ResponseCode = rcWarn + 0x010 // TPM_RC_REFERENCE_H0
	ResponseReferenceH1    ResponseCode = rcWarn + 0x011 // TPM_RC_REFERENCE_H1
	ResponseReferenceH2    ResponseCode = rcWarn + 0x012 // TPM_RC_REFERENCE_H2
	ResponseReferenceH3    ResponseCode = rcWarn + 0x013 // TPM_RC_REFERENCE_H3
	ResponseReferenceH4    ResponseCode = rcWarn + 0x014 // TPM_RC_REFERENCE_H4
	ResponseReferenceH5    ResponseCode = rcWarn + 0x015 // TPM_RC_REFERENCE_H5
	ResponseReferenceH6    ResponseCode = rcWarn + 0x016 // TPM_RC_REFERENCE_H6
	ResponseReferenceS0    ResponseCode = rcWarn + 0x018 // TPM_REFERENCE_S0
	ResponseReferenceS1    ResponseCode = rcWarn + 0x019 // TPM_REFERENCE_S1
	ResponseReferenceS2    ResponseCode = rcWarn + 0x01a // TPM_REFERENCE_S2
	ResponseReferenceS3    ResponseCode = rcWarn + 0x01b // TPM_REFERENCE_S3
	ResponseReferenceS4    ResponseCode = rcWarn + 0x01c // TPM_REFERENCE_S4
	ResponseReferenceS5    ResponseCode = rcWarn + 0x01d // TPM_REFERENCE_S5
	ResponseReferenceS6    ResponseCode = rcWarn + 0x01e // TPM_REFERENCE_S6
	ResponseNVRate         ResponseCode = rcWarn + 0x020 // TPM_RC_RATE
	ResponseLockout        ResponseCode = rcWarn + 0x021 // TPM_RC_LOCKOUT
	ResponseRetry          ResponseCode = rcWarn + 0x022 // TPM_RC_RETRY
	ResponseNVUnavailable  ResponseCode = rcWarn + 0x023 // TPM_RC_NV_UNAVAILABLE

	// ResponseH corresponds to TPM_RC_H and is added to a handle related error.
	ResponseH ResponseCode = 0x000

	// ResponseP corresponds to TPM_RC_P and is added to a parameter related error.
	ResponseP ResponseCode = 0x040

	// RespondsS corresponds to TPM_RC_S and is added to a session related error.
	ResponseS ResponseCode = 0x800

	// Response1 corresponds to TPM_RC_1 and is added to a handle, parameter or
	// session related error.
	Response1 ResponseCode = 0x100

	// Response2 corresponds to TPM_RC_2 and is added to a handle, parameter or
	// session related error.
	Response2 ResponseCode = 0x200

	// Response3 corresponds to TPM_RC_3 and is added to a handle, parameter or
	// session related error.
	Response3 ResponseCode = 0x300

	// Response4 corresponds to TPM_RC_4 and is added to a handle, parameter or
	// session related error.
	Response4 ResponseCode = 0x400

	// Response5 corresponds to TPM_RC_5 and is added to a handle, parameter or
	// session related error.
	Response5 ResponseCode = 0x500

	// Response6 corresponds to TPM_RC_6 and is added to a handle, parameter or
	// session related error.
	Response6 ResponseCode = 0x600

	// Response7 corresponds to TPM_RC_7 and is added to a handle, parameter or
	// session related error.
	Response7 ResponseCode = 0x700

	// Response8 corresponds to TPM_RC_8 and is added to a parameter related error.
	Response8 ResponseCode = 0x800

	// Response9 corresponds to TPM_RC_9 and is added to a parameter related error.
	Response9 ResponseCode = 0x900

	// ResponseA corresponds to TPM_RC_A and is added to a parameter related error.
	ResponseA ResponseCode = 0xa00

	// ResponseB corresponds to TPM_RC_B and is added to a parameter related error.
	ResponseB ResponseCode = 0xb00

	// ResponseC corresponds to TPM_RC_C and is added to a parameter related error.
	ResponseC ResponseCode = 0xc00

	// ResponseD corresponds to TPM_RC_D and is added to a parameter related error.
	ResponseD ResponseCode = 0xd00

	// ResponseE corresponds to TPM_RC_E and is added to a parameter related error.
	ResponseE ResponseCode = 0xe00

	// ResponseF corresponds to TPM_RC_F and is added to a parameter related error.
	ResponseF ResponseCode = 0xf00

	// ResponseNMask corresponds to TPM_RC_N_MASK and indicates the associated handle,
	// parameter or session depending on the status of ResponseH, ResponseP or ResponseS.
	ResponseNMask ResponseCode = 0xf00

	// rcE0 corresponds to the error code (bits 0-6) of format-zero response codes.
	rcE0 ResponseCode = 0x07f

	// rcE1 corresponds to the error code (bits 0-5) of format-one response codes.
	rcE1 ResponseCode = 0x03f

	// rcP corresponds to bit 6 of format-one response codes and is set for errors associated
	// with a parameter or clear for errors associated with a handle or session.
	rcP ResponseCode = 0x040

	// rcF corresponds to bit 7 and is the format indicator. It is clear for format-zero
	// response codes and set for format-one response codes.
	rcF ResponseCode = 0x080

	// rcV corresponds to bit 8 and is the version indicator of format-zero response codes. It
	// is set for TPM2 response codes or clear for TPM1.2 response codes.
	rcV ResponseCode = 0x100

	// rcT corresponds to bit 10 and is the TCG/Vendor indicator of format-zero response codes.
	// It is set for vendor defined response codes or clear for TCG defined response codes.
	rcT ResponseCode = 0x400

	// rcS corresponds to bit 11 and is the severity indicator of format-zero response codes. It
	// is set for warnings or clear for errors.
	rcS ResponseCode = 0x800

	// rcN corresponds to bits 8 to 11 of format-one response codes and is the handle, parameter
	// or session indicator.
	rcN ResponseCode = 0xf00

	// rcNSessionIndicator is the MSB of rcN for format-one response codes and indicates that
	// the N field corresponds to a session if rcP field is clear.
	rcNSessionIndicator = 0x800

	// rcNShift is used to shift the bits defined by ResponseNMask.
	rcNShift ResponseCode = 8
)

func responseCodeIndexUnchecked(index uint8) ResponseCode {
	return ResponseCode(index) << rcNShift
}

// ResponseCodeIndex returns the supplied one-indexed handle, parameter or session
// index as a ResponseCode integer from Response1 to ResponseF that can be added to
// a base response code. It will panic if index is greater than 0xf. An index of zero
// is undefined.
func ResponseCodeIndex(index uint8) ResponseCode {
	rc := responseCodeIndexUnchecked(index)
	if rc > ResponseF {
		panic("invalid handle, parameter, or session index (> 0xf)")
	}
	return rc
}

// ResponseCodeFormat indicates the format or a response code
type ResponseCodeFormat bool

const (
	ResponseCodeFormat0 ResponseCodeFormat = false // A format-zero response code
	ResponseCodeFormat1 ResponseCodeFormat = true  // A format-one response code
)

// ResponseCodeIndexType indicates the type of index that a format-one response code encodes.
type ResponseCodeIndexType uint8

const (
	ResponseCodeIndexTypeNone      ResponseCodeIndexType = 0 // No index is encoded (eg, as with format-zero response codes)
	ResponseCodeIndexTypeHandle    ResponseCodeIndexType = 1 // A one-indexed handle index is encoded
	ResponseCodeIndexTypeParameter ResponseCodeIndexType = 2 // A one-indexed parameter index is encoded
	ResponseCodeIndexTypeSession   ResponseCodeIndexType = 3 // A one-indexed session index is encoded
)

// ResponseCodeVersion indicates the version of a format-zero response code.
type ResponseCodeVersion bool

const (
	ResponseCodeVersionTPM12 ResponseCodeVersion = false // TPM1.2 response
	ResponseCodeVersionTPM2  ResponseCodeVersion = true  // TPM2 response
)

// ResponseCodeSeverity indicates the severity of a format-zero response code.
type ResponseCodeSeverity bool

const (
	ResponseCodeSeverityWarning ResponseCodeSeverity = false // A warning
	ResponseCodeSeverityError   ResponseCodeSeverity = true  // An error
)

// ResponseCodeSpec indicates where a format-zero response code is defined (by
// the TCG or TPM vendor)
type ResponseCodeSpec bool

const (
	ResponseCodeSpecTCG    ResponseCodeSpec = false // Defined by the TCG
	ResponseCodeSpecVendor ResponseCodeSpec = true  // Defined by the TPM vendor
)

// ResponseCodeType indicates some properties of a [ResponseCode].
type ResponseCodeType uint8

const (
	responseCodeTypeFormatOne ResponseCodeType = 1 << 0
	responseCodeTypeIndexType ResponseCodeType = 3 << 1
	responseCodeTypeTPM2      ResponseCodeType = 1 << 3
	responseCodeTypeWarning   ResponseCodeType = 1 << 4
	responseCodeTypeVendor    ResponseCodeType = 1 << 5
)

// Format returns the format of the [ResponseCode] of this type.
func (t ResponseCodeType) Format() ResponseCodeFormat {
	return ResponseCodeFormat(t&responseCodeTypeFormatOne != 0)
}

// IndexType returns the type of index encoded in the [ResponseCode] of this
// type.
func (t ResponseCodeType) IndexType() ResponseCodeIndexType {
	return ResponseCodeIndexType(t & responseCodeTypeIndexType >> 1)
}

// Version returns the version of the [ResponseCode] of this type.
func (t ResponseCodeType) Version() ResponseCodeVersion {
	return ResponseCodeVersion(t&responseCodeTypeTPM2 != 0)
}

// Severity returns the severity of the [ResponseCode] of this type.
func (t ResponseCodeType) Severity() ResponseCodeSeverity {
	return ResponseCodeSeverity(t&responseCodeTypeWarning == 0)
}

// Spec returns where the [ResponseCode] of this type is defined.
func (t ResponseCodeType) Spec() ResponseCodeSpec {
	return ResponseCodeSpec(t&responseCodeTypeVendor != 0)
}

// Base returns the base format-one response code without any handle, parameter or session
// index. This returns format-zero response codes without any changes.
func (rc ResponseCode) Base() ResponseCode {
	if rc.F() {
		// Format-one response codes are returned without their handle, parameter
		// or session index.
		return rc &^ (ResponseH | ResponseP | ResponseS | ResponseNMask)
	}

	// Format-zero response codes are returned untouched.
	return rc
}

// Type returns information about the type of this response code.
func (rc ResponseCode) Type() ResponseCodeType {
	var out ResponseCodeType

	switch rc.F() {
	case true:
		out |= responseCodeTypeFormatOne
		out |= responseCodeTypeTPM2

		switch {
		case rc&rcP != 0:
			// This is associated with a parameter
			out |= ResponseCodeType(ResponseCodeIndexTypeParameter << 1)
		case rc&rcNSessionIndicator != 0:
			// This is associated with a session
			out |= ResponseCodeType(ResponseCodeIndexTypeSession << 1)
		default:
			// This is associated with a handle
			out |= ResponseCodeType(ResponseCodeIndexTypeHandle << 1)
		}
	case false:
		if rc.V() {
			out |= responseCodeTypeTPM2
		}
		if rc.S() {
			out |= responseCodeTypeWarning
		}
		if rc.T() {
			out |= responseCodeTypeVendor
		}
	}

	return out
}

// Index returns the one-indexed handle, parameter or session index associated with this format-one
// response code. This will return 0 if the response code is not associated with a specific handle,
// parameter or session.
func (rc ResponseCode) Index() uint8 {
	switch rc.Type().IndexType() {
	case ResponseCodeIndexTypeHandle, ResponseCodeIndexTypeSession:
		// Handles and sessions only use the lower 3 bits of the N field.
		return rc.N() &^ uint8(rcNSessionIndicator>>rcNShift)
	case ResponseCodeIndexTypeParameter:
		return rc.N()
	default:
		return 0
	}
}

// SetHandleIndex sets the associated one-indexed handle index for this response code. This
// will panic if the handle index is out of range or the response code is not a format-one
// response code. A handle index of zero indicates that the handle is unspecified.
func (rc ResponseCode) SetHandleIndex(h uint8) ResponseCode {
	rc = rc.Base()
	if !rc.F() {
		panic(fmt.Errorf("%w (base response code is not a format-1 response code)", InvalidResponseCodeError(rc)))
	}
	index := responseCodeIndexUnchecked(h)
	rc = rc + ResponseH + index
	if index > Response7 {
		panic(fmt.Errorf("%w (invalid handle index overflows bits 8-10)", InvalidResponseCodeError(rc)))
	}
	return rc
}

// SetParameterIndex sets the associated one-indexed parameter index for this response code. This
// will panic if the parameter index is out of range or the response code is not a format-one
// response code or the specified parameter index is zero.
func (rc ResponseCode) SetParameterIndex(p uint8) ResponseCode {
	rc = rc.Base()
	if !rc.F() {
		panic(fmt.Errorf("%w (base response code is not a format-1 response code)", InvalidResponseCodeError(rc)))
	}
	index := responseCodeIndexUnchecked(p)
	rc = rc + ResponseP + index
	if index > ResponseF {
		panic(fmt.Errorf("%w (invalid parameter index overflows bits 8-11)", InvalidResponseCodeError(rc)))
	}
	return rc
}

// SetSession sets the associated one-indexed session index for this response code. This
// will panic if the session index is out of range or the response code is not a format-one
// response code. A session index of zero indicates that the session is unspecified.
func (rc ResponseCode) SetSessionIndex(s uint8) ResponseCode {
	rc = rc.Base()
	if !rc.F() {
		panic(fmt.Errorf("%w (base response code is not a format-1 response code)", InvalidResponseCodeError(rc)))
	}
	index := responseCodeIndexUnchecked(s)
	rc = rc + ResponseS + index
	if index > Response7 {
		panic(fmt.Errorf("%w (invalid session index overflows bits 8-10)", InvalidResponseCodeError(rc)))
	}
	return rc
}

// E is a low-level function that returns the E field of the response code, corresponding to
// the error number. This is the lower 7-bits for format-zero response codes or the lower
// 6-bits for format-one response codes.
func (rc ResponseCode) E() uint8 {
	if rc.F() {
		return uint8(rc & rcE1)
	}
	return uint8(rc & rcE0)
}

// F is a low-level function that returns the F field of the response code, corresponding to
// the format. If it is set, this is a format-one response code. If it is clear, this is a
// format-zero response code.
func (rc ResponseCode) F() bool {
	return rc&rcF != 0
}

// V is a low-level function that returns the V field of the response code, corresponding to
// the version and is only relevant for format-zero response codes. If this is set then it is
// a TPM2 code returned when the response tag is TPM_ST_NO_SESSIONS. If it is clear then it
// is a TPM1.2 code returned when the response tag is TPM_TAG_RSP_COMMAND.
//
// This will panic if the F field is set.
func (rc ResponseCode) V() bool {
	if rc.F() {
		panic("not a format-0 response code")
	}
	return rc&rcV != 0
}

// T is a low-level function that returns the T field of the response code, corresponding to the
// TCG/Vendor indicator and is only relevant for format-zero response codes. If this is set then
// the code is defined by the TPM vendor. If it is clear then the code is defined by the TCG.
//
// This will panic if the F field is set.
func (rc ResponseCode) T() bool {
	if rc.F() {
		panic("not a format-0 response code")
	}
	return rc&rcT != 0
}

// S is a low-level function that returns the S field of the response code, corresponding to the
// severity and is only relevant for format-zero response codes. If this is set then the code
// indicates a warning. If it is clear then the code indicates an error.
//
// This will panic if the F field is set.
func (rc ResponseCode) S() bool {
	if rc.F() {
		panic("not a format-0 response code")
	}
	return rc&rcS != 0
}

// P is a low-level function that returns the P field of the response code and is only relevant for
// format-one response codes. If this is set then the code is associated with a command parameter.
// If it is not set then the code is associated with a command handle or session.
//
// This will panic if the F field is not set.
func (rc ResponseCode) P() bool {
	if !rc.F() {
		panic("not a format-1 response code")
	}
	return rc&rcP != 0
}

// N is a low-level function that returns the N field of the response code and is only relevant for
// format-one response codes. If the P field is set then this indicates the parameter number from
// 0x1 to 0xf. If the P field is not set then the lower 3 bits indicate the handle or session number
// (0x1 to 0x7 for handles and 0x9 to 0xf for sessions).
//
// This will panic if the F field is not set.
func (rc ResponseCode) N() uint8 {
	if !rc.F() {
		panic("not a format-1 response code")
	}
	return uint8((rc & rcN) >> rcNShift)
}

// ArithmeticOp corresponds to the TPM_EO type.
type ArithmeticOp uint16

const (
	OpEq         ArithmeticOp = 0x0000 // TPM_EO_EQ
	OpNeq        ArithmeticOp = 0x0001 // TPM_EO_NEQ
	OpSignedGT   ArithmeticOp = 0x0002 // TPM_EO_SIGNED_GT
	OpUnsignedGT ArithmeticOp = 0x0003 // TPM_EO_UNSIGNED_GT
	OpSignedLT   ArithmeticOp = 0x0004 // TPM_EO_SIGNED_LT
	OpUnsignedLT ArithmeticOp = 0x0005 // TPM_EO_UNSIGNED_LT
	OpSignedGE   ArithmeticOp = 0x0006 // TPM_EO_SIGNED_GE
	OpUnsignedGE ArithmeticOp = 0x0007 // TPM_EO_UNSIGNED_GE
	OpSignedLE   ArithmeticOp = 0x0008 // TPM_EO_SIGNED_LE
	OpUnsignedLE ArithmeticOp = 0x0009 // TPM_EO_UNSIGNED_LE
	OpBitset     ArithmeticOp = 0x000a // TPM_EO_BITSET
	OpBitclear   ArithmeticOp = 0x000b // TPM_EO_BITCLEAR
)

// StructTag corresponds to the TPM_ST type.
type StructTag uint16

const (
	TagRspCommand StructTag = 0x00c4 // TPM_ST_RSP_COMMAND

	TagNoSessions         StructTag = 0x8001 // TPM_ST_NO_SESSIONS
	TagSessions           StructTag = 0x8002 // TPM_ST_SESSIONS
	TagAttestNV           StructTag = 0x8014 // TPM_ST_ATTEST_NV
	TagAttestCommandAudit StructTag = 0x8015 // TPM_ST_ATTEST_COMMAND_AUDIT
	TagAttestSessionAudit StructTag = 0x8016 // TPM_ST_ATTEST_SESSION_AUDIT
	TagAttestCertify      StructTag = 0x8017 // TPM_ST_ATTEST_CERTIFY
	TagAttestQuote        StructTag = 0x8018 // TPM_ST_ATTEST_QUOTE
	TagAttestTime         StructTag = 0x8019 // TPM_ST_ATTEST_TIME
	TagAttestCreation     StructTag = 0x801a // TPM_ST_ATTEST_CREATION
	TagCreation           StructTag = 0x8021 // TPM_ST_CREATION
	TagVerified           StructTag = 0x8022 // TPM_ST_VERIFIED
	TagAuthSecret         StructTag = 0x8023 // TPM_ST_AUTH_SECRET
	TagHashcheck          StructTag = 0x8024 // TPM_ST_HASHCHECK
	TagAuthSigned         StructTag = 0x8025 // TPM_ST_AUTH_SIGNED
)

// StartupType corresponds to the TPM_SU type.
type StartupType uint16

const (
	StartupClear StartupType = iota
	StartupState
)

// SessionType corresponds to the TPM_SE type.
type SessionType uint8

const (
	SessionTypeHMAC   SessionType = 0x00 // TPM_SE_HMAC
	SessionTypePolicy SessionType = 0x01 // TPM_SE_POLICY
	SessionTypeTrial  SessionType = 0x03 // TPM_SE_TRIAL
)

// Capability corresponds to the TPM_CAP type.
type Capability uint32

const (
	CapabilityAlgs          Capability = 0 // TPM_CAP_ALGS
	CapabilityHandles       Capability = 1 // TPM_CAP_HANDLES
	CapabilityCommands      Capability = 2 // TPM_CAP_COMMANDS
	CapabilityPPCommands    Capability = 3 // TPM_CAP_PP_COMMANDS
	CapabilityAuditCommands Capability = 4 // TPM_CAP_AUDIT_COMMANDS
	CapabilityPCRs          Capability = 5 // TPM_CAP_PCRS
	CapabilityTPMProperties Capability = 6 // TPM_CAP_TPM_PROPERTIES
	CapabilityPCRProperties Capability = 7 // TPM_CAP_PCR_PROPERTIES
	CapabilityECCCurves     Capability = 8 // TPM_CAP_ECC_CURVES
	CapabilityAuthPolicies  Capability = 9 // TPM_CAP_AUTH_POLICIES
)

// Property corresponds to the TPM_PT type.
type Property uint32

const (
	// These constants represent properties that only change when the firmware in the TPM changes.
	PropertyFamilyIndicator   Property = 0x100 // TPM_PT_FAMILY_INDICATOR
	PropertyLevel             Property = 0x101 // TPM_PT_LEVEL
	PropertyRevision          Property = 0x102 // TPM_PT_REVISION
	PropertyDayOfYear         Property = 0x103 // TPM_PT_DAY_OF_YEAR
	PropertyYear              Property = 0x104 // TPM_PT_YEAR
	PropertyManufacturer      Property = 0x105 // TPM_PT_MANUFACTURER
	PropertyVendorString1     Property = 0x106 // TPM_PT_VENDOR_STRING_1
	PropertyVendorString2     Property = 0x107 // TPM_PT_VENDOR_STRING_2
	PropertyVendorString3     Property = 0x108 // TPM_PT_VENDOR_STRING_3
	PropertyVendorString4     Property = 0x109 // TPM_PT_VENDOR_STRING_4
	PropertyVendorTPMType     Property = 0x10a // TPM_PT_VENDOR_TPM_TYPE
	PropertyFirmwareVersion1  Property = 0x10b // TPM_PT_FIRMWARE_VERSION_1
	PropertyFirmwareVersion2  Property = 0x10c // TPM_PT_FIRMWARE_VERSION_2
	PropertyInputBuffer       Property = 0x10d // TPM_PT_INPUT_BUFFER
	PropertyHRTransientMin    Property = 0x10e // TPM_PT_HR_TRANSIENT_MIN
	PropertyHRPersistentMin   Property = 0x10f // TPM_PT_HR_PERSISTENT_MIN
	PropertyHRLoadedMin       Property = 0x110 // TPM_PT_HR_LOADED_MIN
	PropertyActiveSessionsMax Property = 0x111 // TPM_PT_ACTIVE_SESSIONS_MAX
	PropertyPCRCount          Property = 0x112 // TPM_PT_PCR_COUNT
	PropertyPCRSelectMin      Property = 0x113 // TPM_PT_PCR_SELECT_MIN
	PropertyContextGapMax     Property = 0x114 // TPM_PT_CONTEXT_GAP_MAX
	PropertyNVCountersMax     Property = 0x116 // TPM_PT_NV_COUNTERS_MAX
	PropertyNVIndexMax        Property = 0x117 // TPM_PT_NV_INDEX_MAX
	PropertyMemory            Property = 0x118 // TPM_PT_MEMORY
	PropertyClockUpdate       Property = 0x119 // TPM_PT_CLOCK_UPDATE
	PropertyContextHash       Property = 0x11a // TPM_PT_CONTEXT_HASH
	PropertyContextSym        Property = 0x11b // TPM_PT_CONTEXT_SYM
	PropertyContextSymSize    Property = 0x11c // TPM_PT_CONTEXT_SYM_SIZE
	PropertyOrderlyCount      Property = 0x11d // TPM_PT_ORDERLY_COUNT
	PropertyMaxCommandSize    Property = 0x11e // TPM_PT_MAX_COMMAND_SIZE
	PropertyMaxResponseSize   Property = 0x11f // TPM_PT_MAX_RESPONSE_SIZE
	PropertyMaxDigest         Property = 0x120 // TPM_PT_MAX_DIGEST
	PropertyMaxObjectContext  Property = 0x121 // TPM_PT_MAX_OBJECT_CONTEXT
	PropertyMaxSessionContext Property = 0x122 // TPM_PT_MAX_SESSION_CONTEXT
	PropertyPSFamilyIndicator Property = 0x123 // TPM_PT_PS_FAMILY_INDICATOR
	PropertyPSLevel           Property = 0x124 // TPM_PT_PS_LEVEL
	PropertyPSRevision        Property = 0x125 // TPM_PT_PS_REVISION
	PropertyPSDayOfYear       Property = 0x126 // TPM_PT_PS_DAY_OF_YEAR
	PropertyPSYear            Property = 0x127 // TPM_PT_PS_YEAR
	PropertySplitMax          Property = 0x128 // TPM_PT_SPLIT_MAX
	PropertyTotalCommands     Property = 0x129 // TPM_PT_TOTAL_COMMANDS
	PropertyLibraryCommands   Property = 0x12a // TPM_PT_LIBRARY_COMMANDS
	PropertyVendorCommands    Property = 0x12b // TPM_PT_VENDOR_COMMANDS
	PropertyNVBufferMax       Property = 0x12c // TPM_PT_NV_BUFFER_MAX
	PropertyModes             Property = 0x12d // TPM_PT_MODES
	PropertyMaxCapBuffer      Property = 0x12e // TPM_PT_MAX_CAP_BUFFER
	PropertyFirmwareSVN       Property = 0x12f // TPM_PT_FIRMWARE_SVN
	PropertyFirmwareMaxSVN    Property = 0x130 // TPM_PT_FIRMWARE_MAX_SVN

	PropertyFixed Property = PropertyFamilyIndicator
)

const (
	// These constants represent properties that change for reasons other than a firmware upgrade. Some of
	// them may not persist across power cycles.
	PropertyPermanent         Property = 0x200 // TPM_PT_PERMANENT
	PropertyStartupClear      Property = 0x201 // TPM_PT_STARTUP_CLEAR
	PropertyHRNVIndex         Property = 0x202 // TPM_PT_HR_NV_INDEX
	PropertyHRLoaded          Property = 0x203 // TPM_PT_HR_LOADED
	PropertyHRLoadedAvail     Property = 0x204 // TPM_PT_HR_LOADED_AVAIL
	PropertyHRActive          Property = 0x205 // TPM_PT_HR_ACTIVE
	PropertyHRActiveAvail     Property = 0x206 // TPM_PT_HR_ACTIVE_AVAIL
	PropertyHRTransientAvail  Property = 0x207 // TPM_PT_HR_TRANSIENT_AVAIL
	PropertyHRPersistent      Property = 0x208 // TPM_PT_HR_PERSISTENT
	PropertyHRPersistentAvail Property = 0x209 // TPM_PT_HR_PERSISTENT_AVAIL
	PropertyNVCounters        Property = 0x20a // TPM_PT_NV_COUNTERS
	PropertyNVCountersAvail   Property = 0x20b // TPM_PT_NV_COUNTERS_AVAIL
	PropertyAlgorithmSet      Property = 0x20c // TPM_PT_ALGORITHM_SET
	PropertyLoadedCurves      Property = 0x20d // TPM_PT_LOADED_CURVES
	PropertyLockoutCounter    Property = 0x20e // TPM_PT_LOCKOUT_COUNTER
	PropertyMaxAuthFail       Property = 0x20f // TPM_PT_MAX_AUTH_FAIL
	PropertyLockoutInterval   Property = 0x210 // TPM_PT_LOCKOUT_INTERVAL
	PropertyLockoutRecovery   Property = 0x211 // TPM_PT_LOCKOUT_RECOVERY
	PropertyNVWriteRecovery   Property = 0x212 // TPM_PT_NV_WRITE_RECOVERY
	PropertyAuditCounter0     Property = 0x213 // TPM_PT_AUDIT_COUNTER_0
	PropertyAuditCounter1     Property = 0x214 // TPM_PT_AUDIT_COUNTER_1

	PropertyVar Property = PropertyPermanent
)

// PropertyPCR corresponds to the TPM_PT_PCR type.
type PropertyPCR uint32

const (
	PropertyPCRSave        PropertyPCR = 0x00 // TPM_PT_PCR_SAVE
	PropertyPCRExtendL0    PropertyPCR = 0x01 // TPM_PT_PCR_EXTEND_L0
	PropertyPCRResetL0     PropertyPCR = 0x02 // TPM_PT_PCR_RESET_L0
	PropertyPCRExtendL1    PropertyPCR = 0x03 // TPM_PT_PCR_EXTEND_L1
	PropertyPCRResetL1     PropertyPCR = 0x04 // TPM_PT_PCR_RESET_L1
	PropertyPCRExtendL2    PropertyPCR = 0x05 // TPM_PT_PCR_EXTEND_L2
	PropertyPCRResetL2     PropertyPCR = 0x06 // TPM_PT_PCR_RESET_L2
	PropertyPCRExtendL3    PropertyPCR = 0x07 // TPM_PT_PCR_EXTEND_L3
	PropertyPCRResetL3     PropertyPCR = 0x08 // TPM_PT_PCR_RESET_L3
	PropertyPCRExtendL4    PropertyPCR = 0x09 // TPM_PT_PCR_EXTEND_L4
	PropertyPCRResetL4     PropertyPCR = 0x0a // TPM_PT_PCR_RESET_L4
	PropertyPCRNoIncrement PropertyPCR = 0x11 // TPM_PT_PCR_NO_INCREMENT
	PropertyPCRDRTMReset   PropertyPCR = 0x12 // TPM_PT_PCR_DRTM_RESET
	PropertyPCRPolicy      PropertyPCR = 0x13 // TPM_PT_PCR_POLICY
	PropertyPCRAuth        PropertyPCR = 0x14 // TPM_PT_PCR_AUTH

	PropertyPCRFirst PropertyPCR = PropertyPCRSave
)
