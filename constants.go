// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"math"
)

const (
	DefaultRSAExponent = 65537
)

const (
	StartupClear StartupType = iota
	StartupState
)

const (
	TPMManufacturerAMD  TPMManufacturer = 0x414D4400 // AMD
	TPMManufacturerATML TPMManufacturer = 0x41544D4C // Atmel
	TPMManufacturerBRCM TPMManufacturer = 0x4252434D // Broadcom
	TPMManufacturerHPE  TPMManufacturer = 0x48504500 // HPE
	TPMManufacturerIBM  TPMManufacturer = 0x49424d00 // IBM
	TPMManufacturerIFX  TPMManufacturer = 0x49465800 // Infineon
	TPMManufacturerINTC TPMManufacturer = 0x494E5443 // Intel
	TPMManufacturerLEN  TPMManufacturer = 0x4C454E00 // Lenovo
	TPMManufacturerMSFT TPMManufacturer = 0x4D534654 // Microsoft
	TPMManufacturerNSM  TPMManufacturer = 0x4E534D20 // National Semiconductor
	TPMManufacturerNTZ  TPMManufacturer = 0x4E545A00 // Nationz
	TPMManufacturerNTC  TPMManufacturer = 0x4E544300 // Nuvoton Technology
	TPMManufacturerQCOM TPMManufacturer = 0x51434F4D // Qualcomm
	TPMManufacturerSMSC TPMManufacturer = 0x534D5343 // SMSC
	TPMManufacturerSTM  TPMManufacturer = 0x53544D20 // ST Microelectronics
	TPMManufacturerSMSN TPMManufacturer = 0x534D534E // Samsung
	TPMManufacturerSNS  TPMManufacturer = 0x534E5300 // Sinosun
	TPMManufacturerTXN  TPMManufacturer = 0x54584E00 // Texas Instruments
	TPMManufacturerWEC  TPMManufacturer = 0x57454300 // Winbond
	TPMManufacturerROCC TPMManufacturer = 0x524F4343 // Fuzhou Rockchip
	TPMManufacturerGOOG TPMManufacturer = 0x474F4F47 // Google
)

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

const (
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

const (
	TPMGeneratedValue TPMGenerated = 0xff544347 // TPM_GENERATED_VALUE
)

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

const (
	Success ResponseCode = 0
)

const (
	// ErrorInitialize corresponds to TPM_RC_INITIALIZE and is returned for any command executed between a _TPM_Init event and a
	// TPM2_Startup command.
	ErrorInitialize ErrorCode = 0x00

	// ErrorFailure corresponds to TPM_RC_FAILURE and is returned for any command if the TPM is in failure mode.
	ErrorFailure ErrorCode = 0x01

	ErrorSequence  ErrorCode = 0x03 // TPM_RC_SEQUENCE
	ErrorDisabled  ErrorCode = 0x20 // TPM_RC_DISABLED
	ErrorExclusive ErrorCode = 0x21 // TPM_RC_EXCLUSIVE

	// ErrorAuthType corresponds to TPM_RC_AUTH_TYPE and is returned for a command where an authorization is required and the
	// authorization type is expected to be a policy session, but another authorization type has been provided.
	ErrorAuthType ErrorCode = 0x24

	// ErrorAuthMissing corresponds to TPM_RC_AUTH_MISSING and is returned for a command that accepts a HandleContext or Handle
	// argument that requires authorization, but no authorization session has been provided in the command payload.
	ErrorAuthMissing ErrorCode = 0x25

	ErrorPolicy ErrorCode = 0x26 // TPM_RC_POLICY
	ErrorPCR    ErrorCode = 0x27 // TPM_RC_PCR

	// ErrorPCRChanged corresponds to TPM_RC_PCR_CHANGED and is returned for a command where a policy session is used for authorization
	// and the PCR contents have been updated since the last time that they were checked in the session with a TPM2_PolicyPCR assertion.
	ErrorPCRChanged ErrorCode = 0x28

	// ErrorUpgrade corresponds to TPM_RC_UPGRADE and is returned for any command that isn't TPM2_FieldUpgradeData if the TPM is in
	// field upgrade mode.
	ErrorUpgrade ErrorCode = 0x2d

	ErrorTooManyContexts ErrorCode = 0x2e // TPM_RC_TOO_MANY_CONTEXTS

	// ErrorAuthUnavailable corresponds to TPM_RC_AUTH_UNAVAILABLE and is returned for a command where the provided authorization
	// requires the use of the authorization value for an entity, but the authorization value cannot be used. For example, if the entity
	// is an object and the command requires the user auth role but the object does not have the AttrUserWithAuth attribute.
	ErrorAuthUnavailable ErrorCode = 0x2f

	// ErrorReboot corresponds to TPM_RC_REBOOT and is returned for any command if the TPM requires a _TPM_Init event before it will
	// execute any more commands.
	ErrorReboot ErrorCode = 0x30

	ErrorUnbalanced ErrorCode = 0x31 // TPM_RC_UNBALANCED

	// ErrorCommandSize corresponds to TPM_RC_COMMAND_SIZE and indicates that the value of the commandSize field in the command header
	// does not match the size of the command packet transmitted to the TPM.
	ErrorCommandSize ErrorCode = 0x42

	// ErrorCommandCode corresponds to TPM_RC_COMMAND_CODE and is returned for any command that is not implemented by the TPM.
	ErrorCommandCode ErrorCode = 0x43

	ErrorAuthsize ErrorCode = 0x44 // TPM_RC_AUTHSIZE

	// ErrorAuthContext corresponds to TPM_RC_AUTH_CONTEXT and is returned for any command that does not accept any sessions if
	// sessions have been provided in the command payload.
	ErrorAuthContext ErrorCode = 0x45

	ErrorNVRange         ErrorCode = 0x46 // TPM_RC_NV_RANGE
	ErrorNVSize          ErrorCode = 0x47 // TPM_RC_NV_SIZE
	ErrorNVLocked        ErrorCode = 0x48 // TPM_RC_NV_LOCKED
	ErrorNVAuthorization ErrorCode = 0x49 // TPM_RC_NV_AUTHORIZATION
	ErrorNVUninitialized ErrorCode = 0x4a // TPM_RC_NV_UNINITIALIZED
	ErrorNVSpace         ErrorCode = 0x4b // TPM_RC_NV_SPACE
	ErrorNVDefined       ErrorCode = 0x4c // TPM_RC_NV_DEFINED
	ErrorBadContext      ErrorCode = 0x50 // TPM_RC_BAD_CONTEXT
	ErrorCpHash          ErrorCode = 0x51 // TPM_RC_CPHASH
	ErrorParent          ErrorCode = 0x52 // TPM_RC_PARENT
	ErrorNeedsTest       ErrorCode = 0x53 // TPM_RC_NEEDS_TEST

	// ErrorNoResult corresponds to TPM_RC_NO_RESULT and is returned for any command if the TPM cannot process a request due to an
	// unspecified problem.
	ErrorNoResult ErrorCode = 0x54

	ErrorSensitive ErrorCode = 0x55 // TPM_RC_SENSITIVE

	errorCode1Start ErrorCode = 0x80

	ErrorAsymmetric ErrorCode = errorCode1Start + 0x01 // TPM_RC_ASYMMETRIC

	// ErrorAttributes corresponds to TPM_RC_ATTRIBUTES and is returned as a *TPMSessionError for a command in the following
	// circumstances:
	// * More than one SessionContext instance with the AttrCommandEncrypt attribute has been provided.
	// * More than one SessionContext instance with the AttrResponseEncrypt attribute has been provided.
	// * A SessionContext instance referencing a trial session has been provided for authorization.
	ErrorAttributes ErrorCode = errorCode1Start + 0x02

	// ErrorHash corresponds to TPM_RC_HASH and is returned as a *TPMParameterError error for any command that accepts a AlgorithmId
	// parameter that corresponds to the TPMI_ALG_HASH interface type if the parameter value is not a valid digest algorithm.
	ErrorHash ErrorCode = errorCode1Start + 0x03

	// ErrorValue corresponds to TPM_RC_VALUE and is returned as a *TPMParameterError or *TPMHandleError for any command where an
	// argument value is incorrect or out of range for the command.
	ErrorValue ErrorCode = errorCode1Start + 0x04 // TPM_RC_VALUE

	// ErrorHierarchy corresponds to TPM_RC_HIERARCHY and is returned as a *TPMHandleError error for any command that accepts a
	// HandleContext or Handle argument if that argument corresponds to a hierarchy on the TPM that has been disabled.
	ErrorHierarchy ErrorCode = errorCode1Start + 0x05

	ErrorKeySize ErrorCode = errorCode1Start + 0x07 // TPM_RC_KEY_SIZE
	ErrorMGF     ErrorCode = errorCode1Start + 0x08 // TPM_RC_MGF

	// ErrorMode corresponds to TPM_RC_MODE and is returned as a *TPMParameterError error for any command that accepts a AlgorithmId
	// parameter that corresponds to the TPMI_ALG_SYM_MODE interface type if the parameter value is not a valid symmetric mode.
	ErrorMode ErrorCode = errorCode1Start + 0x09

	// ErrorType corresponds to TPM_RC_TYPE and is returned as a *TPMParameterError error for any command that accepts a AlgorithmId
	// parameter that corresponds to the TPMI_ALG_PUBLIC interface type if the parameter value is not a valid public type.
	ErrorType ErrorCode = errorCode1Start + 0x0a

	ErrorHandle ErrorCode = errorCode1Start + 0x0b // TPM_RC_HANDLE

	// ErrorKDF corresponds to TPM_RC_KDF and is returned as a *TPMParameterError error for any command that accepts a AlgorithmId
	// parameter that corresponds to the TPMI_ALG_KDF interface type if the parameter value is not a valid key derivation function.
	ErrorKDF ErrorCode = errorCode1Start + 0x0c

	ErrorRange ErrorCode = errorCode1Start + 0x0d // TPM_RC_RANGE

	// ErrorAuthFail corresponds to TPM_RC_AUTH_FAIL and is returned as a *TPMSessionError error for a command if an authorization
	// check fails. The dictionary attack counter is incremented when this error is returned.
	ErrorAuthFail ErrorCode = errorCode1Start + 0x0e

	// ErrorNonce corresponds to TPM_RC_NONCE and is returned as a *TPMSessionError error for any command where a password authorization
	// has been provided and the authorization session in the command payload contains a non-zero sized nonce field.
	ErrorNonce ErrorCode = errorCode1Start + 0x0f

	// ErrorPP corresponds to TPM_RC_PP and is returned as a *TPMSessionError for a command in the following circumstances:
	// * Authorization of the platform hierarchy is provided and the command requires an assertion of physical presence that hasn't been
	//   provided.
	// * Authorization is provided with a policy session that includes the TPM2_PolicyPhysicalPresence assertion, and an assertion of
	//   physical presence hasn't been provided.
	ErrorPP ErrorCode = errorCode1Start + 0x10

	// ErrorScheme corresponds to TPM_RC_SCHEME and is returned as a *TPMParameterError error for any command that accepts a AlgorithmId
	// parameter that corresponds to the TPMI_ALG_SIG_SCHEME or TPMI_ALG_ECC_SCHEME interface types if the parameter value is not a valid
	// signature or ECC key exchange scheme.
	ErrorScheme ErrorCode = errorCode1Start + 0x12

	// ErrorSize corresponds to TPM_RC_SIZE and is returned for a command in the following circumstances:
	// * As a *TPMParameterError if the command accepts a parameter type corresponding to TPM2B or TPML prefixed types and the size or
	//   length field has an invalid value.
	// * As a *TPMHandleError with an unspecified handle if the TPM's parameter unmarshalling doesn't consume all of the bytes in the
	//   input buffer.
	// * As a *TPMHandleError with an unspecified handle if the size field of the command's authorization area is an invalid value.
	// * As a *TPMSessionError if the authorization area for a command payload contains more than 3 sessions.
	ErrorSize ErrorCode = errorCode1Start + 0x15

	// ErrorSymmetric corresponds to TPM_RC_SYMMETRIC and is returned for a command in the following circumstances:
	// * As a *TPMParameterError if the command accepts a AlgorithmId parameter that corresponds to the TPMI_ALG_SYM interface type
	//   and the parameter value is not a valid symmetric algorithm.
	// * As a *TPMSessionError if a SessionContext instance is provided with the AttrCommandEncrypt attribute set but the session has no
	//   symmetric algorithm.
	// * As a *TPMSessionError if a SessionContext instance is provided with the AttrResponseEncrypt attribute set but the session has no
	//   symmetric algorithm.
	ErrorSymmetric ErrorCode = errorCode1Start + 0x16

	// ErrorTag corresponds to TPM_RC_TAG and is returned as a *TPMParameterError error for a command that accepts a StructTag parameter
	// if the parameter value is not the correct value.
	ErrorTag ErrorCode = errorCode1Start + 0x17

	// ErrorSelector corresponds to TPM_RC_SELECTOR and is returned as a *TPMParameterError error for a command that accepts a parameter
	// type corresponding to a TPMU prefixed type if the value of the selector field in the surrounding TPMT prefixed type is incorrect.
	ErrorSelector ErrorCode = errorCode1Start + 0x18

	// ErrorInsufficient corresponds to TPM_RC_INSUFFICIENT and is returned as a *TPMParameterError for a command if there is
	// insufficient data in the TPM's input buffer to complete unmarshalling of the command parameters.
	ErrorInsufficient ErrorCode = errorCode1Start + 0x1a

	ErrorSignature ErrorCode = errorCode1Start + 0x1b // TPM_RC_SIGNATURE
	ErrorKey       ErrorCode = errorCode1Start + 0x1c // TPM_RC_KEY

	// ErrorPolicyFail corresponds to TPM_RC_POLICY_FAIL and is returned as a *TPMSessionError error for a command in the following
	// circumstances:
	// * A policy session is used for authorization and the policy session digest does not match the authorization policy digest for
	//   the entity being authorized.
	// * A policy session is used for authorization and the digest algorithm of the session does not match the name algorithm of the
	//   entity being authorized.
	// * A policy session is used for authorization but the authorization is for the admin or DUP role and the policy session does not
	//   include a TPM2_PolicyCommandCode assertion.
	// * A policy session is used for authorization and the policy session includes a TPM2_PolicyNvWritten assertion but the entity
	//   being authorized is not a NV index.
	// * A policy session is used for authorization, the policy session includes the TPM2_PolicyNvWritten assertion, but the NV index
	//   being authorized does not have the AttrNVWritten attribute set.
	ErrorPolicyFail ErrorCode = errorCode1Start + 0x1d

	ErrorIntegrity ErrorCode = errorCode1Start + 0x1f // TPM_RC_INTEGRITY
	ErrorTicket    ErrorCode = errorCode1Start + 0x20 // TPM_RC_TICKET

	// ErroReservedBits corresponds to TPM_RC_RESERVED_BITS and is returned as a *TPMParameterError error for a command that accepts
	// a parameter type corresponding to a TPMA prefixed type if the parameter value has reserved bits set.
	ErrorReservedBits ErrorCode = errorCode1Start + 0x21

	// ErrorBadAuth corresponds to TPM_RC_BAD_AUTH and is returned as a *TPMSessionError error for a command if an authorization
	// check fails and the authorized entity is excempt from dictionary attack protections.
	ErrorBadAuth ErrorCode = errorCode1Start + 0x22

	// ErrorExpired corresponds to TPM_RC_EXPIRED and is returned as a *TPMSessionError error for a command if a policy session is used
	// for authorization, and the session has expired.
	ErrorExpired ErrorCode = errorCode1Start + 0x23

	// ErrorPolicyCC corresponds to TPM_RC_POLICY_CC and is returned as a *TPMSessionError error for a command if a policy session is
	// used for authorization, the session includes a TPM2_PolicyCommandCode assertion, but the command code doesn't match the command
	// for which the authorization is being used for.
	ErrorPolicyCC ErrorCode = errorCode1Start + 0x24

	ErrorBinding ErrorCode = errorCode1Start + 0x25 // TPM_RC_BINDING

	// ErrorCurve corresponds to TPM_RC_CURVE and is returned as a *TPMParameterError for a command that accepts a ECCCurve parameter
	// if the parameter value is incorrect.
	ErrorCurve ErrorCode = errorCode1Start + 0x26

	ErrorECCPoint ErrorCode = errorCode1Start + 0x27 // TPM_RC_ECC_POINT
)

const (
	WarningContextGap     WarningCode = 0x01 // TPM_RC_CONTEXT_GAP
	WarningObjectMemory   WarningCode = 0x02 // TPM_RC_OBJECT_MEMORY
	WarningSessionMemory  WarningCode = 0x03 // TPM_RC_SESSION_MEMORY
	WarningMemory         WarningCode = 0x04 // TPM_RC_MEMORY
	WarningSessionHandles WarningCode = 0x05 // TPM_RC_SESSION_HANDLES
	WarningObjectHandles  WarningCode = 0x06 // TPM_RC_OBJECT_HANDLES

	// WarningLocality corresponds to TPM_RC_LOCALITY and is returned for a command if a policy session is used for authorization and the
	// session includes a TPM2_PolicyLocality assertion, but the command isn't executed with the authorized locality.
	WarningLocality WarningCode = 0x07

	// WarningYielded corresponds to TPM_RC_YIELDED and is returned for any command that is suspended as a hint that the command can be
	// retried. This is handled automatically by all methods on TPMContext that execute commands via TPMContext.RunCommand by
	// resubmitting the command.
	WarningYielded WarningCode = 0x08

	// WarningCanceled corresponds to TPM_RC_CANCELED and is returned for any command that is canceled before being able to complete.
	WarningCanceled WarningCode = 0x09

	WarningTesting     WarningCode = 0x0a // TPM_RC_TESTING
	WarningReferenceH0 WarningCode = 0x10 // TPM_RC_REFERENCE_H0
	WarningReferenceH1 WarningCode = 0x11 // TPM_RC_REFERENCE_H1
	WarningReferenceH2 WarningCode = 0x12 // TPM_RC_REFERENCE_H2
	WarningReferenceH3 WarningCode = 0x13 // TPM_RC_REFERENCE_H3
	WarningReferenceH4 WarningCode = 0x14 // TPM_RC_REFERENCE_H4
	WarningReferenceH5 WarningCode = 0x15 // TPM_RC_REFERENCE_H5
	WarningReferenceH6 WarningCode = 0x16 // TPM_RC_REFERENCE_H6
	WarningReferenceS0 WarningCode = 0x18 // TPM_RC_REFERENCE_S0
	WarningReferenceS1 WarningCode = 0x19 // TPM_RC_REFERENCE_S1
	WarningReferenceS2 WarningCode = 0x1a // TPM_RC_REFERENCE_S2
	WarningReferenceS3 WarningCode = 0x1b // TPM_RC_REFERENCE_S3
	WarningReferenceS4 WarningCode = 0x1c // TPM_RC_REFERENCE_S4
	WarningReferenceS5 WarningCode = 0x1d // TPM_RC_REFERENCE_S5
	WarningReferenceS6 WarningCode = 0x1e // TPM_RC_REFERENCE_S6

	// WarningNVRate corresponds to TPM_RC_NV_RATE and is returned for any command that requires NV access if NV access is currently
	// rate limited to prevent the NV memory from wearing out.
	WarningNVRate WarningCode = 0x20

	// WarningLockout corresponds to TPM_RC_LOCKOUT and is returned for any command that requires authorization for an entity that is
	// subject to dictionary attack protection, and the TPM is in dictionary attack lockout mode.
	WarningLockout WarningCode = 0x21

	// WarningRetry corresponds to TPM_RC_RETRY and is returned for any command if the TPM was not able to start the command. This is
	// handled automatically by all methods on TPMContext that execute commands via TPMContext.RunCommand by resubmitting the command.
	WarningRetry WarningCode = 0x22

	// WarningNVUnavailable corresponds to TPM_RC_NV_UNAVAILABLE and is returned for any command that requires NV access but NV memory
	// is currently not available.
	WarningNVUnavailable WarningCode = 0x23
)

const (
	HandleOwner       Handle = 0x40000001 // TPM_RH_OWNER
	HandleNull        Handle = 0x40000007 // TPM_RH_NULL
	HandleUnassigned  Handle = 0x40000008 // TPM_RH_UNASSIGNED
	HandlePW          Handle = 0x40000009 // TPM_RS_PW
	HandleLockout     Handle = 0x4000000a // TPM_RH_LOCKOUT
	HandleEndorsement Handle = 0x4000000b // TPM_RH_ENDORSEMENT
	HandlePlatform    Handle = 0x4000000c // TPM_RH_PLATFORM
	HandlePlatformNV  Handle = 0x4000000d // TPM_RH_PLATFORM_NV
)

const (
	HandleTypePCR           HandleType = 0x00 // TPM_HT_PCR
	HandleTypeNVIndex       HandleType = 0x01 // TPM_HT_NV_INDEX
	HandleTypeHMACSession   HandleType = 0x02 // TPM_HT_HMAC_SESSION
	HandleTypeLoadedSession HandleType = 0x02 // TPM_HT_LOADED_SESSION
	HandleTypePolicySession HandleType = 0x03 // TPM_HT_POLICY_SESSION
	HandleTypeSavedSession  HandleType = 0x03 // TPM_HT_SAVED_SESSION
	HandleTypePermanent     HandleType = 0x40 // TPM_HT_PERMANENT
	HandleTypeTransient     HandleType = 0x80 // TPM_HT_TRANSIENT
	HandleTypePersistent    HandleType = 0x81 // TPM_HT_PERSISTENT
)

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
	AlgorithmECSCHNORR      AlgorithmId = 0x001c // TPM_ALG_ECSCHNORR
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
	AlgorithmCTR            AlgorithmId = 0x0040 // TPM_ALG_CTR
	AlgorithmOFB            AlgorithmId = 0x0041 // TPM_ALG_OFB
	AlgorithmCBC            AlgorithmId = 0x0042 // TPM_ALG_CBC
	AlgorithmCFB            AlgorithmId = 0x0043 // TPM_ALG_CFB
	AlgorithmECB            AlgorithmId = 0x0044 // TPM_ALG_ECB

	AlgorithmFirst AlgorithmId = AlgorithmRSA
)

const (
	HashAlgorithmNull     HashAlgorithmId = HashAlgorithmId(AlgorithmNull)     // TPM_ALG_NULL
	HashAlgorithmSHA1     HashAlgorithmId = HashAlgorithmId(AlgorithmSHA1)     // TPM_ALG_SHA1
	HashAlgorithmSHA256   HashAlgorithmId = HashAlgorithmId(AlgorithmSHA256)   // TPM_ALG_SHA256
	HashAlgorithmSHA384   HashAlgorithmId = HashAlgorithmId(AlgorithmSHA384)   // TPM_ALG_SHA384
	HashAlgorithmSHA512   HashAlgorithmId = HashAlgorithmId(AlgorithmSHA512)   // TPM_ALG_SHA512
	HashAlgorithmSM3_256  HashAlgorithmId = HashAlgorithmId(AlgorithmSM3_256)  // TPM_ALG_SM3_256
	HashAlgorithmSHA3_256 HashAlgorithmId = HashAlgorithmId(AlgorithmSHA3_256) // TPM_ALG_SHA3_256
	HashAlgorithmSHA3_384 HashAlgorithmId = HashAlgorithmId(AlgorithmSHA3_384) // TPM_ALG_SHA3_384
	HashAlgorithmSHA3_512 HashAlgorithmId = HashAlgorithmId(AlgorithmSHA3_512) // TPM_ALG_SHA3_512
)

const (
	SymAlgorithmTDES     SymAlgorithmId = SymAlgorithmId(AlgorithmTDES)     // TPM_ALG_TDES
	SymAlgorithmAES      SymAlgorithmId = SymAlgorithmId(AlgorithmAES)      // TPM_ALG_AES
	SymAlgorithmXOR      SymAlgorithmId = SymAlgorithmId(AlgorithmXOR)      // TPM_ALG_XOR
	SymAlgorithmNull     SymAlgorithmId = SymAlgorithmId(AlgorithmNull)     // TPM_ALG_NULL
	SymAlgorithmSM4      SymAlgorithmId = SymAlgorithmId(AlgorithmSM4)      // TPM_ALG_SM4
	SymAlgorithmCamellia SymAlgorithmId = SymAlgorithmId(AlgorithmCamellia) // TPM_ALG_CAMELLIA
)

const (
	SymObjectAlgorithmAES      SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmAES)      // TPM_ALG_AES
	SymObjectAlgorithmNull     SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmNull)     // TPM_ALG_NULL
	SymObjectAlgorithmSM4      SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmSM4)      // TPM_ALG_SM4
	SymObjectAlgorithmCamellia SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmCamellia) // TPM_ALG_CAMELLIA
)

const (
	SymModeNull SymModeId = SymModeId(AlgorithmNull) // TPM_ALG_NULL
	SymModeCTR  SymModeId = SymModeId(AlgorithmCTR)  // TPM_ALG_CTR
	SymModeOFB  SymModeId = SymModeId(AlgorithmOFB)  // TPM_ALG_OFB
	SymModeCBC  SymModeId = SymModeId(AlgorithmCBC)  // TPM_ALG_CBC
	SymModeCFB  SymModeId = SymModeId(AlgorithmCFB)  // TPM_ALG_CFB
	SymModeECB  SymModeId = SymModeId(AlgorithmECB)  // TPM_ALG_ECB
)

const (
	KDFAlgorithmMGF1           KDFAlgorithmId = KDFAlgorithmId(AlgorithmMGF1)           // TPM_ALG_MGF1
	KDFAlgorithmNull           KDFAlgorithmId = KDFAlgorithmId(AlgorithmNull)           // TPM_ALG_NULL
	KDFAlgorithmKDF1_SP800_56A KDFAlgorithmId = KDFAlgorithmId(AlgorithmKDF1_SP800_56A) // TPM_ALG_KDF1_SP800_56A
	KDFAlgorithmKDF2           KDFAlgorithmId = KDFAlgorithmId(AlgorithmKDF2)           // TPM_ALG_KDF2
	KDFAlgorithmKDF1_SP800_108 KDFAlgorithmId = KDFAlgorithmId(AlgorithmKDF1_SP800_108) // TPM_ALG_KDF1_SP800_108
)

const (
	SigSchemeAlgHMAC      SigSchemeId = SigSchemeId(AlgorithmHMAC)      // TPM_ALG_HMAC
	SigSchemeAlgNull      SigSchemeId = SigSchemeId(AlgorithmNull)      // TPM_ALG_NULL
	SigSchemeAlgRSASSA    SigSchemeId = SigSchemeId(AlgorithmRSASSA)    // TPM_ALG_RSASSA
	SigSchemeAlgRSAPSS    SigSchemeId = SigSchemeId(AlgorithmRSAPSS)    // TPM_ALG_RSAPSS
	SigSchemeAlgECDSA     SigSchemeId = SigSchemeId(AlgorithmECDSA)     // TPM_ALG_ECDSA
	SigSchemeAlgECDAA     SigSchemeId = SigSchemeId(AlgorithmECDAA)     // TPM_ALG_ECDAA
	SigSchemeAlgSM2       SigSchemeId = SigSchemeId(AlgorithmSM2)       // TPM_ALG_SM2
	SigSchemeAlgECSCHNORR SigSchemeId = SigSchemeId(AlgorithmECSCHNORR) // TPM_ALG_ECSCHNORR
)

const (
	KeyedHashSchemeHMAC KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmHMAC) // TPM_ALG_HMAC
	KeyedHashSchemeXOR  KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmXOR)  // TPM_ALG_XOR
	KeyedHashSchemeNull KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmNull) // TPM_ALG_NULL
)

const (
	AsymSchemeNull      AsymSchemeId = AsymSchemeId(AlgorithmNull)      // TPM_ALG_NULL
	AsymSchemeRSASSA    AsymSchemeId = AsymSchemeId(AlgorithmRSASSA)    // TPM_ALG_RSASSA
	AsymSchemeRSAES     AsymSchemeId = AsymSchemeId(AlgorithmRSAES)     // TPM_ALG_RSAES
	AsymSchemeRSAPSS    AsymSchemeId = AsymSchemeId(AlgorithmRSAPSS)    // TPM_ALG_RSAPSS
	AsymSchemeOAEP      AsymSchemeId = AsymSchemeId(AlgorithmOAEP)      // TPM_ALG_OAEP
	AsymSchemeECDSA     AsymSchemeId = AsymSchemeId(AlgorithmECDSA)     // TPM_ALG_ECDSA
	AsymSchemeECDH      AsymSchemeId = AsymSchemeId(AlgorithmECDH)      // TPM_ALG_ECDH
	AsymSchemeECDAA     AsymSchemeId = AsymSchemeId(AlgorithmECDAA)     // TPM_ALG_ECDAA
	AsymSchemeSM2       AsymSchemeId = AsymSchemeId(AlgorithmSM2)       // TPM_ALG_SM2
	AsymSchemeECSCHNORR AsymSchemeId = AsymSchemeId(AlgorithmECSCHNORR) // TPM_ALG_ECSCHNORR
	AsymSchemeECMQV     AsymSchemeId = AsymSchemeId(AlgorithmECMQV)     // TPM_ALG_ECMQV
)

const (
	RSASchemeNull   RSASchemeId = RSASchemeId(AlgorithmNull)   // TPM_ALG_NULL
	RSASchemeRSASSA RSASchemeId = RSASchemeId(AlgorithmRSASSA) // TPM_ALG_RSASSA
	RSASchemeRSAES  RSASchemeId = RSASchemeId(AlgorithmRSAES)  // TPM_ALG_RSAES
	RSASchemeRSAPSS RSASchemeId = RSASchemeId(AlgorithmRSAPSS) // TPM_ALG_RSAPSS
	RSASchemeOAEP   RSASchemeId = RSASchemeId(AlgorithmOAEP)   // TPM_ALG_OAEP
)

const (
	ECCSchemeNull      ECCSchemeId = ECCSchemeId(AlgorithmNull)      // TPM_ALG_NULL
	ECCSchemeECDSA     ECCSchemeId = ECCSchemeId(AlgorithmECDSA)     // TPM_ALG_ECDSA
	ECCSchemeECDH      ECCSchemeId = ECCSchemeId(AlgorithmECDH)      // TPM_ALG_ECDH
	ECCSchemeECDAA     ECCSchemeId = ECCSchemeId(AlgorithmECDAA)     // TPM_ALG_ECDAA
	ECCSchemeSM2       ECCSchemeId = ECCSchemeId(AlgorithmSM2)       // TPM_ALG_SM2
	ECCSchemeECSCHNORR ECCSchemeId = ECCSchemeId(AlgorithmECSCHNORR) // TPM_ALG_ECSCHNORR
	ECCSchemeECMQV     ECCSchemeId = ECCSchemeId(AlgorithmECMQV)     // TPM_ALG_ECMQV
)

const (
	ObjectTypeRSA       ObjectTypeId = ObjectTypeId(AlgorithmRSA)       // TPM_ALG_RSA
	ObjectTypeKeyedHash ObjectTypeId = ObjectTypeId(AlgorithmKeyedHash) // TPM_ALG_KEYEDHASH
	ObjectTypeECC       ObjectTypeId = ObjectTypeId(AlgorithmECC)       // TPM_ALG_ECC
	ObjectTypeSymCipher ObjectTypeId = ObjectTypeId(AlgorithmSymCipher) // TPM_ALG_SYMCIPHER
)

const (
	AttrFixedTPM             ObjectAttributes = 1 << 1  // fixedTPM
	AttrStClear              ObjectAttributes = 1 << 2  // stClear
	AttrFixedParent          ObjectAttributes = 1 << 4  // fixedParent
	AttrSensitiveDataOrigin  ObjectAttributes = 1 << 5  // sensitiveDataOrigin
	AttrUserWithAuth         ObjectAttributes = 1 << 6  // userWithAuth
	AttrAdminWithPolicy      ObjectAttributes = 1 << 7  // adminWithPolicy
	AttrNoDA                 ObjectAttributes = 1 << 10 // noDA
	AttrEncryptedDuplication ObjectAttributes = 1 << 11 // encryptedDuplication
	AttrRestricted           ObjectAttributes = 1 << 16 // restricted
	AttrDecrypt              ObjectAttributes = 1 << 17 // decrypt
	AttrSign                 ObjectAttributes = 1 << 18 // sign
)

const (
	// AttrContinueSession corresponds to continueSession and specifies that the session should not be flushed
	// from the TPM after it is used. If a session is used without this flag, it will be flushed from the TPM
	// after the command completes successfully. In this case, the HandleContext associated with the session
	// will be invalidated.
	AttrContinueSession SessionAttributes = 1 << iota

	// AttrAuditExclusive corresponds to auditExclusive and indicates that the command should only be executed
	// if the session is exclusive at the start of the command. A session becomes exclusive when it is used for
	// auditing for the first time, or if the AttrAuditReset attribute is provided. A session will remain
	// exclusive until the TPM executes any command where the exclusive session isn't used for auditing, if
	// that command allows for audit sessions to be provided.
	//
	// Setting this on SessionContext implies AttrAudit.
	AttrAuditExclusive

	// AttrAuditReset corresponds to auditReset and indicates that the audit digest of the session should be reset.
	// The session will subsequently become exclusive. A session will remain exclusive until the TPM executes any
	// command where the exclusive session isn't used for auditing, if that command allows for audit sessions to be
	// provided.
	//
	// Setting this on SessionContext implies AttrAudit.
	AttrAuditReset

	// AttrCommandEncrypt corresponds to decrypt and specifies that the session should be used for encryption of the
	// first command parameter before being sent from the host to the TPM. This can only be used for parameters that
	// have types corresponding to TPM2B prefixed TCG types, and requires a session that was configured with a valid
	// symmetric algorithm via the symmetric argument of TPMContext.StartAuthSession.
	AttrCommandEncrypt = 1 << (iota + 2)

	// AttrResponseEncrypt corresponds to encrypt and specifies that the session should be used for encryption of the
	// first response parameter before being sent from the TPM to the host. This can only be used for parameters that
	// have types corresponding to TPM2B prefixed TCG types, and requires a session that was configured with a valid
	// symmetric algorithm via the symmetric argument of TPMContext.StartAuthSession. This package automatically
	// decrypts the received encrypted response parameter.
	AttrResponseEncrypt

	// AttrAudit corresponds to audit and indicates that the session should be used for auditing. If this is the first
	// time that the session is used for auditing, then this attribute will result in the session becoming exclusive.
	// A session will remain exclusive until the TPM executes any command where the exclusive session isn't used for
	// auditing, if that command allows for audit sessions to be provided.
	AttrAudit
)

const (
	AttrNVPPWrite        NVAttributes = 1 << 0  // TPMA_NV_PPWRITE
	AttrNVOwnerWrite     NVAttributes = 1 << 1  // TPMA_NV_OWNERWRITE
	AttrNVAuthWrite      NVAttributes = 1 << 2  // TPMA_NV_AUTHWRITE
	AttrNVPolicyWrite    NVAttributes = 1 << 3  // TPMA_NV_POLICY_RITE
	AttrNVPolicyDelete   NVAttributes = 1 << 10 // TPMA_NV_POLICY_DELETE
	AttrNVWriteLocked    NVAttributes = 1 << 11 // TPMA_NV_WRITELOCKED
	AttrNVWriteAll       NVAttributes = 1 << 12 // TPMA_NV_WRITEALL
	AttrNVWriteDefine    NVAttributes = 1 << 13 // TPMA_NV_WRITEDEFINE
	AttrNVWriteStClear   NVAttributes = 1 << 14 // TPMA_NV_WRITE_STCLEAR
	AttrNVGlobalLock     NVAttributes = 1 << 15 // TPMA_NV_GLOBALLOCK
	AttrNVPPRead         NVAttributes = 1 << 16 // TPMA_NV_PPREAD
	AttrNVOwnerRead      NVAttributes = 1 << 17 // TPMA_NV_OWNERREAD
	AttrNVAuthRead       NVAttributes = 1 << 18 // TPMA_NV_AUTHREAD
	AttrNVPolicyRead     NVAttributes = 1 << 19 // TPMA_NV_POLICYREAD
	AttrNVNoDA           NVAttributes = 1 << 25 // TPMA_NV_NO_DA
	AttrNVOrderly        NVAttributes = 1 << 26 // TPMA_NV_ORDERLY
	AttrNVClearStClear   NVAttributes = 1 << 27 // TPMA_NV_CLEAR_STCLEAR
	AttrNVReadLocked     NVAttributes = 1 << 28 // TPMA_NV_READLOCKED
	AttrNVWritten        NVAttributes = 1 << 29 // TPMA_NV_WRITTEN
	AttrNVPlatformCreate NVAttributes = 1 << 30 // TPMA_NV_PLATFORMCREATE
	AttrNVReadStClear    NVAttributes = 1 << 31 // TPMA_NV_READ_STCLEAR
)

const (
	NVTypeOrdinary NVType = 0 // TPM_NT_ORDINARY
	NVTypeCounter  NVType = 1 // TPM_NT_COUNTER
	NVTypeBits     NVType = 2 // TPM_NT_BITS
	NVTypeExtend   NVType = 4 // TPM_NT_EXTEND
	NVTypePinFail  NVType = 8 // TPM_NT_PIN_FAIL
	NVTypePinPass  NVType = 9 // TPM_NT_PIN_PASS
)

const (
	LocalityZero  Locality = 0 // TPM_LOC_ZERO
	LocalityOne   Locality = 1 // TPM_LOC_ONE
	LocalityTwo   Locality = 2 // TPM_LOC_TWO
	LocalityThree Locality = 3 // TPM_LOC_THREE
	LocalityFour  Locality = 4 // TPM_LOC_FOUR
)

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

const (
	CapabilityMaxProperties uint32 = math.MaxUint32
)

const (
	// EventMaxSize indicates the maximum size of arguments of the Event type.
	EventMaxSize = 1024
)

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

const (
	AttrAsymmetric AlgorithmAttributes = 1 << 0
	AttrSymmetric  AlgorithmAttributes = 1 << 1
	AttrHash       AlgorithmAttributes = 1 << 2
	AttrObject     AlgorithmAttributes = 1 << 3
	AttrSigning    AlgorithmAttributes = 1 << 8
	AttrEncrypting AlgorithmAttributes = 1 << 9
	AttrMethod     AlgorithmAttributes = 1 << 10
)

const (
	AttrNV        CommandAttributes = 1 << 22
	AttrExtensive CommandAttributes = 1 << 23
	AttrFlushed   CommandAttributes = 1 << 24
	AttrRHandle   CommandAttributes = 1 << 28
	AttrV         CommandAttributes = 1 << 29
)

const (
	ECCCurveNIST_P192 ECCCurve = 0x0001 // TPM_ECC_NIST_P192
	ECCCurveNIST_P224 ECCCurve = 0x0002 // TPM_ECC_NIST_P224
	ECCCurveNIST_P256 ECCCurve = 0x0003 // TPM_ECC_NIST_P256
	ECCCurveNIST_P384 ECCCurve = 0x0004 // TPM_ECC_NIST_P384
	ECCCurveNIST_P521 ECCCurve = 0x0005 // TPM_ECC_NIST_P521
	ECCCurveBN_P256   ECCCurve = 0x0010 // TPM_ECC_BN_P256
	ECCCurveBN_P638   ECCCurve = 0x0011 // TPM_ECC_BN_P638
	ECCCurveSM2_P256  ECCCurve = 0x0020 // TPM_ECC_SM2_P256

	ECCCurveFirst ECCCurve = ECCCurveNIST_P192
)

const (
	SessionTypeHMAC   SessionType = 0x00 // TPM_SE_HMAC
	SessionTypePolicy SessionType = 0x01 // TPM_SE_POLICY
	SessionTypeTrial  SessionType = 0x03 // TPM_SE_TRIAL
)

const (
	AttrOwnerAuthSet       PermanentAttributes = 1 << 0  // ownerAuthSet
	AttrEndorsementAuthSet PermanentAttributes = 1 << 1  // endorsementAuthSet
	AttrLockoutAuthSet     PermanentAttributes = 1 << 2  // lockoutAuthSet
	AttrDisableClear       PermanentAttributes = 1 << 8  // disableClear
	AttrInLockout          PermanentAttributes = 1 << 9  // inLockout
	AttrTPMGeneratedEPS    PermanentAttributes = 1 << 10 // tpmGeneratedEPS
)

const (
	AttrPhEnable   StartupClearAttributes = 1 << 0  // phEnable
	AttrShEnable   StartupClearAttributes = 1 << 1  // shEnable
	AttrEhEnable   StartupClearAttributes = 1 << 2  // ehEnable
	AttrPhEnableNV StartupClearAttributes = 1 << 3  // phEnableNV
	AttrOrderly    StartupClearAttributes = 1 << 31 // orderly
)
