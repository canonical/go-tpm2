package tpm2

const (
	StartupClear StartupType = iota
	StartupState
)

const (
	TagNoSessions StructTag = 0x8001
	TagSessions   StructTag = 0x8002
	TagCreation   StructTag = 0x8021
)

const (
	CommandFirst CommandCode = 0x0000011A

	CommandEvictControl        CommandCode = 0x00000120
	CommandClear               CommandCode = 0x00000126
	CommandClearControl        CommandCode = 0x00000127
	CommandHierarchyChangeAuth CommandCode = 0x00000129
	CommandCreatePrimary       CommandCode = 0x00000131
	CommandPCREvent            CommandCode = 0x0000013C
	CommandIncrementalSelfTest CommandCode = 0x00000142
	CommandSelfTest            CommandCode = 0x00000143
	CommandStartup             CommandCode = 0x00000144
	CommandShutdown            CommandCode = 0x00000145
	CommandObjectChangeAuth    CommandCode = 0x00000150
	CommandCreate              CommandCode = 0x00000153
	CommandLoad                CommandCode = 0x00000157
	CommandUnseal              CommandCode = 0x0000015E
	CommandContextLoad         CommandCode = 0x00000161
	CommandContextSave         CommandCode = 0x00000162
	CommandFlushContext        CommandCode = 0x00000165
	CommandLoadExternal        CommandCode = 0x00000167
	CommandNVReadPublic        CommandCode = 0x00000169
	CommandReadPublic          CommandCode = 0x00000173
	CommandStartAuthSession    CommandCode = 0x00000176
	CommandGetCapability       CommandCode = 0x0000017A
	CommandGetTestResult       CommandCode = 0x0000017C
	CommandPCRRead             CommandCode = 0x0000017E
	CommandPolicyPCR           CommandCode = 0x0000017F
	CommandPCRExtend           CommandCode = 0x00000182
	CommandPolicyGetDigest     CommandCode = 0x00000189
	CommandCreateLoaded        CommandCode = 0x00000191
)

const (
	Success ResponseCode = 0
)

const (
	ErrorInitialize ErrorCode0 = iota
	ErrorFailure
	ErrorSequence = iota + 1
	ErrorDisabled = iota + 29
	ErrorExclusive
	ErrorAuthType = iota + 31
	ErrorAuthMissing
	ErrorPolicy
	ErrorPCR
	ErrorPCRChanged
	ErrorUpgrade = iota + 35
	ErrorTooManyContexts
	ErrorAuthUnavailable
	ErrorReboot
	ErrorUnbalanced
	ErrorCommandSize = iota + 51
	ErrorCommandCode
	ErrorAuthsize
	ErrorAuthContext
	ErrorNVRange
	ErrorNVSize
	ErrorNVLocked
	ErrorNVAuthorization
	ErrorNVUninitialized
	ErrorNVSpace
	ErrorNVDefined
	ErrorBadContext = iota + 54
	ErrorCpHash
	ErrorParent
	ErrorNeedsTest
	ErrorNoResult
	ErrorSensitive
)

const (
	ErrorAsymmetric ErrorCode1 = iota + 1
	ErrorAttributes
	ErrorHash
	ErrorValue
	ErrorHierarchy
	ErrorKeySize = iota + 2
	ErrorMGF
	ErrorMode
	ErrorType
	ErrorHandle
	ErrorKDF
	ErrorRange
	ErrorAuthFail
	ErrorNonce
	ErrorPP
	ErrorScheme = iota + 3
	ErrorSize   = iota + 5
	ErrorSymmetric
	ErrorTag
	ErrorSelector
	ErrorInsufficient = iota + 6
	ErrorSignature
	ErrorKey
	ErrorPolicyFail
	ErrorIntegrity = iota + 7
	ErrorTicket
	ErrorReservedBits
	ErrorBadAuth
	ErrorExpired
	ErrorPolicyCC
	ErrorBinding
	ErrorCurve
	ErrorECCPoint
)

const (
	WarningContextGap WarningCode = iota + 1
	WarningObjectMemory
	WarningSessionMemory
	WarningMemory
	WarningSessionHandles
	WarningObjectHandles
	WarningLocality
	WarningYielded
	WarningCanceled
	WarningTesting
	WarningReferenceH0 = iota + 6
	WarningReferenceH1
	WarningReferenceH2
	WarningReferenceH3
	WarningReferenceH4
	WarningReferenceH5
	WarningReferenceH6
	WarningReferenceS0 = iota + 7
	WarningReferenceS1
	WarningReferenceS2
	WarningReferenceS3
	WarningReferenceS4
	WarningReferenceS5
	WarningReferenceS6
	WarningNVRate = iota + 8
	WarningLockout
	WarningRetry
	WarningNVUnavailable
)

const (
	HandleOwner       Handle = 0x40000001
	HandleNull        Handle = 0x40000007
	HandleUnassigned  Handle = 0x40000008
	HandlePW          Handle = 0x40000009
	HandleLockout     Handle = 0x4000000a
	HandleEndorsement Handle = 0x4000000b
	HandlePlatform    Handle = 0x4000000c
	HandlePlatformNV  Handle = 0x4000000d
)

const (
	HandleTypePCR              Handle = 0x00000000
	HandleTypeNVIndex          Handle = 0x01000000
	HandleTypeHMACSession      Handle = 0x02000000
	HandleTypePolicySession    Handle = 0x03000000
	HandleTypePermanent        Handle = 0x40000000
	HandleTypeTransientObject  Handle = 0x80000000
	HandleTypePersistentObject Handle = 0x81000000

	HandleTypeLoadedSession Handle = 0x02000000
	HandleTypeActiveSession Handle = 0x03000000
)

const (
	AlgorithmRSA            AlgorithmId = 0x0001
	AlgorithmSHA1           AlgorithmId = 0x0004
	AlgorithmHMAC           AlgorithmId = 0x0005
	AlgorithmAES            AlgorithmId = 0x0006
	AlgorithmMGF1           AlgorithmId = 0x0007
	AlgorithmKeyedHash      AlgorithmId = 0x0008
	AlgorithmXOR            AlgorithmId = 0x000a
	AlgorithmSHA256         AlgorithmId = 0x000b
	AlgorithmSHA384         AlgorithmId = 0x000c
	AlgorithmSHA512         AlgorithmId = 0x000d
	AlgorithmNull           AlgorithmId = 0x0010
	AlgorithmSM3_256        AlgorithmId = 0x0012
	AlgorithmSM4            AlgorithmId = 0x0013
	AlgorithmRSASSA         AlgorithmId = 0x0014
	AlgorithmRSAES          AlgorithmId = 0x0015
	AlgorithmRSAPSS         AlgorithmId = 0x0016
	AlgorithmOAEP           AlgorithmId = 0x0017
	AlgorithmECDSA          AlgorithmId = 0x0018
	AlgorithmECDH           AlgorithmId = 0x0019
	AlgorithmECDAA          AlgorithmId = 0x001a
	AlgorithmSM2            AlgorithmId = 0x001b
	AlgorithmECSCHNORR      AlgorithmId = 0x001c
	AlgorithmECMQV          AlgorithmId = 0x001d
	AlgorithmKDF1_SP800_56A AlgorithmId = 0x0020
	AlgorithmKDF2           AlgorithmId = 0x0021
	AlgorithmKDF1_SP800_108 AlgorithmId = 0x0022
	AlgorithmECC            AlgorithmId = 0x0023
	AlgorithmSymCipher      AlgorithmId = 0x0025
	AlgorithmCamellia       AlgorithmId = 0x0026
	AlgorithmCTR            AlgorithmId = 0x0040
	AlgorithmOFB            AlgorithmId = 0x0041
	AlgorithmCBC            AlgorithmId = 0x0042
	AlgorithmCFB            AlgorithmId = 0x0043
	AlgorithmECB            AlgorithmId = 0x0044

	AlgorithmFirst AlgorithmId = AlgorithmRSA
)

const (
	AttrFixedTPM ObjectAttributes = 1 << (iota + 1)
	AttrStClear
	AttrFixedParent = 1 << (iota + 2)
	AttrSensitiveDataOrigin
	AttrUserWithAuth
	AttrAdminWithPolicy
	AttrNoDA = 1 << (iota + 4)
	AttrEncryptedDuplication
	AttrRestricted = 1 << (iota + 8)
	AttrDecrypt
	AttrSign
)

const (
	AttrNVPPWrite NVAttributes = 1 << iota
	AttrNVOwnerWrite
	AttrNVAuthWrite
	AttrNVPolicyWrite
	AttrNVPolicyDelete = 1 << (iota + 6)
	AttrNVWriteLocked
	AttrNVWriteAll
	AttrNVWriteDefine
	AttrNVWriteStClear
	AttrNVGlobalLock
	AttrNVPPRead
	AttrNVOwnerRead
	AttrNVAuthRead
	AttrNVPolicyRead
	AttrNVNoDA = 1 << (iota + 11)
	AttrNVOrderly
	AttrNVClearStClear
	AttrNVReadLocked
	AttrNVWritten
	AttrNVPlatformCreate
	AttrNVReadStClear
)

const (
	NVTypeOrdinary NVType = iota
	NVTypeCounter
	NVTypeBits
	NVTypeExtend  = iota + 1
	NVTypePinFail = iota + 4
	NVTypePinPass
)

const (
	LocalityZero Locality = iota
	LocalityOne
	LocalityTwo
	LocalityThree
	LocalityFour
)

const (
	CapabilityAlgs Capability = iota
	CapabilityHandles
	CapabilityCommands
	CapabilityPPCommands
	CapabilityAuditCommands
	CapabilityPCRs
	CapabilityTPMProperties
	CapabilityPCRProperties
	CapabilityECCCurves
	CapabilityAuthPolicies
)

const (
	CapabilityMaxAlgs          uint32 = 169
	CapabilityMaxHandles       uint32 = 254
	CapabilityMaxCommands      uint32 = 254
	CapabilityMaxTPMProperties uint32 = 127
	CapabilityMaxPCRProperties uint32 = 112
	CapabilityMaxECCCurves     uint32 = 508
	CapabilityMaxAuthPolicies  uint32 = 15
)

const (
	PropertyFamilyIndicator = iota + 0x100
	PropertyLevel
	PropertyRevision
	PropertyDayOfYear
	PropertyYear
	PropertyManufacturer
	PropertyVendorString1
	PropertyVendorString2
	PropertyVendorString3
	PropertyVendorString4
	PropertyVendorTPMType
	PropertyFirmwareVersion1
	PropertyFirmwareVersion2
	PropertyInputBuffer
	PropertyHRTransientMin
	PropertyHRPersistentMin
	PropertyHRLoadedMin
	PropertyActiveSessionsMax
	PropertyPCRCount
	PropertyPCRSelectMin
	PropertyContextGapMax
	PropertyNVCountersMax = iota + 0x101
	PropertyNVIndexMax
	PropertyMemory
	PropertyClockUpdate
	PropertyContextHash
	PropertyContextSym
	PropertyContextSymSize
	PropertyOrderlyCount
	PropertyMaxCommandSize
	PropertyMaxResponseSize
	PropertyMaxDigest
	PropertyMaxObjectContext
	PropertyMaxSessionContext
	PropertyPSFamilyIndicator
	PropertyPSLevel
	PropertyPSRevision
	PropertyPSDayOfYear
	PropertyPSYear
	PropertySplitMax
	PropertyTotalCommands
	PropertyLibraryCommands
	PropertyVendorCommands
	PropertyNVBufferMax
	PropertyModes
	PropertyMaxCapBuffer

	PropertyFixed Property = PropertyFamilyIndicator
)

const (
	PropertyPermanent = iota + 0x200
	PropertyStartupClear
	PropertyHRNVIndex
	PropertyHRLoaded
	PropertyHRLoadedAvail
	PropertyHRActive
	PropertyHRActiveAvail
	PropertyHRTransientAvail
	PropertyHRPersistent
	PropertyHRPersistentAvail
	PropertyNVCounters
	PropertyNVCountersAvail
	PropertyAlgorithmSet
	PropertyLoadedCurves
	PropertyLockoutCounter
	PropertyMaxAuthFail
	PropertyLockoutInterval
	PropertyLockoutRecovery
	PropertyNVWriteRecovery
	PropertyAuditCounter0
	PropertyAuditCounter1

	PropertyVar Property = PropertyPermanent
)

const (
	PropertyPCRSave PropertyPCR = iota
	PropertyPCRExtendL0
	PropertyPCRResetL0
	PropertyPCRExtendL1
	PropertyPCRResetL1
	PropertyPCRExtendL2
	PropertyPCRResetL2
	PropertyPCRExtendL3
	PropertyPCRResetL3
	PropertyPCRExtendL4
	PropertyPCRResetL4
	PropertyPCRNoIncrement = iota + 6
	PropertyPCRDRTMReset
	PropertyPCRPolicy
	PropertyPCRAuth

	PropertyPCRFirst PropertyPCR = PropertyPCRSave
)

const (
	AttrAsymmetric AlgorithmAttributes = 1 << iota
	AttrSymmetric
	AttrHash
	AttrObject
	AttrSigning = 1 << (iota + 4)
	AttrEncrypting
	AttrMethod
)

const (
	AttrNV CommandAttributes = 1 << (iota + 22)
	AttrExtensive
	AttrFlushed
	AttrRHandle = 1 << (iota + 25)
	AttrV
)

const (
	ECCCurveNIST_P192 ECCCurve = iota + 1
	ECCCurveNIST_P224
	ECCCurveNIST_P256
	ECCCurveNIST_P384
	ECCCurveNIST_P521
	ECCCurveBN_P256 = iota + 10
	ECCCurveBN_P638
	ECCCurveSM2_P256 = iota + 24

	ECCCurveFirst ECCCurve = ECCCurveNIST_P192
)

const (
	SessionTypeHMAC SessionType = iota
	SessionTypePolicy
	SessionTypeTrial = iota + 1
)
