// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// This file contains types defined in section 8 (Attributes) in
// part 2 of the library spec.

// AlgorithmAttributes corresponds to the TPMA_ALGORITHM type and
// represents the attributes for an algorithm.
type AlgorithmAttributes uint32

const (
	AttrAsymmetric AlgorithmAttributes = 1 << 0
	AttrSymmetric  AlgorithmAttributes = 1 << 1
	AttrHash       AlgorithmAttributes = 1 << 2
	AttrObject     AlgorithmAttributes = 1 << 3
	AttrSigning    AlgorithmAttributes = 1 << 8
	AttrEncrypting AlgorithmAttributes = 1 << 9
	AttrMethod     AlgorithmAttributes = 1 << 10
)

// ObjectAttributes corresponds to the TPMA_OBJECT type, and represents
// the attributes for an object.
type ObjectAttributes uint32

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

// SessionAttributes corresponds to the TPMA_SESSION type, and represents
// the attributes for a session.
type SessionAttributes uint8

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
	AttrCommandEncrypt SessionAttributes = 1 << (iota + 2)

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

// Locality corresponds to the TPMA_LOCALITY type. The 5 LSBs are used
// to represent localities 1 to 4. Localities from 32 to 255 are represented
// by setting any of the 3 MSBs.
type Locality uint8

const (
	LocalityZero  Locality = 1 << 0 // TPM_LOC_ZERO
	LocalityOne   Locality = 1 << 1 // TPM_LOC_ONE
	LocalityTwo   Locality = 1 << 2 // TPM_LOC_TWO
	LocalityThree Locality = 1 << 3 // TPM_LOC_THREE
	LocalityFour  Locality = 1 << 4 // TPM_LOC_FOUR
)

// IsValid returns whether this value represents one or more valid
// localities. The zero value does not represent any valid localities.
func (l Locality) IsValid() bool {
	return l > 0
}

// IsExtended indicates whether this value represents an extended locality,
// which is a locality greater than or equal to 32. Note that the Locality
// type cannot represent localities between 5 and 31.
func (l Locality) IsExtended() bool {
	return 0xe0&l > 0
}

// IsMultiple indicates whether this value represents multiple localities.
// This is only possible for localities 0 to 4.
func (l Locality) IsMultiple() bool {
	if l.IsExtended() {
		return false
	}
	found := false
	for n := uint8(0); n < 5; n++ {
		if l&(1<<n) > 0 {
			if found {
				return true
			}
			found = true
		}
	}

	return false
}

// Values returns the localities represented by this value as a slice of
// integers.
func (l Locality) Values() []uint8 {
	if l.IsExtended() {
		return []uint8{uint8(l)}
	}

	var out []uint8
	for n := uint8(0); n < 5; n++ {
		if l&(1<<n) > 0 {
			out = append(out, n)
		}
	}
	return out
}

// Value returns the locality represented by this value as an integer. It
// will panic if it doesn't represent any valid locality ([IsValid] returns
// false), or if it represents multiple localities ([IsMultiple] returns
// true).
func (l Locality) Value() uint8 {
	vals := l.Values()
	if len(vals) != 1 {
		panic("unset or multiple localities are represented")
	}
	return vals[0]
}

// PermanentAttributes corresponds to the TPMA_PERMANENT type and is returned
// when querying the value of [PropertyPermanent].
type PermanentAttributes uint32

const (
	AttrOwnerAuthSet       PermanentAttributes = 1 << 0  // ownerAuthSet
	AttrEndorsementAuthSet PermanentAttributes = 1 << 1  // endorsementAuthSet
	AttrLockoutAuthSet     PermanentAttributes = 1 << 2  // lockoutAuthSet
	AttrDisableClear       PermanentAttributes = 1 << 8  // disableClear
	AttrInLockout          PermanentAttributes = 1 << 9  // inLockout
	AttrTPMGeneratedEPS    PermanentAttributes = 1 << 10 // tpmGeneratedEPS
)

// StatupClearAttributes corresponds to the TPMA_STARTUP_CLEAR type and
// is used to report details of properties that reset after a Startup(CLEAR).
// It is returned when querying the value of [PropertyStartupClear].
type StartupClearAttributes uint32

const (
	AttrPhEnable   StartupClearAttributes = 1 << 0  // phEnable
	AttrShEnable   StartupClearAttributes = 1 << 1  // shEnable
	AttrEhEnable   StartupClearAttributes = 1 << 2  // ehEnable
	AttrPhEnableNV StartupClearAttributes = 1 << 3  // phEnableNV
	AttrOrderly    StartupClearAttributes = 1 << 31 // orderly
)

// MemoryAttributes corresponds to the TPMA_MEMORY type and is used to
// report details about memory management. It is returned when querying
// the value of [PropertyMemory].
type MemoryAttributes uint32

const (
	AttrSharedRAM         MemoryAttributes = 1 << 0 // sharedRAM
	AttrSharedNV          MemoryAttributes = 1 << 1 // sharedNV
	AttrObjectCopiedToRAM MemoryAttributes = 1 << 2 // objectCopiedToRam
)

// CommandAttributes corresponds to the TPMA_CC type and represents the
// attributes of a command. It also encodes the command code to which these
// attributes belong, and the number of command handles for the command.
type CommandAttributes uint32

// CommandCode returns the command code that a set of attributes belongs to.
func (a CommandAttributes) CommandCode() CommandCode {
	return CommandCode(a & (AttrV | 0xffff))
}

// NumberOfCommandHandles returns the number of command handles for the
// command that a set of attributes belong to.
func (a CommandAttributes) NumberOfCommandHandles() int {
	return int((a & AttrCHandles) >> attrCHandlesShift)
}

const (
	attrCHandlesShift = 25

	AttrCommandIndex CommandAttributes = 0xffff                 // commandIndex
	AttrNV           CommandAttributes = 1 << 22                // nv
	AttrExtensive    CommandAttributes = 1 << 23                // extensive
	AttrFlushed      CommandAttributes = 1 << 24                // flushed
	AttrCHandles     CommandAttributes = 7 << attrCHandlesShift // cHandles
	AttrRHandle      CommandAttributes = 1 << 28                // rHandle
	AttrV            CommandAttributes = 1 << 29                // V
)

// ModeAttributes correspnds to TPMA_MODES and is returned when querying
// the value of PropertyModes.
type ModeAttributes uint32

const (
	ModeFIPS140_2           ModeAttributes = 1 << 0 // FIPS_140_2
	ModeFIPS140_3           ModeAttributes = 1 << 1 // FIPS_140_3
	ModeFIPS140_3_Indicator ModeAttributes = 3 << 2 // FIPS_140_3_INDICATOR
)

type FIPS140_3_Indicator uint8

const (
	FIPS140_3_NonSecurityService         FIPS140_3_Indicator = 0x00
	FIPS140_3_ApprovedSecurityService    FIPS140_3_Indicator = 0x01
	FIPS140_3_NonApprovedSecurityService FIPS140_3_Indicator = 0x10
)

func (a ModeAttributes) FIPS140_3_Indicator() FIPS140_3_Indicator {
	return FIPS140_3_Indicator((a & ModeFIPS140_3_Indicator) >> 2)
}
