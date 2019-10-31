// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"unsafe"

	"golang.org/x/xerrors"
)

// 5.3) Miscellaneous Types

// AlgorithmId corresponds to the TPM_ALG_ID type.
type AlgorithmId uint16

// 6) Constants

// TPMGenerated corresponds to the TPM_GENERATED type.
type TPMGenerated uint32

// ECCCurve corresponds to the TPM_ECC_CURVE type.
type ECCCurve uint16

// CommandCode corresponds to the TPM_CC type.
type CommandCode uint32

// ResponseCode corresponds to the TPM_RC type.
type ResponseCode uint32

// ArithmeticOp corresponds to the TPM_EO type.
type ArithmeticOp uint16

// StructTag corresponds to the TPM_ST type.
type StructTag uint16

// StartupType corresponds to the TPM_SU type.
type StartupType uint16

// SessionType corresponds to the TPM_SE type.
type SessionType uint8

// Capability corresponds to the TPM_CAP type.
type Capability uint32

// Property corresponds to the TPM_PT type.
type Property uint32

// PropertyPCR corresponds to the TPM_PT_PCR type.
type PropertyPCR uint32

// 7) Handles

// Handle corresponds to the TPM_HANDLE type, and is a numeric identifier that references a resource on the TPM.
type Handle uint32

// Type returns the type of the handle.
func (h Handle) Type() HandleType {
	return HandleType(h >> 24)
}

// HandleType corresponds to the TPM_HT type, and is used to identify the type of a Handle.
type HandleType uint8

// BaseHandle returns the first handle for the handle type.
func (h HandleType) BaseHandle() Handle {
	return Handle(h) << 24
}

// 8) Attributes

// AlgorithmAttributes corresponds to the TPMA_ALGORITHM type and represents the attributes for an algorithm.
type AlgorithmAttributes uint32

// ObjectAttributes corresponds to the TPMA_OBJECT type, and represents the attributes for an object.
type ObjectAttributes uint32

// Locality corresponds to the TPMA_LOCALITY type.
type Locality uint8

// PermanentAttributes corresponds to the TPMA_PERMANENT type and is returned when querying the value of PropertyPermanent
// with TPMContext.GetCapabilityTPMProperties.
type PermanentAttributes uint32

// StatupClearAttributes corresponds to the TPMA_STARTUP_CLEAR type and is returned when querying the value of PropertyStartupClear
// with TPMContext.GetCapabilityTPMProperties.
type StartupClearAttributes uint32

// CommandAttributes corresponds to the TPMA_CC type and represents the attributes of a command. It also encodes the command code to
// which these attributes belong, and the number of command handles for the command.
type CommandAttributes uint32

// CommandCode returns the command code that a set of attributes belongs to.
func (a CommandAttributes) CommandCode() CommandCode {
	return CommandCode(a & 0xffff)
}

// NumberOfCommandHandles returns the number of command handles for the command that a set of attributes belong to.
func (a CommandAttributes) NumberOfCommandHandles() int {
	return int((a & 0x0e000000) >> 25)
}

// 10) Structure Definitions

type Empty struct{}

// TaggedHash corresponds to the TPMT_HA type.
type TaggedHash struct {
	HashAlg AlgorithmId // Algorithm of the digest contained with Digest. Valid values are determined by the TPMI_ALG_HASH interface type
	Digest  []byte      // Digest data
}

// TaggedHash represents the TPMT_HA type in the TCG spec. In the spec, TPMT_HA.digest is a union type
// (TPMU_HA), which is a union of all of the different hash algorithms. Each member of that union is an
// array of raw bytes. As no length is encoded, we need a custom marshaller implementation that unmarshals the
// correct number of bytes depending on the hash algorithm

func (p *TaggedHash) Marshal(buf io.Writer) error {
	if err := binary.Write(buf, binary.BigEndian, p.HashAlg); err != nil {
		return xerrors.Errorf("cannot marshal digest algorithm: %w", err)
	}
	size, known := cryptGetDigestSize(p.HashAlg)
	if !known {
		return fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	if int(size) != len(p.Digest) {
		return fmt.Errorf("invalid digest size %d", len(p.Digest))
	}

	if _, err := buf.Write(p.Digest); err != nil {
		return xerrors.Errorf("cannot write digest: %w", err)
	}
	return nil
}

func (p *TaggedHash) Unmarshal(buf io.Reader) error {
	if err := binary.Read(buf, binary.BigEndian, &p.HashAlg); err != nil {
		return xerrors.Errorf("cannot unmarshal digest algorithm: %w", err)
	}
	size, known := cryptGetDigestSize(p.HashAlg)
	if !known {
		return fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	p.Digest = make(Digest, size)
	if _, err := io.ReadFull(buf, p.Digest); err != nil {
		return xerrors.Errorf("cannot read digest: %w", err)
	}
	return nil
}

// 10.4 Sized Buffers

// Digest corresponds to the TPM2B_DIGEST type.
type Digest []byte

// Data corresponds to the TPM2B_DATA type.
type Data []byte

// Nonce corresponds to the TPM2B_NONCE type.
type Nonce Digest

// Auth corresponds to the TPM2B_AUTH type.
type Auth Digest

// Operand corresponds to the TPM2B_OPERAND type.
type Operand Digest

// Event corresponds to the TPM2B_EVENT type.
type Event []byte

// MaxBuffer corresponds to the TPM2B_MAX_BUFFER type.
type MaxBuffer []byte

// MaxNVBuffer corresponds to the TPM2B_MAX_NV_BUFFER type.
type MaxNVBuffer []byte

// Timeout corresponds to the TPM2B_TIMEOUT type.
type Timeout []byte

// 10.5) Names

// Name corresponds to the TPM2B_NAME type.
type Name []byte

// 10.6) PCR Structures

// PCRSelectionData is a list of PCR indexes. It is marshalled to and from the TPMS_PCR_SELECT type, which is a bitmap of the PCR
// indexes contained within this list.
type PCRSelectionData []int

func (d *PCRSelectionData) Marshal(buf io.Writer) error {
	bytes := make([]byte, 3)

	for _, i := range *d {
		octet := i / 8
		for octet >= len(bytes) {
			bytes = append(bytes, byte(0))
		}
		bit := uint(i % 8)
		bytes[octet] |= 1 << bit
	}

	if err := binary.Write(buf, binary.BigEndian, uint8(len(bytes))); err != nil {
		return xerrors.Errorf("cannot write size of PCR selection bit mask: %w", err)
	}
	if _, err := buf.Write(bytes); err != nil {
		return xerrors.Errorf("cannot write PCR selection bit mask: %w", err)
	}
	return nil
}

func (d *PCRSelectionData) Unmarshal(buf io.Reader) error {
	var size uint8
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return xerrors.Errorf("cannot read size of PCR selection bit mask: %w", err)
	}

	bytes := make([]byte, size)

	if _, err := io.ReadFull(buf, bytes); err != nil {
		return xerrors.Errorf("cannot read PCR selection bit mask: %w", err)
	}

	*d = make(PCRSelectionData, 0)

	for i, octet := range bytes {
		for bit := uint(0); bit < 8; bit++ {
			if octet&(1<<bit) == 0 {
				continue
			}
			*d = append(*d, int((uint(i)*8)+bit))
		}
	}

	return nil
}

// PCRSelection corresponds to the TPMS_PCR_SELECTION type.
type PCRSelection struct {
	// Hash is the digest algorithm associated with the selection. Valid values are determined by the TPMI_ALG_HASH interface type.
	Hash AlgorithmId

	Select PCRSelectionData // The selected PCRs
}

// 10.7 Tickets

// TkCreation corresponds to the TPMT_TK_CREATION type. It is created by TPMContext.Create and TPMContext.CreatePrimary, and is used
// to cryptographically bind the CreationData to the created object.
type TkCreation struct {
	Tag       StructTag // Ticket structure tag (TagCreation)
	Hierarchy Handle    // The hierarchy of the object to which this ticket belongs.
	Digest    Digest    // HMAC computed using the proof value of Hierarchy
}

// TkVerified corresponds to the TPMT_TK_VERIFIED type. It is created by TPMContext.VerifySignature and provides evidence that the
// TPM has verified that a digest was signed by a specific key.
type TkVerified struct {
	Tag       StructTag // Ticket structure tag (TagVerified)
	Hierarchy Handle    // The hierarchy of the object to which this ticket belongs.
	Digest    Digest    // HMAC computed using the proof value of Hierarcht
}

// TkAuth corresponds to the TPMT_TK_AUTH type. It is created by TPMContext.PolicySigned and TPMContext.PolicySecret when the
// authorization has an expiration time.
type TkAuth struct {
	Tag       StructTag // Ticket structure tag (TagAuthSecret or TagAuthSigned)
	Hierarchy Handle    // The hierarchy of the object used to produce this ticket
	Digest    Digest    // HMAC computed using the proof value of Hierarchy
}

// TkHashcheck corresponds to the TPMT_TK_HASHCHECK type.
type TkHashcheck struct {
	Tag       StructTag // Ticket structure tag (TagHashcheck)
	Hierarchy Handle    // The hierarchy of the object used to produce this ticket
	Digest    Digest    // HMAC computed using the proof value of Hierarchy
}

// 10.8 Property Structures

// AlgorithmProperty corresponds to the TPMS_ALG_PROPERTY type. It is used to report the properties of an algorithm.
type AlgorithmProperty struct {
	Alg        AlgorithmId         // Algorithm identifier
	Properties AlgorithmAttributes // Attributes of the algorithm
}

// TaggedProperty corresponds to the TPMS_TAGGED_PROPERTY type. It is used to report the value of a property.
type TaggedProperty struct {
	Property Property // Property identifier
	Value    uint32   // Value of the property
}

// TaggedPCRSelect corresponds to the TPMS_TAGGED_PCR_SELECT type. It is used to report the PCR indexes associated with a property.
type TaggedPCRSelect struct {
	Tag    PropertyPCR      // Property identifier
	Select PCRSelectionData // PCRs associated with Tag
}

// TaggedPolicy corresponds to the TPMS_TAGGED_POLICY type. It is used to report the authorization policy for a permanent resource.
type TaggedPolicy struct {
	Handle     Handle     // Permanent handle
	PolicyHash TaggedHash // Policy algorithm and hash
}

// 10.9) Lists

// CommandCodeList is a slice of CommandCode values, and corresponds to the TPML_CC type.
type CommandCodeList []CommandCode

// CommandAttributesList is a slice of CommandAttribute values, and corresponds to the TPML_CCA type.
type CommandAttributesList []CommandAttributes

// AlgorithmList is a slice of AlgorithmId values, and corresponds to the TPML_ALG type.
type AlgorithmList []AlgorithmId

// HandleList is a slice of Handle values, and corresponds to the TPML_HANDLE type.
type HandleList []Handle

// DigestList is a slice of Digest values, and corresponds to the TPML_DIGEST type.
type DigestList []Digest

// TaggedHashList is a slice of TaggedHash values, and corresponds to the TPML_DIGEST_VALUES type.
type TaggedHashList []TaggedHash

// PCRSelectionList is a slice of PCRSelection values, and corresponds to the TPML_PCR_SELECTION type.
type PCRSelectionList []PCRSelection

// AlgorithmPropertyList is a slice of AlgorithmProperty values, and corresponds to the TPML_ALG_PROPERTY type.
type AlgorithmPropertyList []AlgorithmProperty

// TaggedTPMPropertyList is a slice of TaggedProperty values, and corresponds to the TPML_TAGGED_TPM_PROPERTY type.
type TaggedTPMPropertyList []TaggedProperty

// TaggedPCRPropertyList is a slice of TaggedPCRSelect values, and corresponds to the TPML_TAGGED_PCR_PROPERTY type.
type TaggedPCRPropertyList []TaggedPCRSelect

// ECCCurveList is a slice of ECCCurve values, and corresponds to the TPML_ECC_CURVE type.
type ECCCurveList []ECCCurve

// TaggedPolicyList is a slice of TaggedPolicy values, and corresponds to the TPML_TAGGED_POLICY type.
type TaggedPolicyList []TaggedPolicy

// 10.10) Capabilities Structures

// Capabilities is a fake union type that corresponds to the TPMU_CAPABILITIES type. The selector type is Capability. Valid types
// for Data for each selector value are:
//  - CapabilityAlgs: AlgorithmPropertyList
//  - CapabilityHandles: HandleList
//  - CapabilityCommands: CommandAttributesList
//  - CapabilityPPCommands: CommandCodeList
//  - CapabilityAuditCommands: CommandCodeList
//  - CapabilityPCRs: PCRSelectionList
//  - CapabilityTPMProperties: TaggedTPMPropertyList
//  - CapabilityPCRProperties: TaggedPCRPropertyList
//  - CapabilityECCCurves: ECCCurveList
//  - CapabilityAuthPolicies: TaggedPolicyList
type CapabilitiesU struct {
	Data interface{}
}

// Algorithms returns the underlying value as AlgorithmPropertyList. It panics if the underlying type is not AlgorithmPropertyList.
func (c CapabilitiesU) Algorithms() AlgorithmPropertyList {
	return c.Data.(AlgorithmPropertyList)
}

// Handles returns the underlying value as HandleList. It panics if the underlying type is not HandleList.
func (c CapabilitiesU) Handles() HandleList {
	return c.Data.(HandleList)
}

// Command returns the underlying value as CommandAttributesList. It panics if the underlying type is not CommandAttributesList.
func (c CapabilitiesU) Command() CommandAttributesList {
	return c.Data.(CommandAttributesList)
}

// PPCommands returns the underlying value as CommandCodeList. If panics if the underlying type is not CommandCodeList.
func (c CapabilitiesU) PPCommands() CommandCodeList {
	return c.Data.(CommandCodeList)
}

// AuditCommands returns the underlying value as CommandCodeList. It panics if the underlying type is not CommandCodeList.
func (c CapabilitiesU) AuditCommands() CommandCodeList {
	return c.Data.(CommandCodeList)
}

// AssignedPCR returns the underlying value as PCRSelectionList. It panics if the underlying type is not PCRSelectionList.
func (c CapabilitiesU) AssignedPCR() PCRSelectionList {
	return c.Data.(PCRSelectionList)
}

// TPMProperties returns the underlying value as TaggedTPMPropertyList. It panics if the underlying type is not TaggedTPMPropertyList.
func (c CapabilitiesU) TPMProperties() TaggedTPMPropertyList {
	return c.Data.(TaggedTPMPropertyList)
}

// PCRProperties returns the underlying value as TaggedPCRPropertyList. It panics if the underlying type is not TaggedPCRPropertyList.
func (c CapabilitiesU) PCRProperties() TaggedPCRPropertyList {
	return c.Data.(TaggedPCRPropertyList)
}

// ECCCurves returns the underlying value as ECCCurveList. It panics if the underlying type is not ECCCurveList.
func (c CapabilitiesU) ECCCurves() ECCCurveList {
	return c.Data.(ECCCurveList)
}

// AuthPolicies returns the underlying value as TaggedPolicyList. It panics if the underlying type is not TaggedPolicyList.
func (c CapabilitiesU) AuthPolicies() TaggedPolicyList {
	return c.Data.(TaggedPolicyList)
}

func (c CapabilitiesU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(Capability) {
	case CapabilityAlgs:
		return reflect.TypeOf(AlgorithmPropertyList(nil)), nil
	case CapabilityHandles:
		return reflect.TypeOf(HandleList(nil)), nil
	case CapabilityCommands:
		return reflect.TypeOf(CommandAttributesList(nil)), nil
	case CapabilityPPCommands:
		return reflect.TypeOf(CommandCodeList(nil)), nil
	case CapabilityAuditCommands:
		return reflect.TypeOf(CommandCodeList(nil)), nil
	case CapabilityPCRs:
		return reflect.TypeOf(PCRSelectionList(nil)), nil
	case CapabilityTPMProperties:
		return reflect.TypeOf(TaggedTPMPropertyList(nil)), nil
	case CapabilityPCRProperties:
		return reflect.TypeOf(TaggedPCRPropertyList(nil)), nil
	case CapabilityECCCurves:
		return reflect.TypeOf(ECCCurveList(nil)), nil
	case CapabilityAuthPolicies:
		return reflect.TypeOf(TaggedPolicyList(nil)), nil
	}
	return nil, invalidSelectorError{selector}
}

// CapabilityData corresponds to the TPMS_CAPABILITY_DATA type, and is returned by TPMContext.GetCapability.
type CapabilityData struct {
	Capability Capability    // Capability
	Data       CapabilitiesU `tpm2:"selector:Capability"` // Capability data
}

// 10.11 Clock/Counter Structures

// ClockInfo corresponds to the TPMS_CLOCK_INFO type.
type ClockInfo struct {
	Clock      uint64 // Time value in milliseconds that increments whilst the TPM is powered
	ResetCount uint32 // Number of TPM resets since the TPM was last cleared
	// RestartCount is the number of TPM restarts or resumes since the last TPM reset or the last time the TPM was cleared.
	RestartCount uint32
	// Safe indicates the the value reported by Clock is guaranteed to be unique for the current owner.
	Safe bool
}

// TimeInfo corresponds to the TPMS_TIME_INFO type.
type TimeInfo struct {
	Time      uint64    // Time value in milliseconds since the last TPM startup
	ClockInfo ClockInfo // Clock information
}

// 10.12 Attestation Structures

// TimeAttestInfo corresponds to the TPMS_TIME_ATTEST_INFO type, and is returned by TPMContext.GetTime.
type TimeAttestInfo struct {
	Time            TimeInfo // Time information
	FirmwareVersion uint64   // TPM vendor specific value indicating the version of the firmware
}

// CertifyInfo corresponds to the TPMS_CERTIFY_INFO type, and is returned by TPMContext.Certify.
type CertifyInfo struct {
	Name          Name // Name of the certified object
	QualifiedName Name // Qualified name of the certified object
}

// QuoteInfo corresponds to the TPMS_QUOTE_INFO type, and is returned by TPMContext.Quote.
type QuoteInfo struct {
	PCRSelect PCRSelectionList // PCRs included in PCRDigest
	PCRDigest Digest           // Digest of the selected PCRs, using the hash algorithm of the signing key
}

// CommandAuditInfo corresponds to the TPMS_COMMAND_AUDIT_INFO type, and is returned by TPMContext.GetCommandAuditDigest.
type CommandAuditInfo struct {
	AuditCounter  uint64      // Monotonic audit counter
	DigestAlg     AlgorithmId // Hash algorithm used for the command audit
	AuditDigest   Digest      // Current value of the audit digest
	CommandDigest Digest      // Digest of command codes being audited, using DigestAlg
}

// SessionAuditInfo corresponds to the TPMS_SESSION_AUDIT_INFO type, and is returned by TPMContext.GetSessionAuditDigest.
type SessionAuditInfo struct {
	// ExclusiveSession indicates the current exclusive status of the session. It is true if all of the commands recorded in
	// SessionDigest were executed without any intervening commands that did not use
	// the audit session.
	ExclusiveSession bool
	SessionDigest    Digest // Current value of the session audit digest
}

// CreationInfo corresponds to the TPMS_CREATION_INFO type, and is returned by TPMContext.CertifyCreation.
type CreationInfo struct {
	ObjectName   Name // Name of the object
	CreationHash Digest
}

// NVCertifyInfo corresponds to the TPMS_NV_CERTIFY_INFO type, and is returned by TPMContext.NVCertify.
type NVCertifyInfo struct {
	IndexName  Name        // Name of the NV index
	Offset     uint16      // Offset parameter of TPMContext.NVCertify
	NVContents MaxNVBuffer // Contents of the NV index
}

// AttestU is a fake union type that corresponds to the TPMU_ATTEST type. The selector type is StructTag. Valid types for Data for
// each selector value are:
//  - TagAttestNV: *NVCertifyInfo
//  - TagAttestCommandAudit: *CommandAuditInfo
//  - TagAttestSessionAudir: *SessionAuditInfo
//  - TagAttestCertify: *CertifyInfo
//  - TagAttestQuote: *QuoteInfo
//  - TagAttestTime: *TimeAttestInfo
//  - TagAttestCreation: *CreationInfo
type AttestU struct {
	Data interface{}
}

func (a AttestU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(StructTag) {
	case TagAttestNV:
		return reflect.TypeOf((*NVCertifyInfo)(nil)), nil
	case TagAttestCommandAudit:
		return reflect.TypeOf((*CommandAuditInfo)(nil)), nil
	case TagAttestSessionAudit:
		return reflect.TypeOf((*SessionAuditInfo)(nil)), nil
	case TagAttestCertify:
		return reflect.TypeOf((*CertifyInfo)(nil)), nil
	case TagAttestQuote:
		return reflect.TypeOf((*QuoteInfo)(nil)), nil
	case TagAttestTime:
		return reflect.TypeOf((*TimeAttestInfo)(nil)), nil
	case TagAttestCreation:
		return reflect.TypeOf((*CreationInfo)(nil)), nil
	}
	return nil, invalidSelectorError{selector}
}

// Certify returns the underlying value as *CertifyInfo. It panics if the underlying type is not *CertifyInfo.
func (a AttestU) Certify() *CertifyInfo {
	return a.Data.(*CertifyInfo)
}

// Creation returns the underlying value as *CreationInfo. It panics if the underlying type is not *CreationInfo.
func (a AttestU) Creation() *CreationInfo {
	return a.Data.(*CreationInfo)
}

// Quote returns the underlying value as *QuoteInfo. It panics if the underlying type is not *QuoteInfo.
func (a AttestU) Quote() *QuoteInfo {
	return a.Data.(*QuoteInfo)
}

// CommandAudit returns the underlying value as *CommandAuditInfo. It panics if the underlying type is not *CommandAuditInfo.
func (a AttestU) CommandAudit() *CommandAuditInfo {
	return a.Data.(*CommandAuditInfo)
}

// SessionAudit returns the underlying value as *SessionAuditInfo. It panics if the underlying type is not *SessionAuditInfo.
func (a AttestU) SessionAudit() *SessionAuditInfo {
	return a.Data.(*SessionAuditInfo)
}

// Time returns the underlying value as *TimeAttestInfo. It panics if the underlying type is not *TimeAttestInfo.
func (a AttestU) Time() *TimeAttestInfo {
	return a.Data.(*TimeAttestInfo)
}

// NV returns the underlying value as *NVCertifyInfo. It panics if the underlying type is not *NVCertifyInfo.
func (a AttestU) NV() *NVCertifyInfo {
	return a.Data.(*NVCertifyInfo)
}

// Attest corresponds to the TPMS_ATTEST type, and is returned by the attestation commands. The signature of the attestation is over
// this structure.
type Attest struct {
	Magic           TPMGenerated // Always TPMGeneratedValue
	Type            StructTag    // Type of the attestation structure
	QualifiedSigner Name         // Qualified name of the signing key
	ExtraData       Data         // External information provided by the caller
	ClockInfo       ClockInfo    // Clock information
	FirmwareVersion uint64       // TPM vendor specific value indicating the version of the firmware
	Attest          AttestU      `tpm2:"selector:Type"` // Type specific attestation data
}

// AttestRaw corresponds to the TPM2B_ATTEST type, and is returned by the attestation commands. The signature of the attestation is
// over this data.
type AttestRaw []byte

// ToStruct unmarshals the underlying buffer to the corresponding Attest structure.
func (a AttestRaw) ToStruct() (*Attest, error) {
	var out Attest
	if _, err := UnmarshalFromBytes(a, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// 11) Algorithm Parameters and Structures

// 11.1) Symmetric

// SymKeyBitsU is a fake union type that corresponds to the TPMU_SYM_KEY_BITS type and is used to specify symmetric encryption key
// sizes. The selector type is AlgorithmId. Valid types for Data for each selector value are:
//  - AlgorithmAES: uint16
//  - AlgorithmSM4: uint16
//  - AlgorithmCamellia: uint16
//  - AlgorithmXOR: AlgorithmId (valid values are determined by the TPMI_ALG_HASH interface type)
//  - AlgorithmNull: <nil>
type SymKeyBitsU struct {
	Data interface{}
}

func (b SymKeyBitsU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return reflect.TypeOf(uint16(0)), nil
	case AlgorithmXOR:
		return reflect.TypeOf(AlgorithmId(0)), nil
	case AlgorithmNull:
		return nil, nil
	}
	return nil, invalidSelectorError{selector}
}

// Sym returns the underlying value as uint16. It panics if the underlying type is not uint16.
func (b SymKeyBitsU) Sym() uint16 {
	return b.Data.(uint16)
}

// XOR returns the underlying value as AlgorithmId. It panics if the underlying type is not AlgorithmId.
func (b SymKeyBitsU) XOR() AlgorithmId {
	return b.Data.(AlgorithmId)
}

// SymModeU is a fake union type that corresponds to the TPMU_SYM_MODE type. The selector type is AlgorithmId. Valid types for Data
// for each selector value are:
//  - AlgorithmAES: AlgorithmId (valid values are determined by the TPMI_ALG_SYM_MODE interface type)
//  - AlgorithmSM4: AlgorithmId (valid values are determined by the TPMI_ALG_SYM_MODE interface type)
//  - AlgorithmCamellia: AlgorithmId (valid values are determined by the TPMI_ALG_SYM_MODE interface type)
//  - AlgorithmXOR: <nil>
//  - AlgorithmNull: <nil>
type SymModeU struct {
	Data interface{}
}

func (m SymModeU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return reflect.TypeOf(AlgorithmId(0)), nil
	case AlgorithmXOR:
		fallthrough
	case AlgorithmNull:
		return nil, nil
	}
	return nil, invalidSelectorError{selector}
}

// Sym returns the underlying value as AlgorithmId. It panics if the underlying type is not AlgorithmId.
func (m SymModeU) Sym() AlgorithmId {
	return m.Data.(AlgorithmId)
}

// SymDef corresponds to the TPMT_SYM_DEF type, and is used to select the algorithm used for parameter encryption.
type SymDef struct {
	Algorithm AlgorithmId // Symmetric algorithm. Valid values are determined by the TPMI_ALG_SYM interface type
	KeyBits   SymKeyBitsU `tpm2:"selector:Algorithm"` // Symmetric key size
	Mode      SymModeU    `tpm2:"selector:Algorithm"` // Symmetric mode
}

// SymDefObject corresponds to the TPMT_SYM_DEF_OBJECT type, and is used to define an object's symmetric algorithm.
type SymDefObject struct {
	Algorithm AlgorithmId // Symmetric algorithm. Valid values are determined by the TPMI_ALG_SYM_OBJECT interface type
	KeyBits   SymKeyBitsU `tpm2:"selector:Algorithm"` // Symmetric key size
	Mode      SymModeU    `tpm2:"selector:Algorithm"` // Symmetric mode
}

// SymKey corresponds to the TPM2B_SYM_KEY type.
type SymKey []byte

// SymCipherParams corresponds to the TPMS_SYMCIPHER_PARMS type, and contains the parameters for a symmetric object.
type SymCipherParams struct {
	Sym SymDefObject
}

// Label corresponds to the TPM2B_LABEL type.
type Label []byte

// SensitiveData corresponds to the TPM2B_SENSITIVE_DATA type.
type SensitiveData []byte

// SensitiveCreate corresponds to the TPMS_SENSITIVE_CREATE type and is used to define the values to be placed in the sensitive area
// of a created object.
type SensitiveCreate struct {
	UserAuth Auth          // Authorization value
	Data     SensitiveData // Secret data
}

type sensitiveCreateSized struct {
	Ptr *SensitiveCreate `tpm2:"sized"`
}

// SchemeHash corresponds to the TPMS_SCHEME_HASH type, and is used for schemes that only require a hash algorithm to complete their
// definition.
type SchemeHash struct {
	HashAlg AlgorithmId // Hash algorithm used to digest the message. Valid values are determined by the TPMI_ALG_HASH interface type
}

// SchemeECDAA corresponds to the TPMS_SCHEME_ECDAA type.
type SchemeECDAA struct {
	HashAlg AlgorithmId // Hash algorithm used to digest the message. Valid values are determined by the TPMI_ALG_HASH interface type
	Count   uint16
}

// SchemeXOR corresponds to the TPMS_SCHEME_XOR type, and is used to define the XOR encryption scheme.
type SchemeXOR struct {
	HashAlg AlgorithmId // Hash algorithm used to digest the message. Valid values are determined by the TPMI_ALG_HASH interface type
	KDF     AlgorithmId // Hash algorithm used for the KDF. Valid values are determined by the TPMI_ALG_KDF interface type
}

// SchemeHMAC corresponds to the TPMS_SCHEME_HMAC type.
type SchemeHMAC SchemeHash

// SchemeKeyedHashU is a fake union type that corresponds to the TPMU_SCHEME_KEYED_HASH type. The selector type is AlgorithmId. Valid
// types for Data for each selector value are:
//  - AlgorithmHMAC: *SchemeHMAC
//  - AlgorithmXOR: *SchemeXOR
//  - AlgorithmNull: <nil>
type SchemeKeyedHashU struct {
	Data interface{}
}

func (d SchemeKeyedHashU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmHMAC:
		return reflect.TypeOf((*SchemeHMAC)(nil)), nil
	case AlgorithmXOR:
		return reflect.TypeOf((*SchemeXOR)(nil)), nil
	case AlgorithmNull:
		return nil, nil
	}
	return nil, invalidSelectorError{selector}
}

// HMAC returns the underlying value as *SchemeHMAC. It panics if the underlying type is not *SchemeHMAC.
func (d SchemeKeyedHashU) HMAC() *SchemeHMAC {
	return d.Data.(*SchemeHMAC)
}

// XOR returns the underlying value as *SchemeXOR. It panics if the underlying type is not *SchemeXOR.
func (d SchemeKeyedHashU) XOR() *SchemeXOR {
	return d.Data.(*SchemeXOR)
}

// KeyedHashScheme corresponds to the TPMS_KEYEDHASH_SCHEME type.
type KeyedHashScheme struct {
	Scheme  AlgorithmId      // Scheme selector. Valid values are determined by the TPMI_ALG_KEYEDHASH_SCHEME interface type
	Details SchemeKeyedHashU `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2 Assymetric

// 11.2.1 Signing Schemes

type SigSchemeRSASSA SchemeHash
type SigSchemeRSAPSS SchemeHash
type SigSchemeECDSA SchemeHash
type SigSchemeECDAA SchemeECDAA
type SigSchemeSM2 SchemeHash
type SigSchemeECSCHNORR SchemeHash

// SigSchemeU is a fake union type that corresponds to the TPMU_SIG_SCHEME type. The selector type is AlgorithmId. Valid types for
// Data for each selector value are:
//  - AlgorithmRSASSA: *SigSchemeRSASSA
//  - AlgorithmRSAPSS: *SigSchemeRSAPSS
//  - AlgorithmECDSA: *SigSchemeECDSA
//  - AlgorithmECDAA: *SigSchemeECDAA
//  - AlgorithmSM2: *SigSchemeSM2
//  - AlgorithmECSCHNORR: *SigSchemeECSCHNORR
//  - AlgorithmHMAC: *SigSchemeHMAC
//  - AlgorithmNull: <nil>
type SigSchemeU struct {
	Data interface{}
}

func (s SigSchemeU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmRSASSA:
		return reflect.TypeOf((*SigSchemeRSASSA)(nil)), nil
	case AlgorithmRSAPSS:
		return reflect.TypeOf((*SigSchemeRSAPSS)(nil)), nil
	case AlgorithmECDSA:
		return reflect.TypeOf((*SigSchemeECDSA)(nil)), nil
	case AlgorithmECDAA:
		return reflect.TypeOf((*SigSchemeECDAA)(nil)), nil
	case AlgorithmSM2:
		return reflect.TypeOf((*SigSchemeSM2)(nil)), nil
	case AlgorithmECSCHNORR:
		return reflect.TypeOf((*SigSchemeECSCHNORR)(nil)), nil
	case AlgorithmHMAC:
		return reflect.TypeOf((*SchemeHMAC)(nil)), nil
	case AlgorithmNull:
		return nil, nil
	}
	return nil, invalidSelectorError{selector}
}

// RSASSA returns the underlying value as *SigSchemeRSASSA. It panics if the underlying type is not *SigSchemeRSASSA
func (s SigSchemeU) RSASSA() *SigSchemeRSASSA {
	return s.Data.(*SigSchemeRSASSA)
}

// RSAPSS returns the underlying value as *SigSchemeRSAPSS. It panics if the underlying type is not *SigSchemeRSAPSS
func (s SigSchemeU) RSAPSS() *SigSchemeRSAPSS {
	return s.Data.(*SigSchemeRSAPSS)
}

// ECDSA returns the underlying value as *SigSchemeECDSA. It panics if the underlying type is not *SigSchemeECDSA
func (s SigSchemeU) ECDSA() *SigSchemeECDSA {
	return s.Data.(*SigSchemeECDSA)
}

// ECDAA returns the underlying value as *SigSchemeECDAA. It panics if the underlying type is not *SigSchemeECDAA
func (s SigSchemeU) ECDAA() *SigSchemeECDAA {
	return s.Data.(*SigSchemeECDAA)
}

// SM2 returns the underlying value as *SigSchemeSM2. It panics if the underlying type is not *SigSchemeSM2
func (s SigSchemeU) SM2() *SigSchemeSM2 {
	return s.Data.(*SigSchemeSM2)
}

// ECSCHNORR returns the underlying value as *SigSchemeECSCHNORR. It panics if the underlying type is not *SigSchemeECSCHNORR
func (s SigSchemeU) ECSCHNORR() *SigSchemeECSCHNORR {
	return s.Data.(*SigSchemeECSCHNORR)
}

// HMAC returns the underlying value as *SchemeHMAC. It panics if the underlying type is not *SchemeHMAC
func (s SigSchemeU) HMAC() *SchemeHMAC {
	return s.Data.(*SchemeHMAC)
}

// Any returns the underlying value as *SchemeHash. It panics if the underlying type is not convertible to *SchemeHash.
func (s SigSchemeU) Any() *SchemeHash {
	return (*SchemeHash)(unsafe.Pointer(reflect.ValueOf(s.Data).Pointer()))
}

// SigScheme corresponds to the TPMT_SIG_SCHEME type.
type SigScheme struct {
	Scheme  AlgorithmId // Scheme selector. Valid values are determined by the TPMI_ALG_SIG_SCHEME interface type
	Details SigSchemeU  `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2.3 Key Derivation Schemes

type SchemeMGF1 SchemeHash
type SchemeKDF1_SP800_56A SchemeHash
type SchemeKDF2 SchemeHash
type SchemeKDF1_SP800_108 SchemeHash

// KDFSchemeU is a fake union type that corresponds to the TPMU_KDF_SCHEME type. The selector type is AlgorithmId. Valid types for
// Data for each selector value are:
//  - AlgorithmMGF1: *SchemeMGF1
//  - AlgorithmKDF1_SP800_56A: *SchemeKDF1_SP800_56A
//  - AlgorithmKDF2: *SchemeKF2
//  - AlgorithmKDF1_SP800_108: *SchemeKDF1_SP800_108
//  - AlgorithmNull: <nil>
type KDFSchemeU struct {
	Data interface{}
}

func (s KDFSchemeU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmMGF1:
		return reflect.TypeOf((*SchemeMGF1)(nil)), nil
	case AlgorithmKDF1_SP800_56A:
		return reflect.TypeOf((*SchemeKDF1_SP800_56A)(nil)), nil
	case AlgorithmKDF2:
		return reflect.TypeOf((*SchemeKDF2)(nil)), nil
	case AlgorithmKDF1_SP800_108:
		return reflect.TypeOf((*SchemeKDF1_SP800_108)(nil)), nil
	case AlgorithmNull:
		return nil, nil
	}
	return nil, invalidSelectorError{selector}
}

// MGF1 returns the underlying value as *SchemeMGF1. It panics if the underlying type is not *SchemeMGF1.
func (s KDFSchemeU) MGF1() *SchemeMGF1 {
	return s.Data.(*SchemeMGF1)
}

// KDF1_SP800_56A returns the underlying value as *SchemeKDF1_SP800_56A. It panics if the underlying type is not
// *SchemeKDF1_SP800_56A.
func (s KDFSchemeU) KDF1_SP800_56A() *SchemeKDF1_SP800_56A {
	return s.Data.(*SchemeKDF1_SP800_56A)
}

// KDF2 returns the underlying value as *SchemeKDF2. It panics if the underlying type is not *SchemeKDF2.
func (s KDFSchemeU) KDF2() *SchemeKDF2 {
	return s.Data.(*SchemeKDF2)
}

// KDF1_SP800_108 returns the underlying value as *SchemeKDF1_SP800_108. It panics if the underlying type is not
// *SchemeKDF1_SP800_108.
func (s KDFSchemeU) KDF1_SP800_108() *SchemeKDF1_SP800_108 {
	return s.Data.(*SchemeKDF1_SP800_108)
}

// KDFScheme corresponds to the TPMT_KDF_SCHEME type.
type KDFScheme struct {
	Scheme  AlgorithmId // Scheme selector. Valid values are determined by the TPMI_ALG_KDF interface type
	Details KDFSchemeU  `tpm2:"selector:Scheme"` // Scheme specific parameters.
}

type KeySchemeECDH SchemeHash
type KeySchemeECMQV SchemeHash
type EncSchemeRSAES Empty
type EncSchemeOAEP SchemeHash

// AsymSchemeU is a fake union type that corresponds to the TPMU_ASYM_SCHEME type. The selector type is AlgorithmId. Valid types for
// Data for each selector value are:
//  - AlgorithmRSASSA: *SigSchemeRSASSA
//  - AlgorithmRSAES: *EncSchemeRSAES
//  - AlgorithmRSAPSS: *SigSchemeRSAPSS
//  - AlgorithmOAEP: *EncSchemeOAEP
//  - AlgorithmECDSA: *SigSchemeECDSA
//  - AlgorithmECDH: *KeySchemeECDH
//  - AlgorithmECDAA: *SigSchemeECDAA
//  - AlgorithmSM2: *SigSchemeSM2
//  - AlgorithmECSCHNORR: *SigSchemeECSCHNORR
//  - AlgorithmECMQV: *KeySchemeECMQV
//  - AlgorithmNull: <nil>
type AsymSchemeU struct {
	Data interface{}
}

func (s AsymSchemeU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmRSASSA:
		return reflect.TypeOf((*SigSchemeRSASSA)(nil)), nil
	case AlgorithmRSAES:
		return reflect.TypeOf((*EncSchemeRSAES)(nil)), nil
	case AlgorithmRSAPSS:
		return reflect.TypeOf((*SigSchemeRSAPSS)(nil)), nil
	case AlgorithmOAEP:
		return reflect.TypeOf((*EncSchemeOAEP)(nil)), nil
	case AlgorithmECDSA:
		return reflect.TypeOf((*SigSchemeECDSA)(nil)), nil
	case AlgorithmECDH:
		return reflect.TypeOf((*KeySchemeECDH)(nil)), nil
	case AlgorithmECDAA:
		return reflect.TypeOf((*SigSchemeECDAA)(nil)), nil
	case AlgorithmSM2:
		return reflect.TypeOf((*SigSchemeSM2)(nil)), nil
	case AlgorithmECSCHNORR:
		return reflect.TypeOf((*SigSchemeECSCHNORR)(nil)), nil
	case AlgorithmECMQV:
		return reflect.TypeOf((*KeySchemeECMQV)(nil)), nil
	case AlgorithmNull:
		return nil, nil
	}
	return nil, invalidSelectorError{selector}
}

// ECDH returns the underlying value as *KeySchemeECDH. It panics if the underlying type is not *KeySchemeECDH.
func (s AsymSchemeU) ECDH() *KeySchemeECDH {
	return s.Data.(*KeySchemeECDH)
}

// ECMQV returns the underlying value as *KeySchemeECMQV. It panics if the underlying type is not *KeySchemeECMQV.
func (s AsymSchemeU) ECMQV() *KeySchemeECMQV {
	return s.Data.(*KeySchemeECMQV)
}

// RSASSA returns the underlying value as *SigSchemeRSASSA. It panics if the underlying type is not *SigSchemeRSASSA.
func (s AsymSchemeU) RSASSA() *SigSchemeRSASSA {
	return s.Data.(*SigSchemeRSASSA)
}

// RSAPSS returns the underlying value as *SigSchemeRSAPSS. It panics if the underlying type is not *SigSchemeRSAPSS.
func (s AsymSchemeU) RSAPSS() *SigSchemeRSAPSS {
	return s.Data.(*SigSchemeRSAPSS)
}

// ECDSA returns the underlying value as *SigSchemeECDSA. It panics if the underlying type is not *SigSchemeECDSA.
func (s AsymSchemeU) ECDSA() *SigSchemeECDSA {
	return s.Data.(*SigSchemeECDSA)
}

// ECDAA returns the underlying value as *SigSchemeECDAA. It panics if the underlying type is not *SigSchemeECDAA.
func (s AsymSchemeU) ECDAA() *SigSchemeECDAA {
	return s.Data.(*SigSchemeECDAA)
}

// SM2 returns the underlying value as *SigSchemeSM2. It panics if the underlying type is not *SigSchemeSM2.
func (s AsymSchemeU) SM2() *SigSchemeSM2 {
	return s.Data.(*SigSchemeSM2)
}

// ECSCHNORR returns the underlying value as *SigSchemeECSCHNORR. It panics if the underlying type is not *SigSchemeECSCHNORR.
func (s AsymSchemeU) ECSCHNORR() *SigSchemeECSCHNORR {
	return s.Data.(*SigSchemeECSCHNORR)
}

// RSAES returns the underlying value as *EncSchemeRSAES. It panics if the underlying type is not *EncSchemeRSAES.
func (s AsymSchemeU) RSAES() *EncSchemeRSAES {
	return s.Data.(*EncSchemeRSAES)
}

// OAEP returns the underlying value as *EncSchemeOAEP. It panics if the underlying type is not *EncSchemeOAEP.
func (s AsymSchemeU) OAEP() *EncSchemeOAEP {
	return s.Data.(*EncSchemeOAEP)
}

// Any returns the underlying value as *SchemeHash. It panics if the underlying type is not convertible to *SchemeHash.
func (s AsymSchemeU) Any() *SchemeHash {
	return (*SchemeHash)(unsafe.Pointer(reflect.ValueOf(s.Data).Pointer()))
}

// AsymScheme corresponds to the TPMT_ASYM_SCHEME type.
type AsymScheme struct {
	Scheme  AlgorithmId // Scheme selector. Valid values are determined by the TPMI_ALG_ASYM_SCHEME interface type
	Details AsymSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2.4 RSA

// RSAScheme corresponds to the TPMT_RSA_SCHEME type.
type RSAScheme struct {
	Scheme  AlgorithmId // Scheme selector. Valid values are determined by the TPMI_ALG_RSA_SCHEME interface type
	Details AsymSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters.
}

// PublicKeyRSA corresponds to the TPM2B_PUBLIC_KEY_RSA type.
type PublicKeyRSA []byte

// PrivateKeyRSA corresponds to the TPM2B_PRIVATE_KEY_RSA type.
type PrivateKeyRSA []byte

// 11.2.5 ECC

// ECCParameter corresponds to the TPM2B_ECC_PARAMETER type.
type ECCParameter []byte

// ECCPoint corresponds to the TPMS_ECC_POINT type, and contains the coordinates that define an ECC point.
type ECCPoint struct {
	X ECCParameter // X coordinate
	Y ECCParameter // Y coordinate
}

// ECCScheme corresponds to the TPMT_ECC_SCHEME type.
type ECCScheme struct {
	Scheme  AlgorithmId // Scheme selector. Valid values are determined by the TPMI_ALG_ECC_SCHEME interface type
	Details AsymSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters.
}

// 11.3 Signatures

// SignatureRSA corresponds to the TPMS_SIGNATURE_RSA type.
type SignatureRSA struct {
	Hash AlgorithmId  // Hash algorithm used to digest the message. Valid values are determined by the TPMI_ALG_HASH interface type
	Sig  PublicKeyRSA // Signature, which is the same size as the public key
}

// SignatureECC corresponds to the TPMS_SIGNATURE_ECC type.
type SignatureECC struct {
	// Hash is the digest algorithm used in the signature process. Valid values are determined by the TPMI_ALG_HASH interface type.
	Hash AlgorithmId

	SignatureR ECCParameter
	SignatureS ECCParameter
}

type SignatureRSASSA SignatureRSA
type SignatureRSAPSS SignatureRSA
type SignatureECDSA SignatureECC
type SignatureECDAA SignatureECC
type SignatureSM2 SignatureECC
type SignatureECSCHNORR SignatureECC

// SignatureU is a fake union type that corresponds to TPMU_SIGNATURE. The selector type is AlgorithmId. Valid types for Data for
// each selector value are:
//  - AlgorithmRSASSA: *SignatureRSASSA
//  - AlgorithmRSAPSS: *SignatureRSAPSS
//  - AlgorithmECDSA: *SignatureECDSA
//  - AlgorithmECDAA: *SignatureECDAA
//  - AlgorithmSM2: *SignatureSM2
//  - AlgorithmECSCHNORR: *SignatureECSCHNORR
//  - AlgorithmHMAC: *TaggedHash
//  - AlgorithmNull: <nil>
type SignatureU struct {
	Data interface{}
}

func (s SignatureU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmRSASSA:
		return reflect.TypeOf((*SignatureRSASSA)(nil)), nil
	case AlgorithmRSAPSS:
		return reflect.TypeOf((*SignatureRSAPSS)(nil)), nil
	case AlgorithmECDSA:
		return reflect.TypeOf((*SignatureECDSA)(nil)), nil
	case AlgorithmECDAA:
		return reflect.TypeOf((*SignatureECDAA)(nil)), nil
	case AlgorithmSM2:
		return reflect.TypeOf((*SignatureSM2)(nil)), nil
	case AlgorithmECSCHNORR:
		return reflect.TypeOf((*SignatureECSCHNORR)(nil)), nil
	case AlgorithmHMAC:
		return reflect.TypeOf((*TaggedHash)(nil)), nil
	case AlgorithmNull:
		return nil, nil
	}
	return nil, invalidSelectorError{selector}
}

// RSASSA returns the underlying value as *SignatureRSASSA. It panics if the underlying type is not *SignatureRSASSA.
func (s SignatureU) RSASSA() *SignatureRSASSA {
	return s.Data.(*SignatureRSASSA)
}

// RSAPSS returns the underlying value as *SignatureRSAPSS. It panics if the underlying type is not *SignatureRSAPSS.
func (s SignatureU) RSAPSS() *SignatureRSAPSS {
	return s.Data.(*SignatureRSAPSS)
}

// ECDSA returns the underlying value as *SignatureECDSA. It panics if the underlying type is not *SignatureECDSA.
func (s SignatureU) ECDSA() *SignatureECDSA {
	return s.Data.(*SignatureECDSA)
}

// ECDAA returns the underlying value as *SignatureECDAA. It panics if the underlying type is not *SignatureECDAA.
func (s SignatureU) ECDAA() *SignatureECDAA {
	return s.Data.(*SignatureECDAA)
}

// SM2 returns the underlying value as *SignatureSM2. It panics if the underlying type is not *SignatureSM2.
func (s SignatureU) SM2() *SignatureSM2 {
	return s.Data.(*SignatureSM2)
}

// ECSCHNORR returns the underlying value as *SignatureECSCHNORR. It panics if the underlying type is not *SignatureECSCHNORR.
func (s SignatureU) ECSCHNORR() *SignatureECSCHNORR {
	return s.Data.(*SignatureECSCHNORR)
}

// HMAC returns the underlying value as *TaggedHash. It panics if the underlying type is not *TaggedHash.
func (s SignatureU) HMAC() *TaggedHash {
	return s.Data.(*TaggedHash)
}

// Any returns the underlying value as *SchemeHash. It panics if the underlying type is not convertible to *SchemeHash.
func (s SignatureU) Any() *SchemeHash {
	return (*SchemeHash)(unsafe.Pointer(reflect.ValueOf(s.Data).Pointer()))
}

// Signature corresponds to the TPMT_SIGNATURE type. It is returned by the attestation commands, and is a parameter for
// TPMContext.VerifySignature and TPMContext.PolicySigned.
type Signature struct {
	SigAlg    AlgorithmId // Signature algorithm. Valid values are determined by the TPMI_ALG_SIG_SCHEME interface type
	Signature SignatureU  `tpm2:"selector:SigAlg"` // Actual signature
}

// 11.4) Key/Secret Exchange

// EncryptedSecret corresponds to the TPM2B_ENCRYPTED_SECRET type.
type EncryptedSecret []byte

// 12) Key/Object Complex

// 12.2) Public Area Structures

// PublicIDU is a fake union type that corresponds to the TPMU_PUBLIC_ID type. The selector type is AlgorithmId. Valid types for Data
// for each selector value are:
//  - AlgorithmRSA: PublicKeyRSA
//  - AlgorithmKeyedHash: Digest
//  - AlgorithmECC: *ECCPoint
//  - AlgorithmSymCipher: Digest
type PublicIDU struct {
	Data interface{}
}

func (p PublicIDU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmRSA:
		return reflect.TypeOf(PublicKeyRSA(nil)), nil
	case AlgorithmKeyedHash:
		return reflect.TypeOf(Digest(nil)), nil
	case AlgorithmECC:
		return reflect.TypeOf((*ECCPoint)(nil)), nil
	case AlgorithmSymCipher:
		return reflect.TypeOf(Digest(nil)), nil
	}
	return nil, invalidSelectorError{selector}
}

// KeyedHash returns the underlying value as Digest. It panics if the underlying type is not Digest.
func (p PublicIDU) KeyedHash() Digest {
	return p.Data.(Digest)
}

// Sym returns the underlying value as Digest. It panics if the underlying type is not Digest.
func (p PublicIDU) Sym() Digest {
	return p.Data.(Digest)
}

// RSA returns the underlying value as PublicKeyRSA. It panics if the underlying type is not PublicKeyRSA.
func (p PublicIDU) RSA() PublicKeyRSA {
	return p.Data.(PublicKeyRSA)
}

// ECC returns the underlying value as *ECCPoint. It panics if the underlying type is not *ECCPoint.
func (p PublicIDU) ECC() *ECCPoint {
	return p.Data.(*ECCPoint)
}

// KeyedHashParams corresponds to the TPMS_KEYEDHASH_PARMS type, and defines the public parameters for a keyedhash object.
type KeyedHashParams struct {
	Scheme KeyedHashScheme // Signing method for a keyed hash signing object
}

// AsymParams corresponds to the TPMS_ASYM_PARMS type, and defines the common public parameters for an asymmetric key.
type AsymParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For a key with the AttrSign attribute: a signing scheme.
	// For a key with the AttrDecrypt attribute: a key exchange protocol.
	// For a key with both AttrSign and AttrDecrypt attributes: AlgorithmNull.
	Scheme AsymScheme
}

// RSAParams corresponds to the TPMS_RSA_PARMS type, and defines the public parameters for an RSA key.
type RSAParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For an unrestricted signing key: AlgorithmRSAPSS, AlgorithmRSASSA or AlgorithmNull.
	// For a restricted signing key: AlgorithmRSAPSS or AlgorithmRSASSA.
	// For an unrestricted decrypt key: AlgorithmRSAES, AlgorithmOAEP or AlgorithmNull.
	// For a restricted decrypt key: AlgorithmNull.
	Scheme   RSAScheme
	KeyBits  uint16 // Number of bits in the public modulus
	Exponent uint32 // Public exponent. When the value is zero, the exponent is 65537
}

// ECCParams corresponds to the TPMS_ECC_PARMS type, and defines the public parameters for an ECC key.
type ECCParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For a key with the AttrSign attribute: a signing scheme.
	// For a key with the AttrDecrypt attribute: a key exchange protocol or AlgorithmNull.
	// For a storage key: AlgorithmNull.
	Scheme  ECCScheme
	CurveID ECCCurve  // ECC curve ID
	KDF     KDFScheme // Unused - always AlgorithmNull
}

// PublicParamsU is a fake union type that corresponds to the TPMU_PUBLIC_PARMS type. The selector type is AlgorithmId. Valid types
// for Data for each selector value are:
//  - AlgorithmRSA: *RSAParams
//  - AlgorithmKeyedHash: *KeyedHashParams
//  - AlgorithmECC: *ECCParams
//  - AlgorithmSymCipher: *SymCipherParams
type PublicParamsU struct {
	Data interface{}
}

func (p PublicParamsU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmRSA:
		return reflect.TypeOf((*RSAParams)(nil)), nil
	case AlgorithmKeyedHash:
		return reflect.TypeOf((*KeyedHashParams)(nil)), nil
	case AlgorithmECC:
		return reflect.TypeOf((*ECCParams)(nil)), nil
	case AlgorithmSymCipher:
		return reflect.TypeOf((*SymCipherParams)(nil)), nil
	}
	return nil, invalidSelectorError{selector}
}

// KeyedHashDetail returns the underlying value as *KeyedHashParams. It panics if the underlying type is not *KeyedHashParams.
func (p PublicParamsU) KeyedHashDetail() *KeyedHashParams {
	return p.Data.(*KeyedHashParams)
}

// SymDetail returns the underlying value as *SymCipherParams. It panics if the underlying type is not *SymCipherParams.
func (p PublicParamsU) SymDetail() *SymCipherParams {
	return p.Data.(*SymCipherParams)
}

// RSADetail returns the underlying value as *RSAParams. It panics if the underlying type is not *RSAParams.
func (p PublicParamsU) RSADetail() *RSAParams {
	return p.Data.(*RSAParams)
}

// ECCDetail returns the underlying value as *ECCParams. It panics if the underlying type is not *ECCParams.
func (p PublicParamsU) ECCDetail() *ECCParams {
	return p.Data.(*ECCParams)
}

// AsymDetail returns the underlying value as *AsymParams. It panics if the underlying type is not *RSAParams or *ECCParams.
func (p PublicParamsU) AsymDetail() *AsymParams {
	switch d := p.Data.(type) {
	case *RSAParams:
		return (*AsymParams)(unsafe.Pointer(d))
	case *ECCParams:
		return (*AsymParams)(unsafe.Pointer(d))
	default:
		panic(fmt.Sprintf("data type is %s, expected %s or %s", reflect.TypeOf(p.Data),
			reflect.TypeOf((*RSAParams)(nil)), reflect.TypeOf((*ECCParams)(nil))))
	}
}

// Public corresponds to the TPMT_PUBLIC type, and defines the public area for an object.
type Public struct {
	Type AlgorithmId // Type of this object. Valid values are determined by the TPMI_ALG_PUBLIC interface type

	// NameAlg is the algorithm used to compute the name of this object. Valid values are determined by the TPMI_ALG_HASH interface type.
	NameAlg    AlgorithmId
	Attrs      ObjectAttributes // Object attributes
	AuthPolicy Digest           // Authorization policy for this object
	Params     PublicParamsU    `tpm2:"selector:Type"` // Type specific parameters
	Unique     PublicIDU        `tpm2:"selector:Type"` // Type specific unique identifier
}

// Name computes the name of this object
func (p *Public) Name() (Name, error) {
	if !cryptIsKnownDigest(p.NameAlg) {
		return nil, fmt.Errorf("unsupported name algorithm: %v", p.NameAlg)
	}
	hasher := cryptConstructHash(p.NameAlg)
	if err := MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	name, err := MarshalToBytes(p.NameAlg, RawBytes(hasher.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal algorithm and digest to name: %v", err)
	}
	return name, nil
}

func (p *Public) copyTo(dest *Public) error {
	b, err := MarshalToBytes(p)
	if err != nil {
		return err
	}
	_, err = UnmarshalFromBytes(b, dest)
	if err != nil {
		return err
	}
	return nil
}

type publicSized struct {
	Ptr *Public `tpm2:"sized"`
}

// 12.3) Private Area Structures

// PrivateVendorSpecific corresponds to the TPM2B_PRIVATE_VENDOR_SPECIFIC type.
type PrivateVendorSpecific []byte

// SensitiveCompositeU is a fake union type that corresponds to the TPMU_SENSITIVE_COMPOSITE type. The selector type is AlgorithmId.
// Valid types for Data for each selector value are:
//  - AlgorithmRSA: PrivateKeyRSA
//  - AlgorithmECC: ECCParameter
//  - AlgorithmKeyedHash: SensitiveData
//  - AlgorithmSymCipher: SymKey
type SensitiveCompositeU struct {
	Data interface{}
}

func (s SensitiveCompositeU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmRSA:
		return reflect.TypeOf(PrivateKeyRSA(nil)), nil
	case AlgorithmECC:
		return reflect.TypeOf(ECCParameter(nil)), nil
	case AlgorithmKeyedHash:
		return reflect.TypeOf(SensitiveData(nil)), nil
	case AlgorithmSymCipher:
		return reflect.TypeOf(SymKey(nil)), nil
	}
	return nil, invalidSelectorError{selector}
}

// RSA returns the underlying value as PrivateKeyRSA. It panics if the underlying type is not PrivateKeyRSA.
func (s SensitiveCompositeU) RSA() PrivateKeyRSA {
	return s.Data.(PrivateKeyRSA)
}

// ECC returns the underlying value as ECCParameter. It panics if the underlying type is not ECCParameter.
func (s SensitiveCompositeU) ECC() ECCParameter {
	return s.Data.(ECCParameter)
}

// Bits returns the underlying value as SensitiveData. It panics if the underlying type is not SensitiveData.
func (s SensitiveCompositeU) Bits() SensitiveData {
	return s.Data.(SensitiveData)
}

// Sym returns the underlying value as SymKey. It panics if the underlying type is not SymKey.
func (s SensitiveCompositeU) Sym() SymKey {
	return s.Data.(SymKey)
}

// Any returns the underlying value as PrivateVendorSpecific. It panics if the underlying type is not convertible to
// PrivateVendorSpecific.
func (s SensitiveCompositeU) Any() PrivateVendorSpecific {
	return reflect.ValueOf(s.Data).Convert(reflect.TypeOf((PrivateVendorSpecific)(nil))).Interface().(PrivateVendorSpecific)
}

// Sensitive corresponds to the TPMT_SENSITIVE type.
type Sensitive struct {
	Type      AlgorithmId         // Same as the corresponding Type in the Public object
	AuthValue Auth                // Authorization value
	SeedValue Digest              // For a parent object, the seed value for protecting descendant objects
	Sensitive SensitiveCompositeU `tpm2:"selector:Type"` // Type specific private data
}

type sensitiveSized struct {
	Ptr *Sensitive `tpm2:"sized"`
}

// Private corresponds to the TPM2B_PRIVATE type.
type Private []byte

// 12.4) Identity Object

// IDObjectRaw corresponds to the TPM2B_ID_OBJECT type.
type IDObjectRaw []byte

// 13) Storage Structures

// NVType corresponds to the TPM_NT type.
type NVType uint32

// NVPinCounterParams corresponds to the TPMS_NV_PIN_COUNTER_PARAMETERS type.
type NVPinCounterParams struct {
	Count uint32
	Limit uint32
}

// NVAttributes corresponds to the TPMA_NV type, and represents the attributes of a NV index. When exchanged with the TPM, some bits
// are reserved to encode the type of the NV index (NVType).
type NVAttributes uint32

// Type returns the NVType from a composite NVAttributes value.
func (a NVAttributes) Type() NVType {
	return NVType((a & 0xf0) >> 4)
}

// MakeNVAttributes converts a NVAttributes value and NVType value in to a composite NVAttributes value suitable for marshalling to
// the TPM wire format.
func MakeNVAttributes(a NVAttributes, t NVType) NVAttributes {
	return a | NVAttributes(t<<4)
}

// NVPublic corresponds to the TPMS_NV_PUBLIC type, which describes a NV index.
type NVPublic struct {
	Index Handle // Handle of the NV index

	// NameAlg is the digest algorithm used to compute the name of the index. Valid values are determined by the TPMI_ALG_HASH interface
	// type.
	NameAlg    AlgorithmId
	Attrs      NVAttributes // Attributes of this index
	AuthPolicy Digest       // Authorization policy for this index
	Size       uint16       // Size of this index
}

// Name computes the name of this NV index
func (p *NVPublic) Name() (Name, error) {
	if !cryptIsKnownDigest(p.NameAlg) {
		return nil, fmt.Errorf("unsupported name algorithm: %v", p.NameAlg)
	}
	hasher := cryptConstructHash(p.NameAlg)
	if err := MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	name, err := MarshalToBytes(p.NameAlg, RawBytes(hasher.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal algorithm and digest to name: %v", err)
	}
	return name, nil
}

type nvPublicSized struct {
	Ptr *NVPublic `tpm2:"sized"`
}

// 14) Context Data

// ContextData corresponds to the TPM2B_CONTEXT_DATA type.
type ContextData []byte

// Context corresponds to the TPMS_CONTEXT type and is used in TPMContext.ContextLoad and TPMContext.ContextSave.
type Context struct {
	Sequence    uint64      // Sequence number of the context
	SavedHandle Handle      // Handle indicating if this is a session or object
	Hierarchy   Handle      // Hierarchy of the context
	Blob        ContextData // Encrypted context data and integrity HMAC
}

// 15) Creation Data

// CreationData corresponds to the TPMS_CREATION_DATA type, which provides information about the creation environment of an object.
type CreationData struct {
	PCRSelect PCRSelectionList // PCRs included in PCRDigest
	// Digest of the selected PCRs using the name algorithm of the object associated with this data.
	PCRDigest           Digest
	Locality            Locality    // Locality at which the object was created
	ParentNameAlg       AlgorithmId // Name algorithm of the parent
	ParentName          Name        // Name of the parent
	ParentQualifiedName Name        // Qualified name of the parent
	OutsideInfo         Data        // External information provided by the caller
}

type creationDataSized struct {
	Ptr *CreationData `tpm2:"sized"`
}
