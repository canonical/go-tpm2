// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"reflect"
	"sort"
	"unsafe"

	"github.com/canonical/go-tpm2/mu"

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

// GoCurve returns the equivalent elliptic.Curve for this ECC curve.
func (c ECCCurve) GoCurve() elliptic.Curve {
	return eccCurves[c]
}

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

// SessionAttributes corresponds to the TPMA_SESSION type, and represents the attributes for a session.
type SessionAttributes uint8

func (a SessionAttributes) canonicalize() SessionAttributes {
	if a&AttrAuditExclusive > 0 {
		a |= AttrAudit
	}
	if a&AttrAuditReset > 0 {
		a |= AttrAudit
	}
	return a
}

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
	return CommandCode(a & (AttrV | 0xffff))
}

// NumberOfCommandHandles returns the number of command handles for the command that a set of attributes belong to.
func (a CommandAttributes) NumberOfCommandHandles() int {
	return int((a & 0x0e000000) >> 25)
}

// 9) Interface types

// HashAlgorithmId corresponds to the TPMI_ALG_HASH type
type HashAlgorithmId AlgorithmId

// GetHash returns the equivalent crypto.Hash value for this algorithm if one
// exists.
func (a HashAlgorithmId) GetHash() crypto.Hash {
	switch a {
	case HashAlgorithmSHA1:
		return crypto.SHA1
	case HashAlgorithmSHA256:
		return crypto.SHA256
	case HashAlgorithmSHA384:
		return crypto.SHA384
	case HashAlgorithmSHA512:
		return crypto.SHA512
	case HashAlgorithmSHA3_256:
		return crypto.SHA3_256
	case HashAlgorithmSHA3_384:
		return crypto.SHA3_384
	case HashAlgorithmSHA3_512:
		return crypto.SHA3_512
	default:
		return 0
	}
}

// Supported determines if the TPM digest algorithm has an equivalent go crypto.Hash.
func (a HashAlgorithmId) Supported() bool {
	return a.GetHash() != crypto.Hash(0)
}

// Available determines if the TPM digest algorithm has an equivalent go crypto.Hash
// that is linked into the current binary.
func (a HashAlgorithmId) Available() bool {
	return a.GetHash().Available()
}

// NewHash constructs a new hash.Hash implementation for this algorithm. It will panic if
// HashAlgorithmId.Available returns false.
func (a HashAlgorithmId) NewHash() hash.Hash {
	return a.GetHash().New()
}

// Size returns the size of the algorithm. It will panic if HashAlgorithmId.Supported returns false.
func (a HashAlgorithmId) Size() int {
	return a.GetHash().Size()
}

// SymAlgorithmId corresponds to the TPMI_ALG_SYM type
type SymAlgorithmId AlgorithmId

// Available indicates whether the TPM symmetric cipher has a registered go implementation.
func (a SymAlgorithmId) Available() bool {
	_, ok := symmetricAlgs[a]
	return ok
}

// BlockSize indicates the block size of the symmetric cipher. This will panic if there
// is no registered go implementation of the cipher or the algorithm does not correspond
// to a symmetric cipher.
func (a SymAlgorithmId) BlockSize() int {
	c, ok := symmetricAlgs[a]
	if !ok {
		panic("unsupported cipher")
	}
	return c.blockSize
}

// NewCipher constructs a new symmetric cipher with the supplied key, if there is a go
// implementation registered.
func (a SymAlgorithmId) NewCipher(key []byte) (cipher.Block, error) {
	c, ok := symmetricAlgs[a]
	if !ok {
		return nil, errors.New("unavailable cipher")
	}
	return c.fn(key)
}

// SymObjectAlgorithmId corresponds to the TPMI_ALG_SYM_OBJECT type
type SymObjectAlgorithmId AlgorithmId

// Available indicates whether the TPM symmetric cipher has a registered go implementation.
func (a SymObjectAlgorithmId) Available() bool {
	return SymAlgorithmId(a).Available()
}

// BlockSize indicates the block size of the symmetric cipher. This will panic if there
// is no registered go implementation of the cipher or the algorithm does not correspond
// to a symmetric cipher.
func (a SymObjectAlgorithmId) BlockSize() int {
	return SymAlgorithmId(a).BlockSize()
}

// NewCipher constructs a new symmetric cipher with the supplied key, if there is a go
// implementation registered.
func (a SymObjectAlgorithmId) NewCipher(key []byte) (cipher.Block, error) {
	return SymAlgorithmId(a).NewCipher(key)
}

// SymModeId corresponds to the TPMI_ALG_SYM_MODE type
type SymModeId AlgorithmId

// KDFAlgorithmId corresppnds to the TPMI_ALG_KDF type
type KDFAlgorithmId AlgorithmId

// SigSchemeId corresponds to the TPMI_ALG_SIG_SCHEME type
type SigSchemeId AlgorithmId

// 10) Structure Definitions

type Empty struct{}

// TaggedHash corresponds to the TPMT_HA type.
type TaggedHash struct {
	HashAlg HashAlgorithmId // Algorithm of the digest contained with Digest
	Digest  []byte          // Digest data
}

// TaggedHash represents the TPMT_HA type in the TCG spec. In the spec, TPMT_HA.digest is a union type
// (TPMU_HA), which is a union of all of the different hash algorithms. Each member of that union is an
// array of raw bytes. As no length is encoded, we need a custom marshaller implementation that unmarshals the
// correct number of bytes depending on the hash algorithm

func (p TaggedHash) Marshal(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, p.HashAlg); err != nil {
		return xerrors.Errorf("cannot marshal digest algorithm: %w", err)
	}
	if !p.HashAlg.Supported() {
		return fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	if p.HashAlg.Size() != len(p.Digest) {
		return fmt.Errorf("invalid digest size %d", len(p.Digest))
	}

	if _, err := w.Write(p.Digest); err != nil {
		return xerrors.Errorf("cannot write digest: %w", err)
	}
	return nil
}

func (p *TaggedHash) Unmarshal(r mu.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &p.HashAlg); err != nil {
		return xerrors.Errorf("cannot unmarshal digest algorithm: %w", err)
	}
	if !p.HashAlg.Supported() {
		return fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	p.Digest = make(Digest, p.HashAlg.Size())
	if _, err := io.ReadFull(r, p.Digest); err != nil {
		return xerrors.Errorf("cannot read digest: %w", err)
	}
	return nil
}

// 10.4 Sized Buffers

// Digest corresponds to the TPM2B_DIGEST type. The largest size of this supported by the TPM can be determined by calling
// TPMContext.GetMaxDigest.
type Digest []byte

// Data corresponds to the TPM2B_DATA type. The largest size of this supported by the TPM can be determined by calling
// TPMContext.GetMaxData.
type Data []byte

// Nonce corresponds to the TPM2B_NONCE type.
type Nonce Digest

// Auth corresponds to the TPM2B_AUTH type.
type Auth Digest

// Operand corresponds to the TPM2B_OPERAND type.
type Operand Digest

// Event corresponds to the TPM2B_EVENT type. The largest size of this is indicated by EventMaxSize.
type Event []byte

// MaxBuffer corresponds to the TPM2B_MAX_BUFFER type. The largest size of this supported by the TPM can be determined by
// calling TPMContext.GetInputBuffer.
type MaxBuffer []byte

// MaxNVBuffer corresponds to the TPM2B_MAX_NV_BUFFER type. The largest size of this supported by the TPM can be determined by
// calling TPMContext.GetNVBufferMax.
type MaxNVBuffer []byte

// Timeout corresponds to the TPM2B_TIMEOUT type.
type Timeout []byte

// 10.5) Names

// Name corresponds to the TPM2B_NAME type.
type Name []byte

// IsHandle returns true if the name contains a handle.
func (n Name) IsHandle() bool {
	return len(n) == binary.Size(Handle(0))
}

// Handle returns the handle of the resource that this name corresponds to. If it does not contain a handle, it will panic.
func (n Name) Handle() Handle {
	if !n.IsHandle() {
		panic("name is not a handle")
	}
	return Handle(binary.BigEndian.Uint32(n))
}

// Algorithm returns the digest algorithm of the name, if it contains a digest. If the name does not contain a digest,
// HashAlgorithmNull will be returned.
func (n Name) Algorithm() HashAlgorithmId {
	if len(n) < binary.Size(HashAlgorithmId(0)) || n.IsHandle() {
		return HashAlgorithmNull
	}
	a := HashAlgorithmId(binary.BigEndian.Uint16(n))
	if !a.Supported() {
		return HashAlgorithmNull
	}
	if a.Size() != len(n)-binary.Size(HashAlgorithmId(0)) {
		return HashAlgorithmNull
	}
	return a
}

// Digest returns the name as a digest, without the algorithm identifier. If it doesn't contain a digest, it will panic.
func (n Name) Digest() Digest {
	if n.Algorithm() == HashAlgorithmNull {
		panic("name is not a valid digest")
	}
	return Digest(n[binary.Size(HashAlgorithmId(0)):])
}

// 10.6) PCR Structures

// PCRSelect is a slice of PCR indexes. It is marshalled to and from the TPMS_PCR_SELECT type, which is a bitmap of the PCR indices
// contained within this slice.
type PCRSelect []int

func (d PCRSelect) Marshal(w io.Writer) error {
	bytes := make([]byte, 3)

	for _, i := range d {
		octet := i / 8
		for octet >= len(bytes) {
			bytes = append(bytes, byte(0))
		}
		bit := uint(i % 8)
		bytes[octet] |= 1 << bit
	}

	if err := binary.Write(w, binary.BigEndian, uint8(len(bytes))); err != nil {
		return xerrors.Errorf("cannot write size of PCR selection bit mask: %w", err)
	}

	if _, err := w.Write(bytes); err != nil {
		return xerrors.Errorf("cannot write PCR selection bit mask: %w", err)
	}
	return nil
}

func (d *PCRSelect) Unmarshal(r mu.Reader) error {
	var size uint8
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return xerrors.Errorf("cannot read size of PCR selection bit mask: %w", err)
	}
	if int(size) > r.Len() {
		return errors.New("size field is larger than the remaining bytes")
	}

	bytes := make([]byte, size)

	if _, err := io.ReadFull(r, bytes); err != nil {
		return xerrors.Errorf("cannot read PCR selection bit mask: %w", err)
	}

	*d = make(PCRSelect, 0)

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
	Hash   HashAlgorithmId // Hash is the digest algorithm associated with the selection
	Select PCRSelect       // The selected PCRs
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
	Tag    PropertyPCR // Property identifier
	Select PCRSelect   // PCRs associated with Tag
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

func (l PCRSelectionList) copy() (out PCRSelectionList) {
	b, _ := mu.MarshalToBytes(l)
	mu.UnmarshalFromBytes(b, &out)
	return
}

// Equal indicates whether l and r contain the same PCR selections. Equal selections will marshal to the same bytes in the TPM
// wire format. To be considered equal, each set of selections must be identical length, contain the same PCR banks in the same
// order, and each PCR bank must contain the same set of PCRs - the order of the PCRs listed in each bank are not important because
// that ordering is not preserved on the wire and PCRs are selected in ascending numerical order.
func (l PCRSelectionList) Equal(r PCRSelectionList) bool {
	lb, err := mu.MarshalToBytes(l)
	if err != nil {
		panic(err)
	}
	rb, err := mu.MarshalToBytes(r)
	if err != nil {
		panic(err)
	}
	return bytes.Equal(lb, rb)
}

// Sort will sort the list of PCR selections in order of ascending algorithm ID. A new list of selections is returned.
func (l PCRSelectionList) Sort() (out PCRSelectionList) {
	out = l.copy()
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return
}

// Merge will merge the PCR selections specified by l and r together and return a new set of PCR selections which contains a
// combination of both. For each PCR found in r that isn't found in l, it will be added to the first occurence of the corresponding
// PCR bank found in l if that exists, or otherwise a selection for that PCR bank will be appended to the result.
func (l PCRSelectionList) Merge(r PCRSelectionList) (out PCRSelectionList) {
	out = l.copy()
	r = r.copy()

	for _, sr := range r {
		for _, pr := range sr.Select {
			found := false
			for _, so := range out {
				if so.Hash != sr.Hash {
					continue
				}
				for _, po := range so.Select {
					if po == pr {
						found = true
					}
					if po >= pr {
						break
					}
				}
				if found {
					break
				}
			}

			if !found {
				added := false
				for i, so := range out {
					if so.Hash != sr.Hash {
						continue
					}
					out[i].Select = append(so.Select, pr)
					added = true
					break
				}
				if !added {
					out = append(out, PCRSelection{Hash: sr.Hash, Select: []int{pr}})
				}
			}
		}
	}
	return out.copy()
}

// Remove will remove the PCR selections in r from the PCR selections in l, and return a new set of selections.
func (l PCRSelectionList) Remove(r PCRSelectionList) (out PCRSelectionList) {
	out = l.copy()
	r = r.copy()

	for _, sr := range r {
		for _, pr := range sr.Select {
			for i, so := range out {
				if so.Hash != sr.Hash {
					continue
				}
				for j, po := range so.Select {
					if po == pr {
						if j < len(so.Select)-1 {
							copy(out[i].Select[j:], so.Select[j+1:])
						}
						out[i].Select = so.Select[:len(so.Select)-1]
					}
					if po >= pr {
						break
					}
				}
			}
		}
	}

	for i, so := range out {
		if len(so.Select) > 0 {
			continue
		}
		if i < len(out)-1 {
			copy(out[i:], out[i+1:])
		}
		out = out[:len(out)-1]
	}
	return
}

// IsEmpty returns true if the list of PCR selections selects no PCRs.
func (l PCRSelectionList) IsEmpty() bool {
	for _, s := range l {
		if len(s.Select) > 0 {
			return false
		}
	}
	return true
}

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

// Capabilities is a union type that corresponds to the TPMU_CAPABILITIES type. The selector type is Capability.
// Mapping of selector values to fields is as follows:
//  - CapabilityAlgs: Algorithms
//  - CapabilityHandles: Handles
//  - CapabilityCommands: Command
//  - CapabilityPPCommands: PPCommands
//  - CapabilityAuditCommands: AuditCommands
//  - CapabilityPCRs: AssignedPCR
//  - CapabilityTPMProperties: TPMProperties
//  - CapabilityPCRProperties: PCRProperties
//  - CapabilityECCCurves: ECCCurves
//  - CapabilityAuthPolicies: AuthPolicies
type CapabilitiesU struct {
	Algorithms    AlgorithmPropertyList
	Handles       HandleList
	Command       CommandAttributesList
	PPCommands    CommandCodeList
	AuditCommands CommandCodeList
	AssignedPCR   PCRSelectionList
	TPMProperties TaggedTPMPropertyList
	PCRProperties TaggedPCRPropertyList
	ECCCurves     ECCCurveList
	AuthPolicies  TaggedPolicyList
}

func (c *CapabilitiesU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(Capability) {
	case CapabilityAlgs:
		return &c.Algorithms
	case CapabilityHandles:
		return &c.Handles
	case CapabilityCommands:
		return &c.Command
	case CapabilityPPCommands:
		return &c.PPCommands
	case CapabilityAuditCommands:
		return &c.AuditCommands
	case CapabilityPCRs:
		return &c.AssignedPCR
	case CapabilityTPMProperties:
		return &c.TPMProperties
	case CapabilityPCRProperties:
		return &c.PCRProperties
	case CapabilityECCCurves:
		return &c.ECCCurves
	case CapabilityAuthPolicies:
		return &c.AuthPolicies
	default:
		return nil
	}
}

// CapabilityData corresponds to the TPMS_CAPABILITY_DATA type, and is returned by TPMContext.GetCapability.
type CapabilityData struct {
	Capability Capability     // Capability
	Data       *CapabilitiesU `tpm2:"selector:Capability"` // Capability data
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

// AttestU is a union type that corresponds to the TPMU_ATTEST type. The selector type is StructTag.
// Mapping of selector values to fields is as follows:
//  - TagAttestNV: NV
//  - TagAttestCommandAudit: CommandAudit
//  - TagAttestSessionAudit: SessionAudit
//  - TagAttestCertify: Certify
//  - TagAttestQuote: Quote
//  - TagAttestTime: Time
//  - TagAttestCreation: Creation
type AttestU struct {
	Certify      *CertifyInfo
	Creation     *CreationInfo
	Quote        *QuoteInfo
	CommandAudit *CommandAuditInfo
	SessionAudit *SessionAuditInfo
	Time         *TimeAttestInfo
	NV           *NVCertifyInfo
}

func (a *AttestU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(StructTag) {
	case TagAttestNV:
		return &a.NV
	case TagAttestCommandAudit:
		return &a.CommandAudit
	case TagAttestSessionAudit:
		return &a.SessionAudit
	case TagAttestCertify:
		return &a.Certify
	case TagAttestQuote:
		return &a.Quote
	case TagAttestTime:
		return &a.Time
	case TagAttestCreation:
		return &a.Creation
	default:
		return nil
	}
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
	Attested        *AttestU     `tpm2:"selector:Type"` // Type specific attestation data
}

type attestSized struct {
	Ptr *Attest `tpm2:"sized"`
}

// 10.13) Authorization Structures

// AuthCommand corresppnds to the TPMS_AUTH_COMMAND type, and represents an authorization
// for a command.
type AuthCommand struct {
	SessionHandle     Handle
	Nonce             Nonce
	SessionAttributes SessionAttributes
	HMAC              Auth
}

// AuthResponse corresponds to the TPMS_AUTH_RESPONSE type, and represents an authorization
// response for a command.
type AuthResponse struct {
	Nonce             Nonce
	SessionAttributes SessionAttributes
	HMAC              Auth
}

// 11) Algorithm Parameters and Structures

// 11.1) Symmetric

// SymKeyBitsU is a union type that corresponds to the TPMU_SYM_KEY_BITS type and is used to specify symmetric encryption key
// sizes. The selector type is AlgorithmId. Mapping of selector values to fields is as follows:
//  - AlgorithmAES: Sym
//  - AlgorithmSM4: Sym
//  - AlgorithmCamellia: Sym
//  - AlgorithmXOR: XOR
//  - AlgorithmNull: none
type SymKeyBitsU struct {
	Sym uint16
	XOR HashAlgorithmId
}

func (b *SymKeyBitsU) Select(selector reflect.Value) interface{} {
	switch selector.Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return &b.Sym
	case AlgorithmXOR:
		return &b.XOR
	case AlgorithmNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// SymModeU is a union type that corresponds to the TPMU_SYM_MODE type. The selector type is AlgorithmId.
// The mapping of selector values to fields is as follows:
//  - AlgorithmAES: Sym
//  - AlgorithmSM4: Sym
//  - AlgorithmCamellia: Sym
//  - AlgorithmXOR: none
//  - AlgorithmNull: none
type SymModeU struct {
	Sym SymModeId
}

func (m *SymModeU) Select(selector reflect.Value) interface{} {
	switch selector.Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return &m.Sym
	case AlgorithmXOR:
		fallthrough
	case AlgorithmNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// SymDef corresponds to the TPMT_SYM_DEF type, and is used to select the algorithm used for parameter encryption.
type SymDef struct {
	Algorithm SymAlgorithmId // Symmetric algorithm
	KeyBits   *SymKeyBitsU   `tpm2:"selector:Algorithm"` // Symmetric key size
	Mode      *SymModeU      `tpm2:"selector:Algorithm"` // Symmetric mode
}

// SymDefObject corresponds to the TPMT_SYM_DEF_OBJECT type, and is used to define an object's symmetric algorithm.
type SymDefObject struct {
	Algorithm SymObjectAlgorithmId // Symmetric algorithm
	KeyBits   *SymKeyBitsU         `tpm2:"selector:Algorithm"` // Symmetric key size
	Mode      *SymModeU            `tpm2:"selector:Algorithm"` // Symmetric mode
}

// SymKey corresponds to the TPM2B_SYM_KEY type.
type SymKey []byte

// SymCipherParams corresponds to the TPMS_SYMCIPHER_PARMS type, and contains the parameters for a symmetric object.
type SymCipherParams struct {
	Sym SymDefObject
}

// Label corresponds to the TPM2B_LABEL type.
type Label []byte

// Derive corresponds to the TPMS_DERIVE type.
type Derive struct {
	Label   Label
	Context Label
}

// SensitiveCreate corresponds to the TPMS_SENSITIVE_CREATE type and is used to define the values to be placed in the sensitive area
// of a created object.
type SensitiveCreate struct {
	UserAuth Auth          // Authorization value
	Data     SensitiveData // Secret data
}

type sensitiveCreateSized struct {
	Ptr *SensitiveCreate `tpm2:"sized"`
}

// SensitiveData corresponds to the TPM2B_SENSITIVE_DATA type.
type SensitiveData []byte

// SchemeHash corresponds to the TPMS_SCHEME_HASH type, and is used for schemes that only require a hash algorithm to complete their
// definition.
type SchemeHash struct {
	HashAlg HashAlgorithmId // Hash algorithm used to digest the message
}

// SchemeECDAA corresponds to the TPMS_SCHEME_ECDAA type.
type SchemeECDAA struct {
	HashAlg HashAlgorithmId // Hash algorithm used to digest the message
	Count   uint16
}

// KeyedHashSchemeId corresponds to the TPMI_ALG_KEYEDHASH_SCHEME type
type KeyedHashSchemeId AlgorithmId

// SchemeHMAC corresponds to the TPMS_SCHEME_HMAC type.
type SchemeHMAC SchemeHash

// SchemeXOR corresponds to the TPMS_SCHEME_XOR type, and is used to define the XOR encryption scheme.
type SchemeXOR struct {
	HashAlg HashAlgorithmId // Hash algorithm used to digest the message
	KDF     KDFAlgorithmId  // Hash algorithm used for the KDF
}

// SchemeKeyedHashU is a union type that corresponds to the TPMU_SCHEME_KEYED_HASH type. The selector type is KeyedHashSchemeId.
// The mapping of selector values to fields is as follows:
//  - KeyedHashSchemeHMAC: HMAC
//  - KeyedHashSchemeXOR: XOR
//  - KeyedHashSchemeNull: none
type SchemeKeyedHashU struct {
	HMAC *SchemeHMAC
	XOR  *SchemeXOR
}

func (d *SchemeKeyedHashU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(KeyedHashSchemeId) {
	case KeyedHashSchemeHMAC:
		return &d.HMAC
	case KeyedHashSchemeXOR:
		return &d.XOR
	case KeyedHashSchemeNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// KeyedHashScheme corresponds to the TPMT_KEYEDHASH_SCHEME type.
type KeyedHashScheme struct {
	Scheme  KeyedHashSchemeId // Scheme selector
	Details *SchemeKeyedHashU `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2 Assymetric

// 11.2.1 Signing Schemes

type SigSchemeRSASSA SchemeHash
type SigSchemeRSAPSS SchemeHash
type SigSchemeECDSA SchemeHash
type SigSchemeECDAA SchemeECDAA
type SigSchemeSM2 SchemeHash
type SigSchemeECSCHNORR SchemeHash

// SigSchemeU is a union type that corresponds to the TPMU_SIG_SCHEME type. The selector type is SigSchemeId.
// The mapping of selector value to fields is as follows:
//  - SigSchemeAlgRSASSA: RSASSA
//  - SigSchemeAlgRSAPSS: RSAPSS
//  - SigSchemeAlgECDSA: ECDSA
//  - SigSchemeAlgECDAA: ECDAA
//  - SigSchemeAlgSM2: SM2
//  - SigSchemeAlgECSCHNORR: ECSCHNORR
//  - SigSchemeAlgHMAC: HMAC
//  - SigSchemeAlgNull: none
type SigSchemeU struct {
	RSASSA    *SigSchemeRSASSA
	RSAPSS    *SigSchemeRSAPSS
	ECDSA     *SigSchemeECDSA
	ECDAA     *SigSchemeECDAA
	SM2       *SigSchemeSM2
	ECSCHNORR *SigSchemeECSCHNORR
	HMAC      *SchemeHMAC
}

func (s *SigSchemeU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return &s.RSASSA
	case SigSchemeAlgRSAPSS:
		return &s.RSAPSS
	case SigSchemeAlgECDSA:
		return &s.ECDSA
	case SigSchemeAlgECDAA:
		return &s.ECDAA
	case SigSchemeAlgSM2:
		return &s.SM2
	case SigSchemeAlgECSCHNORR:
		return &s.ECSCHNORR
	case SigSchemeAlgHMAC:
		return &s.HMAC
	case SigSchemeAlgNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// Any returns the underlying value as *SchemeHash. Note that if more than one field is set, it will return the
// first set field as *SchemeHash.
func (s SigSchemeU) Any() *SchemeHash {
	switch {
	case s.RSASSA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.RSASSA))
	case s.RSAPSS != nil:
		return (*SchemeHash)(unsafe.Pointer(s.RSAPSS))
	case s.ECDSA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECDSA))
	case s.ECDAA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECDAA))
	case s.SM2 != nil:
		return (*SchemeHash)(unsafe.Pointer(s.SM2))
	case s.ECSCHNORR != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECSCHNORR))
	case s.HMAC != nil:
		return (*SchemeHash)(unsafe.Pointer(s.HMAC))
	default:
		return nil
	}
}

// SigScheme corresponds to the TPMT_SIG_SCHEME type.
type SigScheme struct {
	Scheme  SigSchemeId // Scheme selector
	Details *SigSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2.3 Key Derivation Schemes

type SchemeMGF1 SchemeHash
type SchemeKDF1_SP800_56A SchemeHash
type SchemeKDF2 SchemeHash
type SchemeKDF1_SP800_108 SchemeHash

// KDFSchemeU is a union type that corresponds to the TPMU_KDF_SCHEME type. The selector type is KDFAlgorithmId.
// The mapping of selector value to field is as follows:
//  - KDFAlgorithmMGF1: MGF1
//  - KDFAlgorithmKDF1_SP800_56A: KDF1_SP800_56A
//  - KDFAlgorithmKDF2: KDF2
//  - KDFAlgorithmKDF1_SP800_108: KDF1_SP800_108
//  - KDFAlgorithmNull: none
type KDFSchemeU struct {
	MGF1           *SchemeMGF1
	KDF1_SP800_56A *SchemeKDF1_SP800_56A
	KDF2           *SchemeKDF2
	KDF1_SP800_108 *SchemeKDF1_SP800_108
}

func (s *KDFSchemeU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(KDFAlgorithmId) {
	case KDFAlgorithmMGF1:
		return &s.MGF1
	case KDFAlgorithmKDF1_SP800_56A:
		return &s.KDF1_SP800_56A
	case KDFAlgorithmKDF2:
		return &s.KDF2
	case KDFAlgorithmKDF1_SP800_108:
		return &s.KDF1_SP800_108
	case KDFAlgorithmNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// KDFScheme corresponds to the TPMT_KDF_SCHEME type.
type KDFScheme struct {
	Scheme  KDFAlgorithmId // Scheme selector
	Details *KDFSchemeU    `tpm2:"selector:Scheme"` // Scheme specific parameters.
}

type KeySchemeECDH SchemeHash
type KeySchemeECMQV SchemeHash
type EncSchemeRSAES Empty
type EncSchemeOAEP SchemeHash

// AsymSchemeId corresponds to the TPMI_ALG_ASYM_SCHEME type
type AsymSchemeId AlgorithmId

// AsymSchemeU is a union type that corresponds to the TPMU_ASYM_SCHEME type. The selector type is AsymSchemeId.
// The mapping of selector values to fields is as follows:
//  - AsymSchemeRSASSA: RSASSA
//  - AsymSchemeRSAES: RSAES
//  - AsymSchemeRSAPSS: RSAPSS
//  - AsymSchemeOAEP: OAEP
//  - AsymSchemeECDSA: ECDSA
//  - AsymSchemeECDH: ECDH
//  - AsymSchemeECDAA: ECDAA
//  - AsymSchemeSM2: SM2
//  - AsymSchemeECSCHNORR: ECSCHNORR
//  - AsymSchemeECMQV: ECMQV
//  - AsymSchemeNull: none
type AsymSchemeU struct {
	RSASSA    *SigSchemeRSASSA
	RSAES     *EncSchemeRSAES
	RSAPSS    *SigSchemeRSAPSS
	OAEP      *EncSchemeOAEP
	ECDSA     *SigSchemeECDSA
	ECDH      *KeySchemeECDH
	ECDAA     *SigSchemeECDAA
	SM2       *SigSchemeSM2
	ECSCHNORR *SigSchemeECSCHNORR
	ECMQV     *KeySchemeECMQV
}

func (s *AsymSchemeU) Select(selector reflect.Value) interface{} {
	switch selector.Convert(reflect.TypeOf(AsymSchemeId(0))).Interface().(AsymSchemeId) {
	case AsymSchemeRSASSA:
		return &s.RSASSA
	case AsymSchemeRSAES:
		return &s.RSAES
	case AsymSchemeRSAPSS:
		return &s.RSAPSS
	case AsymSchemeOAEP:
		return &s.OAEP
	case AsymSchemeECDSA:
		return &s.ECDSA
	case AsymSchemeECDH:
		return &s.ECDH
	case AsymSchemeECDAA:
		return &s.ECDAA
	case AsymSchemeSM2:
		return &s.SM2
	case AsymSchemeECSCHNORR:
		return &s.ECSCHNORR
	case AsymSchemeECMQV:
		return &s.ECMQV
	case AsymSchemeNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// Any returns the underlying value as *SchemeHash. Note that if more than one field is set, it will return the
// first set field as *SchemeHash.
func (s AsymSchemeU) Any() *SchemeHash {
	switch {
	case s.RSASSA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.RSASSA))
	case s.RSAPSS != nil:
		return (*SchemeHash)(unsafe.Pointer(s.RSAPSS))
	case s.OAEP != nil:
		return (*SchemeHash)(unsafe.Pointer(s.OAEP))
	case s.ECDSA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECDSA))
	case s.ECDH != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECDH))
	case s.ECDAA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECDAA))
	case s.SM2 != nil:
		return (*SchemeHash)(unsafe.Pointer(s.SM2))
	case s.ECSCHNORR != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECSCHNORR))
	case s.ECMQV != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECMQV))
	default:
		return nil
	}
}

// AsymScheme corresponds to the TPMT_ASYM_SCHEME type.
type AsymScheme struct {
	Scheme  AsymSchemeId // Scheme selector
	Details *AsymSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2.4 RSA

// RSASchemeId corresponds to the TPMI_ALG_RSA_SCHEME type.
type RSASchemeId AsymSchemeId

// RSAScheme corresponds to the TPMT_RSA_SCHEME type.
type RSAScheme struct {
	Scheme  RSASchemeId  // Scheme selector
	Details *AsymSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters.
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

// ECCSchemeId corresponds to the TPMI_ALG_ECC_SCHEME type.
type ECCSchemeId AsymSchemeId

// ECCScheme corresponds to the TPMT_ECC_SCHEME type.
type ECCScheme struct {
	Scheme  ECCSchemeId  // Scheme selector
	Details *AsymSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters.
}

// 11.3 Signatures

// SignatureRSA corresponds to the TPMS_SIGNATURE_RSA type.
type SignatureRSA struct {
	Hash HashAlgorithmId // Hash algorithm used to digest the message
	Sig  PublicKeyRSA    // Signature, which is the same size as the public key
}

// SignatureECC corresponds to the TPMS_SIGNATURE_ECC type.
type SignatureECC struct {
	Hash       HashAlgorithmId // Hash is the digest algorithm used in the signature process
	SignatureR ECCParameter
	SignatureS ECCParameter
}

type SignatureRSASSA SignatureRSA
type SignatureRSAPSS SignatureRSA
type SignatureECDSA SignatureECC
type SignatureECDAA SignatureECC
type SignatureSM2 SignatureECC
type SignatureECSCHNORR SignatureECC

// SignatureU is a union type that corresponds to TPMU_SIGNATURE. The selector type is SigSchemeId.
// The mapping of selector values to fields is as follows:
//  - SigSchemeAlgRSASSA: RSASSA
//  - SigSchemeAlgRSAPSS: RSAPSS
//  - SigSchemeAlgECDSA: ECDSA
//  - SigSchemeAlgECDAA: ECDAA
//  - SigSchemeAlgSM2: SM2
//  - SigSchemeAlgECSCHNORR: ECSCHNORR
//  - SigSchemeAlgHMAC: HMAC
//  - SigSchemeAlgNull: none
type SignatureU struct {
	RSASSA    *SignatureRSASSA
	RSAPSS    *SignatureRSAPSS
	ECDSA     *SignatureECDSA
	ECDAA     *SignatureECDAA
	SM2       *SignatureSM2
	ECSCHNORR *SignatureECSCHNORR
	HMAC      *TaggedHash
}

func (s *SignatureU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return &s.RSASSA
	case SigSchemeAlgRSAPSS:
		return &s.RSAPSS
	case SigSchemeAlgECDSA:
		return &s.ECDSA
	case SigSchemeAlgECDAA:
		return &s.ECDAA
	case SigSchemeAlgSM2:
		return &s.SM2
	case SigSchemeAlgECSCHNORR:
		return &s.ECSCHNORR
	case SigSchemeAlgHMAC:
		return &s.HMAC
	case SigSchemeAlgNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// Any returns the underlying value as *SchemeHash. Note that if more than one field is set, it will return the
// first set field as *SchemeHash.
func (s SignatureU) Any() *SchemeHash {
	switch {
	case s.RSASSA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.RSASSA))
	case s.RSAPSS != nil:
		return (*SchemeHash)(unsafe.Pointer(s.RSAPSS))
	case s.ECDSA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECDSA))
	case s.ECDAA != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECDAA))
	case s.SM2 != nil:
		return (*SchemeHash)(unsafe.Pointer(s.SM2))
	case s.ECSCHNORR != nil:
		return (*SchemeHash)(unsafe.Pointer(s.ECSCHNORR))
	case s.HMAC != nil:
		return (*SchemeHash)(unsafe.Pointer(s.HMAC))
	default:
		return nil
	}
}

// Signature corresponds to the TPMT_SIGNATURE type. It is returned by the attestation commands, and is a parameter for
// TPMContext.VerifySignature and TPMContext.PolicySigned.
type Signature struct {
	SigAlg    SigSchemeId // Signature algorithm
	Signature *SignatureU `tpm2:"selector:SigAlg"` // Actual signature
}

// 11.4) Key/Secret Exchange

// EncryptedSecret corresponds to the TPM2B_ENCRYPTED_SECRET type.
type EncryptedSecret []byte

// 12) Key/Object Complex

// 12.2) Public Area Structures

// ObjectTypeId corresponds to the TPMI_ALG_PUBLIC type.
type ObjectTypeId AlgorithmId

// PublicIDU is a union type that corresponds to the TPMU_PUBLIC_ID type. The selector type is ObjectTypeId.
// The mapping of selector values to fields is as follows:
//  - ObjectTypeRSA: RSA
//  - ObjectTypeKeyedHash: KeyedHash
//  - ObjectTypeECC: ECC
//  - ObjectTypeSymCipher: Sym
type PublicIDU struct {
	KeyedHash Digest
	Sym       Digest
	RSA       PublicKeyRSA
	ECC       *ECCPoint
}

func (p *PublicIDU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return &p.RSA
	case ObjectTypeKeyedHash:
		return &p.KeyedHash
	case ObjectTypeECC:
		return &p.ECC
	case ObjectTypeSymCipher:
		return &p.Sym
	default:
		return nil
	}
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
	KDF     KDFScheme // Unused - always KDFAlgorithmNull
}

// PublicParamsU is a union type that corresponds to the TPMU_PUBLIC_PARMS type. The selector type is ObjectTypeId.
// The mapping of selector values to fields is as follows:
//  - ObjectTypeRSA: RSADetail
//  - ObjectTypeKeyedHash: KeyedHashDetail
//  - ObjectTypeECC: ECCDetail
//  - ObjectTypeSymCipher: SymDetail
type PublicParamsU struct {
	KeyedHashDetail *KeyedHashParams
	SymDetail       *SymCipherParams
	RSADetail       *RSAParams
	ECCDetail       *ECCParams
}

func (p *PublicParamsU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return &p.RSADetail
	case ObjectTypeKeyedHash:
		return &p.KeyedHashDetail
	case ObjectTypeECC:
		return &p.ECCDetail
	case ObjectTypeSymCipher:
		return &p.SymDetail
	default:
		return nil
	}
}

// AsymDetail returns the underlying value as *AsymParams. It panics if the underlying type is not *RSAParams or *ECCParams.
func (p PublicParamsU) AsymDetail() *AsymParams {
	switch {
	case p.RSADetail != nil:
		return (*AsymParams)(unsafe.Pointer(p.RSADetail))
	case p.ECCDetail != nil:
		return (*AsymParams)(unsafe.Pointer(p.ECCDetail))
	default:
		panic("invalid type")
	}
}

// PublicParams corresponds to the TPMT_PUBLIC_PARMS type.
type PublicParams struct {
	Type       ObjectTypeId   // Type specifier
	Parameters *PublicParamsU `tpm2:"selector:Type"` // Algorithm details
}

// Public corresponds to the TPMT_PUBLIC type, and defines the public area for an object.
type Public struct {
	Type       ObjectTypeId     // Type of this object
	NameAlg    HashAlgorithmId  // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes // Object attributes
	AuthPolicy Digest           // Authorization policy for this object
	Params     *PublicParamsU   `tpm2:"selector:Type"` // Type specific parameters
	Unique     *PublicIDU       `tpm2:"selector:Type"` // Type specific unique identifier
}

// Name computes the name of this object
func (p *Public) Name() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	hasher := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	name, err := mu.MarshalToBytes(p.NameAlg, mu.RawBytes(hasher.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal algorithm and digest to name: %v", err)
	}
	return name, nil
}

func (p *Public) copy() (*Public, error) {
	b, err := mu.MarshalToBytes(p)
	if err != nil {
		return nil, err
	}
	var out *Public
	_, err = mu.UnmarshalFromBytes(b, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Public) compareName(name Name) bool {
	n, err := p.Name()
	if err != nil {
		return false
	}
	return bytes.Equal(n, name)
}

func (p *Public) ToTemplate() (Template, error) {
	b, err := mu.MarshalToBytes(p)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal object: %v", err)
	}
	return b, nil
}

// IsStorage indicates that this public area is associated with an object that can
// be the target of a duplication operation.
func (p *Public) IsStorage() bool {
	switch p.Type {
	case ObjectTypeRSA, ObjectTypeECC:
		return p.Attrs&(AttrRestricted|AttrDecrypt|AttrSign) == AttrRestricted|AttrDecrypt
	default:
		return false
	}
}

// IsParent indicates that this public area is associated with an object that can be
// a storage parent.
func (p *Public) IsParent() bool {
	switch p.Type {
	case ObjectTypeKeyedHash:
		return false
	default:
		if p.NameAlg == HashAlgorithmNull {
			return false
		}
		return p.Attrs&(AttrRestricted|AttrDecrypt) == AttrRestricted|AttrDecrypt
	}
}

// Public returns a corresponding public key for the TPM public area.
// This will panic if the public area does not correspond to an asymmetric
// key.
func (p *Public) Public() crypto.PublicKey {
	switch p.Type {
	case ObjectTypeRSA:
		exp := int(p.Params.RSADetail.Exponent)
		if exp == 0 {
			exp = DefaultRSAExponent
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(p.Unique.RSA),
			E: exp}
	case ObjectTypeECC:
		return &ecdsa.PublicKey{
			Curve: p.Params.ECCDetail.CurveID.GoCurve(),
			X:     new(big.Int).SetBytes(p.Unique.ECC.X),
			Y:     new(big.Int).SetBytes(p.Unique.ECC.Y)}
	default:
		panic("object is not a public key")
	}
}

type publicSized struct {
	Ptr *Public `tpm2:"sized"`
}

// PublicDerived is similar to Public but can be used as a template to create a derived object with TPMContext.CreateLoaded
type PublicDerived struct {
	Type       ObjectTypeId     // Type of this object
	NameAlg    HashAlgorithmId  // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes // Object attributes
	AuthPolicy Digest           // Authorization policy for this object
	Params     *PublicParamsU   `tpm2:"selector:Type"` // Type specific parameters

	// Unique contains the derivation values. These take precedence over any values specified in SensitiveCreate.Data when creating a
	// derived object,
	Unique *Derive
}

// Name computes the name of this object
func (p *PublicDerived) Name() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	hasher := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	name, err := mu.MarshalToBytes(p.NameAlg, mu.RawBytes(hasher.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal algorithm and digest to name: %v", err)
	}
	return name, nil
}

func (p *PublicDerived) ToTemplate() (Template, error) {
	b, err := mu.MarshalToBytes(p)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal object: %v", err)
	}
	return b, nil
}

// Template corresponds to the TPM2B_TEMPLATE type
type Template []byte

// PublicTemplate exists to allow either Public or PublicDerived structures to be used as the template value for
// TPMContext.CreateLoaded.
type PublicTemplate interface {
	ToTemplate() (Template, error)
}

// 12.3) Private Area Structures

// PrivateVendorSpecific corresponds to the TPM2B_PRIVATE_VENDOR_SPECIFIC type.
type PrivateVendorSpecific []byte

// SensitiveCompositeU is a union type that corresponds to the TPMU_SENSITIVE_COMPOSITE type. The selector type is ObjectTypeId.
// The mapping of selector values to fields is as follows:
//  - ObjectTypeRSA: RSA
//  - ObjectTypeECC: ECC
//  - ObjectTypeKeyedHash: Bits
//  - ObjectTypeSymCipher: Sym
type SensitiveCompositeU struct {
	RSA  PrivateKeyRSA
	ECC  ECCParameter
	Bits SensitiveData
	Sym  SymKey
}

func (s *SensitiveCompositeU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return &s.RSA
	case ObjectTypeECC:
		return &s.ECC
	case ObjectTypeKeyedHash:
		return &s.Bits
	case ObjectTypeSymCipher:
		return &s.Sym
	default:
		return nil
	}
}

// Any returns the underlying value as PrivateVendorSpecific. Note that if more than one field is set, it will return
// the first set field as PrivateVendorSpecific.
func (s SensitiveCompositeU) Any() PrivateVendorSpecific {
	switch {
	case len(s.RSA) > 0:
		return PrivateVendorSpecific(s.RSA)
	case len(s.ECC) > 0:
		return PrivateVendorSpecific(s.ECC)
	case len(s.Bits) > 0:
		return PrivateVendorSpecific(s.Bits)
	case len(s.Sym) > 0:
		return PrivateVendorSpecific(s.Sym)
	default:
		return nil
	}
}

// Sensitive corresponds to the TPMT_SENSITIVE type.
type Sensitive struct {
	Type      ObjectTypeId         // Same as the corresponding Type in the Public object
	AuthValue Auth                 // Authorization value
	SeedValue Digest               // For a parent object, the seed value for protecting descendant objects
	Sensitive *SensitiveCompositeU `tpm2:"selector:Type"` // Type specific private data
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

// WithAttrs returns NVAttributes for this type with the specified attributes set.
func (t NVType) WithAttrs(attrs NVAttributes) NVAttributes {
	return NVAttributes(t<<4) | attrs
}

// NVPinCounterParams corresponds to the TPMS_NV_PIN_COUNTER_PARAMETERS type.
type NVPinCounterParams struct {
	Count uint32
	Limit uint32
}

// NVAttributes corresponds to the TPMA_NV type, and represents the attributes of a NV index. When exchanged with the TPM, some bits
// are reserved to encode the type of the NV index (NVType).
type NVAttributes uint32

// Type returns the NVType encoded in a NVAttributes value.
func (a NVAttributes) Type() NVType {
	return NVType((a & 0xf0) >> 4)
}

// AttrsOnly returns the NVAttributes without the encoded NVType.
func (a NVAttributes) AttrsOnly() NVAttributes {
	return a & ^NVAttributes(0xf0)
}

// NVPublic corresponds to the TPMS_NV_PUBLIC type, which describes a NV index.
type NVPublic struct {
	Index      Handle          // Handle of the NV index
	NameAlg    HashAlgorithmId // NameAlg is the digest algorithm used to compute the name of the index
	Attrs      NVAttributes    // Attributes of this index
	AuthPolicy Digest          // Authorization policy for this index
	Size       uint16          // Size of this index
}

// Name computes the name of this NV index
func (p *NVPublic) Name() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	hasher := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	name, err := mu.MarshalToBytes(p.NameAlg, mu.RawBytes(hasher.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal algorithm and digest to name: %v", err)
	}
	return name, nil
}

func (p *NVPublic) compareName(name Name) bool {
	n, err := p.Name()
	if err != nil {
		return false
	}
	return bytes.Equal(n, name)
}

func (p *NVPublic) copy() (*NVPublic, error) {
	b, err := mu.MarshalToBytes(p)
	if err != nil {
		return nil, err
	}
	var out *NVPublic
	_, err = mu.UnmarshalFromBytes(b, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
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
