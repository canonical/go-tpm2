// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
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
	switch c {
	case ECCCurveNIST_P224:
		return elliptic.P224()
	case ECCCurveNIST_P256:
		return elliptic.P256()
	case ECCCurveNIST_P384:
		return elliptic.P384()
	case ECCCurveNIST_P521:
		return elliptic.P521()
	default:
		return nil
	}
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

// GetHash returns the equivalent crypto.Hash value for this algorithm.
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
	default:
		return 0
	}
}

// Supported determines if the TPM digest algorithm has an equivalent go crypto.Hash.
func (a HashAlgorithmId) Supported() bool {
	return a.GetHash() != crypto.Hash(0)
}

// NewHash constructs a new hash.Hash implementation for this algorithm. It will panic if HashAlgorithmId.Supported
// returns false.
func (a HashAlgorithmId) NewHash() hash.Hash {
	return a.GetHash().New()
}

// Size returns the size of the algorithm. It will panic if HashAlgorithmId.Supported returns false.
func (a HashAlgorithmId) Size() int {
	return a.GetHash().Size()
}

// SymAlgorithmId corresponds to the TPMI_ALG_SYM type
type SymAlgorithmId AlgorithmId

// SymObjectAlgorithmId corresponds to the TPMI_ALG_SYM_OBJECT type
type SymObjectAlgorithmId AlgorithmId

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

func (p *TaggedHash) Marshal(buf io.Writer) (nbytes int, err error) {
	if err := binary.Write(buf, binary.BigEndian, p.HashAlg); err != nil {
		return nbytes, xerrors.Errorf("cannot marshal digest algorithm: %w", err)
	}
	nbytes += binary.Size(p.HashAlg)
	if !p.HashAlg.Supported() {
		return nbytes, fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	if p.HashAlg.Size() != len(p.Digest) {
		return nbytes, fmt.Errorf("invalid digest size %d", len(p.Digest))
	}

	n, err := buf.Write(p.Digest)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot write digest: %w", err)
	}
	return
}

func (p *TaggedHash) Unmarshal(buf io.Reader) (nbytes int, err error) {
	if err := binary.Read(buf, binary.BigEndian, &p.HashAlg); err != nil {
		return nbytes, xerrors.Errorf("cannot unmarshal digest algorithm: %w", err)
	}
	nbytes += binary.Size(p.HashAlg)
	if !p.HashAlg.Supported() {
		return nbytes, fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	p.Digest = make(Digest, p.HashAlg.Size())
	n, err := io.ReadFull(buf, p.Digest)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot read digest: %w", err)
	}
	return
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

func (d *PCRSelect) Marshal(buf io.Writer) (nbytes int, err error) {
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
		return nbytes, xerrors.Errorf("cannot write size of PCR selection bit mask: %w", err)
	}
	nbytes += binary.Size(uint8(0))

	n, err := buf.Write(bytes)
	nbytes += int(n)
	if err != nil {
		return nbytes, xerrors.Errorf("cannot write PCR selection bit mask: %w", err)
	}
	return
}

func (d *PCRSelect) Unmarshal(buf io.Reader) (nbytes int, err error) {
	var size uint8
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nbytes, xerrors.Errorf("cannot read size of PCR selection bit mask: %w", err)
	}
	nbytes += binary.Size(uint8(0))

	bytes := make([]byte, size)

	n, err := io.ReadFull(buf, bytes)
	nbytes += n
	if err != nil {
		return nbytes, xerrors.Errorf("cannot read PCR selection bit mask: %w", err)
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

	return
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

// Equal indicates whether l and r contain the same PCR selections. Equal selections will marshal to the same bytes in the TPM
// wire format. To be considered equal, each set of selections must be identical length, contain the same PCR banks in the same
// order, and each PCR bank must contain the same set of PCRs - the order of the PCRs in each bank are not important.
func (l PCRSelectionList) Equal(r PCRSelectionList) bool {
	if len(l) != len(r) {
		return false
	}
	for i, sl := range l {
		if sl.Hash != r[i].Hash {
			return false
		}

		if len(sl.Select) != len(r[i].Select) {
			return false
		}

		sls := make([]int, len(sl.Select))
		copy(sls, sl.Select)
		sort.Ints(sls)
		srs := make([]int, len(r[i].Select))
		copy(srs, r[i].Select)
		sort.Ints(srs)

		for i := range sls {
			if sls[i] != srs[i] {
				return false
			}
		}
	}

	return true
}

// Sort will sort the list of PCR selections in order of ascending algorithm ID, and for each PCR selection it will also sort the list
// of PCRs in ascending order. A new list of selections is returned.
func (l PCRSelectionList) Sort() (out PCRSelectionList) {
	for _, p := range l {
		o := PCRSelection{Hash: p.Hash}
		o.Select = make([]int, len(p.Select))
		copy(o.Select, p.Select)
		sort.Ints(o.Select)
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return
}

// Normalize will return a new sorted list of PCR selections with each PCR and each PCR bank only appearing once.
func (l PCRSelectionList) Normalize() PCRSelectionList {
	return PCRSelectionList{}.Merge(l).Sort()
}

// Merge will merge the PCR selections specified by l and r together and return a new set of PCR selections which contains a
// combination of both. For each PCR found in r that isn't found in l, it will be added to the first occurence of the corresponding
// PCR bank found in l if that exists, or otherwise a selection for that PCR bank will be appended to the result.
func (l PCRSelectionList) Merge(r PCRSelectionList) (out PCRSelectionList) {
	for _, s := range l {
		o := PCRSelection{Hash: s.Hash}
		o.Select = make([]int, len(s.Select))
		copy(o.Select, s.Select)
		out = append(out, o)
	}

	for _, s := range r {
		for _, y := range s.Select {
			found := false
			for _, o := range out {
				if o.Hash != s.Hash {
					continue
				}
				for _, x := range o.Select {
					if x == y {
						found = true
						break
					}
				}
				if found {
					break
				}
			}

			if !found {
				added := false
				for i, o := range out {
					if o.Hash != s.Hash {
						continue
					}
					found = false
					for _, x := range o.Select {
						if x == y {
							found = true
							break
						}
					}
					if !found {
						out[i].Select = append(o.Select, y)
						added = true
						break
					}
				}
				if !added {
					out = append(out, PCRSelection{Hash: s.Hash, Select: []int{y}})
				}
			}
		}
	}
	return
}

// Subtract will subtract the PCR selections in r from the PCR selections in l, and return a new set of selections. For each PCR
// selected in r, the first occurence found in l is removed from the result. If r references a PCR that is not found in l, an error
// is returned.
func (l PCRSelectionList) Subtract(r PCRSelectionList) (out PCRSelectionList, err error) {
	var scratch PCRSelectionList
	for _, s := range l {
		o := PCRSelection{Hash: s.Hash}
		o.Select = make([]int, len(s.Select))
		copy(o.Select, s.Select)
		scratch = append(scratch, o)
	}

	for _, s := range r {
		for _, y := range s.Select {
			subtracted := false
			for i, o := range scratch {
				if o.Hash != s.Hash {
					continue
				}
				for j, x := range o.Select {
					if x == y {
						if j < len(o.Select)-1 {
							copy(scratch[i].Select[j:], o.Select[j+1:])
						}
						scratch[i].Select = o.Select[:len(o.Select)-1]
						subtracted = true
						break
					}
				}
				if subtracted {
					break
				}
			}
			if !subtracted {
				return nil, fmt.Errorf("cannot subtract PCR%d/%v from selection", y, s.Hash)
			}
		}
	}

	for _, o := range scratch {
		if len(o.Select) == 0 {
			continue
		}
		out = append(out, o)
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

func (c CapabilitiesU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(Capability) {
	case CapabilityAlgs:
		return reflect.TypeOf(AlgorithmPropertyList(nil))
	case CapabilityHandles:
		return reflect.TypeOf(HandleList(nil))
	case CapabilityCommands:
		return reflect.TypeOf(CommandAttributesList(nil))
	case CapabilityPPCommands:
		return reflect.TypeOf(CommandCodeList(nil))
	case CapabilityAuditCommands:
		return reflect.TypeOf(CommandCodeList(nil))
	case CapabilityPCRs:
		return reflect.TypeOf(PCRSelectionList(nil))
	case CapabilityTPMProperties:
		return reflect.TypeOf(TaggedTPMPropertyList(nil))
	case CapabilityPCRProperties:
		return reflect.TypeOf(TaggedPCRPropertyList(nil))
	case CapabilityECCCurves:
		return reflect.TypeOf(ECCCurveList(nil))
	case CapabilityAuthPolicies:
		return reflect.TypeOf(TaggedPolicyList(nil))
	default:
		return nil
	}
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
//  - TagAttestSessionAudit: *SessionAuditInfo
//  - TagAttestCertify: *CertifyInfo
//  - TagAttestQuote: *QuoteInfo
//  - TagAttestTime: *TimeAttestInfo
//  - TagAttestCreation: *CreationInfo
type AttestU struct {
	Data interface{}
}

func (a AttestU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(StructTag) {
	case TagAttestNV:
		return reflect.TypeOf((*NVCertifyInfo)(nil))
	case TagAttestCommandAudit:
		return reflect.TypeOf((*CommandAuditInfo)(nil))
	case TagAttestSessionAudit:
		return reflect.TypeOf((*SessionAuditInfo)(nil))
	case TagAttestCertify:
		return reflect.TypeOf((*CertifyInfo)(nil))
	case TagAttestQuote:
		return reflect.TypeOf((*QuoteInfo)(nil))
	case TagAttestTime:
		return reflect.TypeOf((*TimeAttestInfo)(nil))
	case TagAttestCreation:
		return reflect.TypeOf((*CreationInfo)(nil))
	default:
		return nil
	}
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
	Attested        AttestU      `tpm2:"selector:Type"` // Type specific attestation data
}

// AttestRaw corresponds to the TPM2B_ATTEST type, and is returned by the attestation commands. The signature of the attestation is
// over this data.
type AttestRaw []byte

// Decode unmarshals the underlying buffer to the corresponding Attest structure.
func (a AttestRaw) Decode() (*Attest, error) {
	var out Attest
	if _, err := mu.UnmarshalFromBytes(a, &out); err != nil {
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
//  - AlgorithmXOR: HashAlgorithmId
//  - AlgorithmNull: <nil>
type SymKeyBitsU struct {
	Data interface{}
}

func (b SymKeyBitsU) Select(selector reflect.Value) reflect.Type {
	switch selector.Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return reflect.TypeOf(uint16(0))
	case AlgorithmXOR:
		return reflect.TypeOf(HashAlgorithmId(0))
	case AlgorithmNull:
		return reflect.TypeOf(mu.NilUnionValue)
	default:
		return nil
	}
}

// Sym returns the underlying value as uint16. It panics if the underlying type is not uint16.
func (b SymKeyBitsU) Sym() uint16 {
	return b.Data.(uint16)
}

// XOR returns the underlying value as HashAlgorithmId. It panics if the underlying type is not HashAlgorithmId.
func (b SymKeyBitsU) XOR() HashAlgorithmId {
	return b.Data.(HashAlgorithmId)
}

// SymModeU is a fake union type that corresponds to the TPMU_SYM_MODE type. The selector type is AlgorithmId. Valid types for Data
// for each selector value are:
//  - AlgorithmAES: SymModeId
//  - AlgorithmSM4: SymModeId
//  - AlgorithmCamellia: SymModeId
//  - AlgorithmXOR: <nil>
//  - AlgorithmNull: <nil>
type SymModeU struct {
	Data interface{}
}

func (m SymModeU) Select(selector reflect.Value) reflect.Type {
	switch selector.Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return reflect.TypeOf(SymModeId(0))
	case AlgorithmXOR:
		fallthrough
	case AlgorithmNull:
		return reflect.TypeOf(mu.NilUnionValue)
	default:
		return nil
	}
}

// Sym returns the underlying value as SymModeId. It panics if the underlying type is not SymModeId.
func (m SymModeU) Sym() SymModeId {
	return m.Data.(SymModeId)
}

// SymDef corresponds to the TPMT_SYM_DEF type, and is used to select the algorithm used for parameter encryption.
type SymDef struct {
	Algorithm SymAlgorithmId // Symmetric algorithm
	KeyBits   SymKeyBitsU    `tpm2:"selector:Algorithm"` // Symmetric key size
	Mode      SymModeU       `tpm2:"selector:Algorithm"` // Symmetric mode
}

// SymDefObject corresponds to the TPMT_SYM_DEF_OBJECT type, and is used to define an object's symmetric algorithm.
type SymDefObject struct {
	Algorithm SymObjectAlgorithmId // Symmetric algorithm
	KeyBits   SymKeyBitsU          `tpm2:"selector:Algorithm"` // Symmetric key size
	Mode      SymModeU             `tpm2:"selector:Algorithm"` // Symmetric mode
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

// SchemeKeyedHashU is a fake union type that corresponds to the TPMU_SCHEME_KEYED_HASH type. The selector type is KeyedHashSchemeId. Valid
// types for Data for each selector value are:
//  - KeyedHashSchemeHMAC: *SchemeHMAC
//  - KeyedHashSchemeXOR: *SchemeXOR
//  - KeyedHashSchemeNull: <nil>
type SchemeKeyedHashU struct {
	Data interface{}
}

func (d SchemeKeyedHashU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(KeyedHashSchemeId) {
	case KeyedHashSchemeHMAC:
		return reflect.TypeOf((*SchemeHMAC)(nil))
	case KeyedHashSchemeXOR:
		return reflect.TypeOf((*SchemeXOR)(nil))
	case KeyedHashSchemeNull:
		return reflect.TypeOf(mu.NilUnionValue)
	default:
		return nil
	}
}

// HMAC returns the underlying value as *SchemeHMAC. It panics if the underlying type is not *SchemeHMAC.
func (d SchemeKeyedHashU) HMAC() *SchemeHMAC {
	return d.Data.(*SchemeHMAC)
}

// XOR returns the underlying value as *SchemeXOR. It panics if the underlying type is not *SchemeXOR.
func (d SchemeKeyedHashU) XOR() *SchemeXOR {
	return d.Data.(*SchemeXOR)
}

// KeyedHashScheme corresponds to the TPMT_KEYEDHASH_SCHEME type.
type KeyedHashScheme struct {
	Scheme  KeyedHashSchemeId // Scheme selector
	Details SchemeKeyedHashU  `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2 Assymetric

// 11.2.1 Signing Schemes

type SigSchemeRSASSA SchemeHash
type SigSchemeRSAPSS SchemeHash
type SigSchemeECDSA SchemeHash
type SigSchemeECDAA SchemeECDAA
type SigSchemeSM2 SchemeHash
type SigSchemeECSCHNORR SchemeHash

// SigSchemeU is a fake union type that corresponds to the TPMU_SIG_SCHEME type. The selector type is SigSchemeId. Valid types for
// Data for each selector value are:
//  - SigSchemeAlgRSASSA: *SigSchemeRSASSA
//  - SigSchemeAlgRSAPSS: *SigSchemeRSAPSS
//  - SigSchemeAlgECDSA: *SigSchemeECDSA
//  - SigSchemeAlgECDAA: *SigSchemeECDAA
//  - SigSchemeAlgSM2: *SigSchemeSM2
//  - SigSchemeAlgECSCHNORR: *SigSchemeECSCHNORR
//  - SigSchemeAlgHMAC: *SigSchemeHMAC
//  - SigSchemeAlgNull: <nil>
type SigSchemeU struct {
	Data interface{}
}

func (s SigSchemeU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return reflect.TypeOf((*SigSchemeRSASSA)(nil))
	case SigSchemeAlgRSAPSS:
		return reflect.TypeOf((*SigSchemeRSAPSS)(nil))
	case SigSchemeAlgECDSA:
		return reflect.TypeOf((*SigSchemeECDSA)(nil))
	case SigSchemeAlgECDAA:
		return reflect.TypeOf((*SigSchemeECDAA)(nil))
	case SigSchemeAlgSM2:
		return reflect.TypeOf((*SigSchemeSM2)(nil))
	case SigSchemeAlgECSCHNORR:
		return reflect.TypeOf((*SigSchemeECSCHNORR)(nil))
	case SigSchemeAlgHMAC:
		return reflect.TypeOf((*SchemeHMAC)(nil))
	case SigSchemeAlgNull:
		return reflect.TypeOf(mu.NilUnionValue)
	default:
		return nil
	}
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
	Scheme  SigSchemeId // Scheme selector
	Details SigSchemeU  `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2.3 Key Derivation Schemes

type SchemeMGF1 SchemeHash
type SchemeKDF1_SP800_56A SchemeHash
type SchemeKDF2 SchemeHash
type SchemeKDF1_SP800_108 SchemeHash

// KDFSchemeU is a fake union type that corresponds to the TPMU_KDF_SCHEME type. The selector type is KDFAlgorithmId. Valid types for
// Data for each selector value are:
//  - KDFAlgorithmMGF1: *SchemeMGF1
//  - KDFAlgorithmKDF1_SP800_56A: *SchemeKDF1_SP800_56A
//  - KDFAlgorithmKDF2: *SchemeKF2
//  - KDFAlgorithmKDF1_SP800_108: *SchemeKDF1_SP800_108
//  - KDFAlgorithmNull: <nil>
type KDFSchemeU struct {
	Data interface{}
}

func (s KDFSchemeU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(KDFAlgorithmId) {
	case KDFAlgorithmMGF1:
		return reflect.TypeOf((*SchemeMGF1)(nil))
	case KDFAlgorithmKDF1_SP800_56A:
		return reflect.TypeOf((*SchemeKDF1_SP800_56A)(nil))
	case KDFAlgorithmKDF2:
		return reflect.TypeOf((*SchemeKDF2)(nil))
	case KDFAlgorithmKDF1_SP800_108:
		return reflect.TypeOf((*SchemeKDF1_SP800_108)(nil))
	case KDFAlgorithmNull:
		return reflect.TypeOf(mu.NilUnionValue)
	default:
		return nil
	}
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
	Scheme  KDFAlgorithmId // Scheme selector
	Details KDFSchemeU     `tpm2:"selector:Scheme"` // Scheme specific parameters.
}

type KeySchemeECDH SchemeHash
type KeySchemeECMQV SchemeHash
type EncSchemeRSAES Empty
type EncSchemeOAEP SchemeHash

// AsymSchemeId corresponds to the TPMI_ALG_ASYM_SCHEME type
type AsymSchemeId AlgorithmId

// AsymSchemeU is a fake union type that corresponds to the TPMU_ASYM_SCHEME type. The selector type is AsymSchemeId. Valid types for
// Data for each selector value are:
//  - AsymSchemeRSASSA: *SigSchemeRSASSA
//  - AsymSchemeRSAES: *EncSchemeRSAES
//  - AsymSchemeRSAPSS: *SigSchemeRSAPSS
//  - AsymSchemeOAEP: *EncSchemeOAEP
//  - AsymSchemeECDSA: *SigSchemeECDSA
//  - AsymSchemeECDH: *KeySchemeECDH
//  - AsymSchemeECDAA: *SigSchemeECDAA
//  - AsymSchemeSM2: *SigSchemeSM2
//  - AsymSchemeECSCHNORR: *SigSchemeECSCHNORR
//  - AsymSchemeECMQV: *KeySchemeECMQV
//  - AsymSchemeNull: <nil>
type AsymSchemeU struct {
	Data interface{}
}

func (s AsymSchemeU) Select(selector reflect.Value) reflect.Type {
	switch selector.Convert(reflect.TypeOf(AsymSchemeId(0))).Interface().(AsymSchemeId) {
	case AsymSchemeRSASSA:
		return reflect.TypeOf((*SigSchemeRSASSA)(nil))
	case AsymSchemeRSAES:
		return reflect.TypeOf((*EncSchemeRSAES)(nil))
	case AsymSchemeRSAPSS:
		return reflect.TypeOf((*SigSchemeRSAPSS)(nil))
	case AsymSchemeOAEP:
		return reflect.TypeOf((*EncSchemeOAEP)(nil))
	case AsymSchemeECDSA:
		return reflect.TypeOf((*SigSchemeECDSA)(nil))
	case AsymSchemeECDH:
		return reflect.TypeOf((*KeySchemeECDH)(nil))
	case AsymSchemeECDAA:
		return reflect.TypeOf((*SigSchemeECDAA)(nil))
	case AsymSchemeSM2:
		return reflect.TypeOf((*SigSchemeSM2)(nil))
	case AsymSchemeECSCHNORR:
		return reflect.TypeOf((*SigSchemeECSCHNORR)(nil))
	case AsymSchemeECMQV:
		return reflect.TypeOf((*KeySchemeECMQV)(nil))
	case AsymSchemeNull:
		return reflect.TypeOf(mu.NilUnionValue)
	default:
		return nil
	}
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
	Scheme  AsymSchemeId // Scheme selector
	Details AsymSchemeU  `tpm2:"selector:Scheme"` // Scheme specific parameters
}

// 11.2.4 RSA

// RSASchemeId corresponds to the TPMI_ALG_RSA_SCHEME type.
type RSASchemeId AsymSchemeId

// RSAScheme corresponds to the TPMT_RSA_SCHEME type.
type RSAScheme struct {
	Scheme  RSASchemeId // Scheme selector
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

// ECCSchemeId corresponds to the TPMI_ALG_ECC_SCHEME type.
type ECCSchemeId AsymSchemeId

// ECCScheme corresponds to the TPMT_ECC_SCHEME type.
type ECCScheme struct {
	Scheme  ECCSchemeId // Scheme selector
	Details AsymSchemeU `tpm2:"selector:Scheme"` // Scheme specific parameters.
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

// SignatureU is a fake union type that corresponds to TPMU_SIGNATURE. The selector type is SigSchemeId. Valid types for Data for
// each selector value are:
//  - SigSchemeAlgRSASSA: *SignatureRSASSA
//  - SigSchemeAlgRSAPSS: *SignatureRSAPSS
//  - SigSchemeAlgECDSA: *SignatureECDSA
//  - SigSchemeAlgECDAA: *SignatureECDAA
//  - SigSchemeAlgSM2: *SignatureSM2
//  - SigSchemeAlgECSCHNORR: *SignatureECSCHNORR
//  - SigSchemeAlgHMAC: *TaggedHash
//  - SigSchemeAlgNull: <nil>
type SignatureU struct {
	Data interface{}
}

func (s SignatureU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return reflect.TypeOf((*SignatureRSASSA)(nil))
	case SigSchemeAlgRSAPSS:
		return reflect.TypeOf((*SignatureRSAPSS)(nil))
	case SigSchemeAlgECDSA:
		return reflect.TypeOf((*SignatureECDSA)(nil))
	case SigSchemeAlgECDAA:
		return reflect.TypeOf((*SignatureECDAA)(nil))
	case SigSchemeAlgSM2:
		return reflect.TypeOf((*SignatureSM2)(nil))
	case SigSchemeAlgECSCHNORR:
		return reflect.TypeOf((*SignatureECSCHNORR)(nil))
	case SigSchemeAlgHMAC:
		return reflect.TypeOf((*TaggedHash)(nil))
	case SigSchemeAlgNull:
		return reflect.TypeOf(mu.NilUnionValue)
	default:
		return nil
	}
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
	SigAlg    SigSchemeId // Signature algorithm
	Signature SignatureU  `tpm2:"selector:SigAlg"` // Actual signature
}

// 11.4) Key/Secret Exchange

// EncryptedSecret corresponds to the TPM2B_ENCRYPTED_SECRET type.
type EncryptedSecret []byte

// 12) Key/Object Complex

// 12.2) Public Area Structures

// ObjectTypeId corresponds to the TPMI_ALG_PUBLIC type.
type ObjectTypeId AlgorithmId

// PublicIDU is a fake union type that corresponds to the TPMU_PUBLIC_ID type. The selector type is ObjectTypeId. Valid types for Data
// for each selector value are:
//  - ObjectTypeRSA: PublicKeyRSA
//  - ObjectTypeKeyedHash: Digest
//  - ObjectTypeECC: *ECCPoint
//  - ObjectTypeSymCipher: Digest
type PublicIDU struct {
	Data interface{}
}

func (p PublicIDU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return reflect.TypeOf(PublicKeyRSA(nil))
	case ObjectTypeKeyedHash:
		return reflect.TypeOf(Digest(nil))
	case ObjectTypeECC:
		return reflect.TypeOf((*ECCPoint)(nil))
	case ObjectTypeSymCipher:
		return reflect.TypeOf(Digest(nil))
	default:
		return nil
	}
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

// PublicParamsU is a fake union type that corresponds to the TPMU_PUBLIC_PARMS type. The selector type is ObjectTypeId. Valid types
// for Data for each selector value are:
//  - ObjectTypeRSA: *RSAParams
//  - ObjectTypeKeyedHash: *KeyedHashParams
//  - ObjectTypeECC: *ECCParams
//  - ObjectTypeSymCipher: *SymCipherParams
type PublicParamsU struct {
	Data interface{}
}

func (p PublicParamsU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return reflect.TypeOf((*RSAParams)(nil))
	case ObjectTypeKeyedHash:
		return reflect.TypeOf((*KeyedHashParams)(nil))
	case ObjectTypeECC:
		return reflect.TypeOf((*ECCParams)(nil))
	case ObjectTypeSymCipher:
		return reflect.TypeOf((*SymCipherParams)(nil))
	default:
		return nil
	}
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

// PublicParams corresponds to the TPMT_PUBLIC_PARMS type.
type PublicParams struct {
	Type       ObjectTypeId  // Type specifier
	Parameters PublicParamsU `tpm2:"selector:Type"` // Algorithm details
}

// Public corresponds to the TPMT_PUBLIC type, and defines the public area for an object.
type Public struct {
	Type       ObjectTypeId     // Type of this object
	NameAlg    HashAlgorithmId  // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes // Object attributes
	AuthPolicy Digest           // Authorization policy for this object
	Params     PublicParamsU    `tpm2:"selector:Type"` // Type specific parameters
	Unique     PublicIDU        `tpm2:"selector:Type"` // Type specific unique identifier
}

// Name computes the name of this object
func (p *Public) Name() (Name, error) {
	if !p.NameAlg.Supported() {
		return nil, fmt.Errorf("unsupported name algorithm: %v", p.NameAlg)
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

type publicSized struct {
	Ptr *Public `tpm2:"sized"`
}

// PublicDerived is similar to Public but can be used as a template to create a derived object with TPMContext.CreateLoaded
type PublicDerived struct {
	Type       ObjectTypeId     // Type of this object
	NameAlg    HashAlgorithmId  // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes // Object attributes
	AuthPolicy Digest           // Authorization policy for this object
	Params     PublicParamsU    `tpm2:"selector:Type"` // Type specific parameters

	// Unique contains the derivation values. These take precedence over any values specified in SensitiveCreate.Data when creating a
	// derived object,
	Unique *Derive
}

// Name computes the name of this object
func (p *PublicDerived) Name() (Name, error) {
	if !p.NameAlg.Supported() {
		return nil, fmt.Errorf("unsupported name algorithm: %v", p.NameAlg)
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

// SensitiveCompositeU is a fake union type that corresponds to the TPMU_SENSITIVE_COMPOSITE type. The selector type is ObjectTypeId.
// Valid types for Data for each selector value are:
//  - ObjectTypeRSA: PrivateKeyRSA
//  - ObjectTypeECC: ECCParameter
//  - ObjectTypeKeyedHash: SensitiveData
//  - ObjectTypeSymCipher: SymKey
type SensitiveCompositeU struct {
	Data interface{}
}

func (s SensitiveCompositeU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return reflect.TypeOf(PrivateKeyRSA(nil))
	case ObjectTypeECC:
		return reflect.TypeOf(ECCParameter(nil))
	case ObjectTypeKeyedHash:
		return reflect.TypeOf(SensitiveData(nil))
	case ObjectTypeSymCipher:
		return reflect.TypeOf(SymKey(nil))
	default:
		return nil
	}
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
	Type      ObjectTypeId        // Same as the corresponding Type in the Public object
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
	if !p.NameAlg.Supported() {
		return nil, fmt.Errorf("unsupported name algorithm: %v", p.NameAlg)
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
