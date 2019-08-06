// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// 6) Constants
type TPMGenerated uint32
type AlgorithmId uint16
type ECCCurve uint16
type CommandCode uint32
type ResponseCode uint32
type StructTag uint16
type StartupType uint16
type SessionType uint8
type Capability uint32
type Property uint32
type PropertyPCR uint32

// 7) Handles
type Handle uint32

// 8) Attributes
type AlgorithmAttributes uint32
type ObjectAttributes uint32
type Locality uint8
type PermanentAttributes uint32
type StartupClearAttributes uint32

type CommandAttributes uint32

func (a CommandAttributes) CommandCode() CommandCode {
	return CommandCode(a & 0xffff)
}

func (a CommandAttributes) NumberOfCommandHandles() int {
	return int((a & 0x0e000000) >> 25)
}

func (a CommandAttributes) Attrs() CommandAttributes {
	return a &^ 0x0e00ffff
}


// 10) Structure Definitions
type Empty struct{}

type TaggedHash struct {
	HashAlg AlgorithmId
	Digest  []byte
}

// TaggedHash represents the TPMT_HA type in the TCG spec. In the spec, TPMT_HA.digest is a union type
// (TPMU_HA), which is a union of all of the different hash algorithms. Each member of that union is an
// array of raw bytes. As no length is encoded, we need a custom marshaller implementation that unmarshals the
// correct number of bytes depending on the hash algorithm
func (p *TaggedHash) Marshal(buf io.Writer) error {
	if err := binary.Write(buf, binary.BigEndian, p.HashAlg); err != nil {
		return err
	}
	size, known := cryptGetDigestSize(p.HashAlg)
	if !known {
		return fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	if int(size) != len(p.Digest) {
		return fmt.Errorf("invalid digest size %d", len(p.Digest))
	}

	n, err := buf.Write(p.Digest)
	if err != nil {
		return fmt.Errorf("cannot write digest: %v", err)
	}
	if n != int(size) {
		return fmt.Errorf("cannot write entire digest")
	}
	return nil
}

func (p *TaggedHash) Unmarshal(buf io.Reader) error {
	if err := binary.Read(buf, binary.BigEndian, &p.HashAlg); err != nil {
		return err
	}
	size, known := cryptGetDigestSize(p.HashAlg)
	if !known {
		return fmt.Errorf("cannot determine digest size for unknown algorithm %v", p.HashAlg)
	}

	p.Digest = make(Digest, size)
	n, err := buf.Read(p.Digest)
	if err != nil {
		return fmt.Errorf("cannot read digest: %v", err)
	}
	if n != int(size) {
		return fmt.Errorf("cannot read digest: %v", io.EOF)
	}
	return nil
}

// 10.4 Sized Buffers
type Digest []byte
type Data []byte
type Nonce Digest
type Auth Digest
type Event []byte
type MaxBuffer []byte
type MaxNVBuffer []byte
type Timeout []byte

// 10.5) Names
type Name []byte

// 10.6) PCR Structures
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
		return fmt.Errorf("cannot write size of PCR selection bit mask: %v", err)
	}
	n, err := buf.Write(bytes)
	if err != nil {
		return fmt.Errorf("cannot write PCR selection bit mask: %v", err)
	}
	if n != len(bytes) {
		return errors.New("cannot write complete PCR selection bit mask")
	}
	return nil
}

func (d *PCRSelectionData) Unmarshal(buf io.Reader) error {
	var size uint8
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return fmt.Errorf("cannot read size of PCR selection bit mask: %v", err)
	}

	bytes := make([]byte, size)

	n, err := buf.Read(bytes)
	if err != nil {
		return fmt.Errorf("cannot read PCR selection bit mask: %v", err)
	}
	if n != int(size) {
		return errors.New("cannot read complete PCR selection bit mask")
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

type PCRSelection struct {
	Hash   AlgorithmId
	Select PCRSelectionData
}

// 10.7 Tickets
type TkCreation struct {
	Tag       StructTag
	Hierarchy Handle
	Digest    Digest
}

type TkAuth struct {
	Tag       StructTag
	Hierarchy Handle
	Digest    Digest
}

// 10.8 Property Structures
type AlgorithmProperty struct {
	Alg        AlgorithmId
	Properties AlgorithmAttributes
}

type TaggedProperty struct {
	Property Property
	Value    uint32
}

type TaggedPCRSelect struct {
	Tag    PropertyPCR
	Select PCRSelectionData
}

type TaggedPolicy struct {
	Handle     Handle
	PolicyHash TaggedHash
}

// 10.9) Lists
type CommandCodeList []CommandCode
type CommandAttributesList []CommandAttributes
type AlgorithmList []AlgorithmId
type HandleList []Handle
type DigestList []Digest
type TaggedHashList []TaggedHash
type PCRSelectionList []PCRSelection
type AlgorithmPropertyList []AlgorithmProperty
type TaggedTPMPropertyList []TaggedProperty
type TaggedPCRPropertyList []TaggedPCRSelect
type ECCCurveList []ECCCurve
type TaggedPolicyList []TaggedPolicy

// 10.10) Capabilities Structures
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

func (c CapabilitiesU) Select(selector interface{}) (string, error) {
	switch selector.(Capability) {
	case CapabilityAlgs:
		return "Algorithms", nil
	case CapabilityHandles:
		return "Handles", nil
	case CapabilityCommands:
		return "Command", nil
	case CapabilityPPCommands:
		return "PPCommands", nil
	case CapabilityAuditCommands:
		return "AuditCommands", nil
	case CapabilityPCRs:
		return "AssignedPCR", nil
	case CapabilityTPMProperties:
		return "TPMProperties", nil
	case CapabilityPCRProperties:
		return "PCRProperties", nil
	case CapabilityECCCurves:
		return "ECCCurves", nil
	case CapabilityAuthPolicies:
		return "AuthPolicies", nil
	}
	return "", invalidSelectorError{selector}
}

type CapabilityData struct {
	Capability Capability
	Data       CapabilitiesU
}

func (d CapabilityData) Selector(field reflect.StructField) interface{} {
	return d.Capability
}

// 10.11 Clock/Counter Structures
type ClockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
}

type TimeInfo struct {
	Time uint64
	ClockInfo
}

// 10.12 Attestation Structures
type TimeAttestInfo struct {
	Time            TimeInfo
	FirmwareVersion uint64
}

type CertifyInfo struct {
	Name,
	QualifiedName Name
}

type QuoteInfo struct {
	PCRSelect PCRSelectionList
	PCRDigest Digest
}

type CommandAuditInfo struct {
	AuditCounter  uint64
	DigestAlg     AlgorithmId
	AuditDigest   Digest
	CommandDigest Digest
}

type SessionAuditInfo struct {
	ExclusiveSession bool
	SessionDigest    Digest
}

type CreationInfo struct {
	ObjectName   Name
	CreationHash Digest
}

type NVCertifyInfo struct {
	IndexName  Name
	Offset     uint16
	NVContents MaxNVBuffer
}

type AttestU struct {
	Certify      *CertifyInfo
	Creation     *CreationInfo
	Quote        *QuoteInfo
	CommandAudit *CommandAuditInfo
	SessionAudit *SessionAuditInfo
	Time         *TimeAttestInfo
	NV           *NVCertifyInfo
}

func (a AttestU) Select(selector interface{}) (string, error) {
	switch selector.(StructTag) {
	case TagAttestNV:
		return "NV", nil
	case TagAttestCommandAudit:
		return "CommandAudit", nil
	case TagAttestSessionAudit:
		return "SessionAudit", nil
	case TagAttestCertify:
		return "Certify", nil
	case TagAttestQuote:
		return "Quote", nil
	case TagAttestTime:
		return "Time", nil
	case TagAttestCreation:
		return "Creation", nil
	}
	return "", invalidSelectorError{selector}
}

type Attest struct {
	Magic           TPMGenerated
	Type            StructTag
	QualifiedSigner Name
	ExtraData       Data
	ClockInfo
	FirmwareVersion uint64
	Attest          AttestU
}

func (a Attest) Selector(field reflect.StructField) interface{} {
	return a.Type
}

type Attest2B []byte

func (a Attest2B) ToStruct() (*Attest, error) {
	var out Attest
	if _, err := UnmarshalFromBytes(a, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// 11) Algorithm Parameters and Structures

// 11.1) Symmetric
type SymKeyBitsU struct {
	Sym uint16
	XOR AlgorithmId
}

func (b SymKeyBitsU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmXOR:
		return "XOR", nil
	case AlgorithmNull:
		return "", nil
	}
	return "Sym", nil
}

type SymModeU struct {
	Sym AlgorithmId
}

func (m SymModeU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmXOR:
		fallthrough
	case AlgorithmNull:
		return "", nil
	}
	return "Sym", nil
}

type SymDef struct {
	Algorithm AlgorithmId
	KeyBits   SymKeyBitsU
	Mode      SymModeU
}

func (d SymDef) Selector(field reflect.StructField) interface{} {
	return d.Algorithm
}

type SymDefObject struct {
	Algorithm AlgorithmId
	KeyBits   SymKeyBitsU
	Mode      SymModeU
}

func (o SymDefObject) Selector(field reflect.StructField) interface{} {
	return o.Algorithm
}

type SymKey []byte

type SymCipherParams struct {
	Sym SymDefObject
}

type Label []byte
type SensitiveData []byte

type SensitiveCreate struct {
	UserAuth Auth
	Data     SensitiveData
}

type SensitiveCreate2B SensitiveCreate

func (s SensitiveCreate2B) UnsizedStructType() reflect.Type {
	return reflect.TypeOf(SensitiveCreate(s))
}

type SchemeHash struct {
	HashAlg AlgorithmId
}

type SchemeECDAA struct {
	HashAlg AlgorithmId
	Count   uint16
}

type SchemeXOR struct {
	HashAlg AlgorithmId
	KDF     AlgorithmId
}

type SchemeHMAC SchemeHash

type SchemeKeyedHashU struct {
	HMAC *SchemeHMAC
	XOR  *SchemeXOR
}

func (d SchemeKeyedHashU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmHMAC:
		return "HMAC", nil
	case AlgorithmXOR:
		return "XOR", nil
	case AlgorithmNull:
		return "", nil
	}
	return "", invalidSelectorError{selector}
}

type KeyedHashScheme struct {
	Scheme  AlgorithmId
	Details SchemeKeyedHashU
}

func (s KeyedHashScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

// 11.2 Assymetric

// 11.2.1 Signing Schemes
type SigSchemeRSASSA SchemeHash
type SigSchemeRSAPSS SchemeHash
type SigSchemeECDSA SchemeHash
type SigSchemeECDAA SchemeECDAA
type SigSchemeSM2 SchemeHash
type SigSchemeECSCHNORR SchemeHash

type SigSchemeU struct {
	RSASSA    *SigSchemeRSASSA
	RSAPSS    *SigSchemeRSAPSS
	ECDSA     *SigSchemeECDSA
	ECDAA     *SigSchemeECDAA
	SM2       *SigSchemeSM2
	ECSCHNORR *SigSchemeECSCHNORR
	HMAC      *SchemeHMAC
}

func (s SigSchemeU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSASSA:
		return "RSASSA", nil
	case AlgorithmRSAPSS:
		return "RSAPSS", nil
	case AlgorithmECDSA:
		return "ECDSA", nil
	case AlgorithmECDAA:
		return "ECDAA", nil
	case AlgorithmSM2:
		return "SM2", nil
	case AlgorithmECSCHNORR:
		return "ECSCHNORR", nil
	case AlgorithmHMAC:
		return "HMAC", nil
	case AlgorithmNull:
		return "", nil
	}
	return "", invalidSelectorError{selector}
}

type SigScheme struct {
	Scheme  AlgorithmId
	Details SigSchemeU
}

func (s SigScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

// 11.2.3 Key Derivation Schemes
type SchemeMGF1 SchemeHash
type SchemeKDF1_SP800_56A SchemeHash
type SchemeKDF2 SchemeHash
type SchemeKDF1_SP800_108 SchemeHash

type KDFSchemeU struct {
	MGF1           *SchemeMGF1
	KDF1_SP800_56A *SchemeKDF1_SP800_56A
	KDF2           *SchemeKDF2
	KDF1_SP800_108 *SchemeKDF1_SP800_108
}

func (s KDFSchemeU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmMGF1:
		return "MGF1", nil
	case AlgorithmKDF1_SP800_56A:
		return "KDF1_SP800_56A", nil
	case AlgorithmKDF2:
		return "KDF2", nil
	case AlgorithmKDF1_SP800_108:
		return "KDF1_SP800_108", nil
	case AlgorithmNull:
		return "", nil
	}
	return "", invalidSelectorError{selector}
}

type KDFScheme struct {
	Scheme  AlgorithmId
	Details KDFSchemeU
}

func (s KDFScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

type KeySchemeECDH SchemeHash
type KeySchemeECMQV SchemeHash
type EncSchemeRSAES Empty
type EncSchemeOAEP SchemeHash

type AsymSchemeU struct {
	ECDH      *KeySchemeECDH
	ECMQV     *KeySchemeECMQV
	RSASSA    *SigSchemeRSASSA
	RSAPSS    *SigSchemeRSAPSS
	ECDSA     *SigSchemeECDSA
	ECDAA     *SigSchemeECDAA
	SM2       *SigSchemeSM2
	ECSCHNORR *SigSchemeECSCHNORR
	RSAES     *EncSchemeRSAES
	OAEP      *EncSchemeOAEP
}

func (s AsymSchemeU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSASSA:
		return "RSASSA", nil
	case AlgorithmRSAES:
		return "RSAES", nil
	case AlgorithmRSAPSS:
		return "RSAPSS", nil
	case AlgorithmOAEP:
		return "OAEP", nil
	case AlgorithmECDSA:
		return "ECDSA", nil
	case AlgorithmECDH:
		return "ECDH", nil
	case AlgorithmECDAA:
		return "ECDAA", nil
	case AlgorithmSM2:
		return "SM2", nil
	case AlgorithmECSCHNORR:
		return "ECSCHNORR", nil
	case AlgorithmECMQV:
		return "ECMQV", nil
	case AlgorithmNull:
		return "", nil
	}
	return "", invalidSelectorError{selector}
}

// 11.2.4 RSA
type RSAScheme struct {
	Scheme  AlgorithmId
	Details AsymSchemeU
}

func (s RSAScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

type PublicKeyRSA []byte
type PrivateKeyRSA []byte

// 11.2.5 ECC
type ECCParameter []byte

type ECCPoint struct {
	X, Y ECCParameter
}

type ECCScheme struct {
	Scheme  AlgorithmId
	Details AsymSchemeU
}

func (s ECCScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

// 11.3 Signatures
type SignatureRSA struct {
	Hash AlgorithmId
	Sig  PublicKeyRSA
}

type SignatureECC struct {
	Hash       AlgorithmId
	SignatureR ECCParameter
	SignatureS ECCParameter
}

type SignatureRSASSA SignatureRSA
type SignatureRSAPSS SignatureRSA
type SignatureECDSA SignatureECC
type SignatureECDAA SignatureECC
type SignatureSM2 SignatureECC
type SignatureECSCHNORR SignatureECC

type SignatureU struct {
	RSASSA    *SignatureRSASSA
	RSAPSS    *SignatureRSAPSS
	ECDSA     *SignatureECDSA
	ECDAA     *SignatureECDAA
	SM2       *SignatureSM2
	ECSCHNORR *SignatureECSCHNORR
	HMAC      *TaggedHash
}

func (s SignatureU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSASSA:
		return "RSASSA", nil
	case AlgorithmRSAPSS:
		return "RSAPSS", nil
	case AlgorithmECDSA:
		return "ECDSA", nil
	case AlgorithmECDAA:
		return "ECDAA", nil
	case AlgorithmSM2:
		return "SM2", nil
	case AlgorithmECSCHNORR:
		return "ECSCHNORR", nil
	case AlgorithmHMAC:
		return "HMAC", nil
	case AlgorithmNull:
		return "", nil
	}
	return "", invalidSelectorError{selector}
}

type Signature struct {
	SigAlg    AlgorithmId
	Signature SignatureU
}

func (s Signature) Selector(field reflect.StructField) interface{} {
	return s.SigAlg
}

// 11.4) Key/Secret Exchange
type EncryptedSecret []byte

// 12) Key/Object Complex

// 12.2) Public Area Structures
type PublicIDU struct {
	KeyedHash Digest
	Sym       Digest
	RSA       PublicKeyRSA
	ECC       *ECCPoint
}

func (p PublicIDU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSA:
		return "RSA", nil
	case AlgorithmKeyedHash:
		return "KeyedHash", nil
	case AlgorithmECC:
		return "ECC", nil
	case AlgorithmSymCipher:
		return "Sym", nil
	}
	return "", invalidSelectorError{selector}
}

type KeyedHashParams struct {
	Scheme KeyedHashScheme
}

type RSAParams struct {
	Symmetric SymDefObject
	Scheme    RSAScheme
	KeyBits   uint16
	Exponent  uint32
}

type ECCParams struct {
	Symmetric SymDefObject
	Scheme    ECCScheme
	CurveID   ECCCurve
	KDF       KDFScheme
}

type PublicParamsU struct {
	KeyedHashDetail *KeyedHashParams
	SymDetail       *SymCipherParams
	RSADetail       *RSAParams
	ECCDetail       *ECCParams
}

func (p PublicParamsU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSA:
		return "RSADetail", nil
	case AlgorithmKeyedHash:
		return "KeyedHashDetail", nil
	case AlgorithmECC:
		return "ECCDetail", nil
	case AlgorithmSymCipher:
		return "SymDetail", nil
	}
	return "", invalidSelectorError{selector}
}

type Public struct {
	Type       AlgorithmId
	NameAlg    AlgorithmId
	Attrs      ObjectAttributes
	AuthPolicy Digest
	Params     PublicParamsU
	Unique     PublicIDU
}

func (p Public) Selector(field reflect.StructField) interface{} {
	switch field.Name {
	case "Params", "Unique":
		return p.Type
	}
	return nil
}

func (p *Public) Name() (Name, error) {
	if !cryptIsKnownDigest(p.NameAlg) {
		return nil, fmt.Errorf("unsupported name algorithm: %v", p.NameAlg)
	}
	hasher := cryptConstructHash(p.NameAlg)
	if err := MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	name, err := MarshalToBytes(p.NameAlg, RawSlice(hasher.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal algorithm and digest to name: %v", err)
	}
	return name, nil
}

func (p *Public) Copy() *Public {
	b, err := MarshalToBytes(p)
	if err != nil {
		return nil
	}
	var c Public
	n, err := UnmarshalFromBytes(b, &c)
	if err != nil || n != len(b) {
		return nil
	}
	return &c
}

type Public2B Public

func (p Public2B) UnsizedStructType() reflect.Type {
	return reflect.TypeOf(Public(p))
}

// 12.3) Private Area Structures
type SensitiveCompositeU struct {
	RSA  PrivateKeyRSA
	ECC  ECCParameter
	Bits SensitiveData
	Sym  SymKey
}

func (s SensitiveCompositeU) Select(selector interface{}) (string, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSA:
		return "RSA", nil
	case AlgorithmECC:
		return "ECC", nil
	case AlgorithmKeyedHash:
		return "Bits", nil
	case AlgorithmSymCipher:
		return "Sym", nil
	}
	return "", invalidSelectorError{selector}
}

type Sensitive struct {
	Type      AlgorithmId
	AuthValue Auth
	SeedValue Digest
	Sensitive SensitiveCompositeU
}

func (s Sensitive) Selector(field reflect.StructField) interface{} {
	return s.Type
}

type Sensitive2B Sensitive

func (s Sensitive2B) UnsizedStructType() reflect.Type {
	return reflect.TypeOf(Sensitive(s))
}

type Private []byte

// 13) Storage Structures
type NVType uint32

type NVAttributes uint32

func (a NVAttributes) Type() NVType {
	return NVType((a & 0xf0) >> 4)
}

func MakeNVAttributes(a NVAttributes, t NVType) NVAttributes {
	return a | NVAttributes(t<<4)
}

type NVPublic struct {
	Index      Handle
	NameAlg    AlgorithmId
	Attrs      NVAttributes
	AuthPolicy Digest
	Size       uint16
}

func (p *NVPublic) Name() (Name, error) {
	if !cryptIsKnownDigest(p.NameAlg) {
		return nil, fmt.Errorf("unsupported name algorithm: %v", p.NameAlg)
	}
	hasher := cryptConstructHash(p.NameAlg)
	if err := MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	name, err := MarshalToBytes(p.NameAlg, RawSlice(hasher.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal algorithm and digest to name: %v", err)
	}
	return name, nil
}

type NVPublic2B NVPublic

func (p NVPublic2B) UnsizedStructType() reflect.Type {
	return reflect.TypeOf(NVPublic(p))
}

// 14) Context Data
type ContextData []byte

type Context struct {
	Sequence    uint64
	SavedHandle Handle
	Hierarchy   Handle
	Blob        ContextData
}

// 15) Creation Data
type CreationData struct {
	PCRSelect           PCRSelectionList
	PCRDigest           Digest
	Locality            Locality
	ParentNameAlg       AlgorithmId
	ParentName          Name
	ParentQualifiedName Name
	OutsideInfo         Data
}

type CreationData2B CreationData

func (c CreationData2B) UnsizedStructType() reflect.Type {
	return reflect.TypeOf(CreationData(c))
}
