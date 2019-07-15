package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

type AlgorithmAttributes uint32
type AlgorithmId uint16
type Capability uint32
type CommandCode uint32
type ECCCurve uint16
type Handle uint32
type Locality uint8
type NVType uint32
type ObjectAttributes uint32
type Property uint32
type PropertyPCR uint32
type ResponseCode uint32
type StartupType uint16
type StructTag uint16

type ErrorCode ResponseCode

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

type NVAttributes uint32

func (a NVAttributes) Type() NVType {
	return NVType((a & 0xf0) >> 4)
}

type Auth Digest

func (a Auth) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type Data []byte

func (d Data) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type Digest []byte

func (d Digest) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type ECCParameter []byte

func (e ECCParameter) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type Label []byte

func (l Label) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type MaxBuffer []byte

func (b MaxBuffer) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type Name []byte

func (n Name) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

func (n Name) IsHandle() bool {
	return len(n) == 4
}

func (n Name) Handle() Handle {
    if !n.IsHandle() {
	    panic("Name is not a handle")
    }
    return Handle(binary.BigEndian.Uint32(n))
}

type Nonce Digest

func (n Nonce) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type Private []byte

func (p Private) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type PrivateKeyRSA []byte

func (k PrivateKeyRSA) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type PublicKeyRSA []byte

func (k PublicKeyRSA) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type SensitiveData []byte

func (s SensitiveData) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type SymKey []byte

func (s SymKey) SliceType() SliceType {
	return SliceTypeSizedBufferU16
}

type PublicIDU struct {
	KeyedHash Digest
	Sym       Digest
	RSA       PublicKeyRSA
	ECC       *ECCPoint
}

func (p PublicIDU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (p PublicIDU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSA:
		return u.FieldByName("RSA"), nil
	case AlgorithmKeyedHash:
		return u.FieldByName("KeyedHash"), nil
	case AlgorithmECC:
		return u.FieldByName("ECC"), nil
	case AlgorithmSymCipher:
		return u.FieldByName("Sym"), nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

type SchemeKeyedHashU struct {
	HMAC *SchemeHMAC
	XOR  *SchemeXOR
}

func (d SchemeKeyedHashU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (d SchemeKeyedHashU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmHMAC:
		return u.FieldByName("HMAC"), nil
	case AlgorithmXOR:
		return u.FieldByName("XOR"), nil
	case AlgorithmNull:
		return reflect.Value{}, nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

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

func (s AsymSchemeU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (s AsymSchemeU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSASSA:
		return u.FieldByName("RSASSA"), nil
	case AlgorithmRSAES:
		return u.FieldByName("RSAES"), nil
	case AlgorithmRSAPSS:
		return u.FieldByName("RSAPSS"), nil
	case AlgorithmOAEP:
		return u.FieldByName("OAEP"), nil
	case AlgorithmECDSA:
		return u.FieldByName("ECDSA"), nil
	case AlgorithmECDH:
		return u.FieldByName("ECDH"), nil
	case AlgorithmECDAA:
		return u.FieldByName("ECDAA"), nil
	case AlgorithmSM2:
		return u.FieldByName("SM2"), nil
	case AlgorithmECSCHNORR:
		return u.FieldByName("ECSCHNORR"), nil
	case AlgorithmECMQV:
		return u.FieldByName("ECMQV"), nil
	case AlgorithmNull:
		return reflect.Value{}, nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

type KDFSchemeU struct {
	MGF1           *SchemeMGF1
	KDF1_SP800_56A *SchemeKDF1_SP800_56A
	KDF2           *SchemeKDF2
	KDF1_SP800_108 *SchemeKDF1_SP800_108
}

func (s KDFSchemeU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (s KDFSchemeU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmMGF1:
		return u.FieldByName("MGF1"), nil
	case AlgorithmKDF1_SP800_56A:
		return u.FieldByName("KDF1_SP800_56A"), nil
	case AlgorithmKDF2:
		return u.FieldByName("KDF2"), nil
	case AlgorithmKDF1_SP800_108:
		return u.FieldByName("KDF1_SP800_108"), nil
	case AlgorithmNull:
		return reflect.Value{}, nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

type PublicParamsU struct {
	KeyedHashDetail *KeyedHashParams
	SymDetail       *SymCipherParams
	RSADetail       *RSAParams
	ECCDetail       *ECCParams
}

func (p PublicParamsU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (p PublicParamsU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSA:
		return u.FieldByName("RSADetail"), nil
	case AlgorithmKeyedHash:
		return u.FieldByName("KeyedHashDetail"), nil
	case AlgorithmECC:
		return u.FieldByName("ECCDetail"), nil
	case AlgorithmSymCipher:
		return u.FieldByName("SymDetail"), nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

type KeyBitsU struct {
	Sym uint16
	XOR AlgorithmId
}

func (b KeyBitsU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (b KeyBitsU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmXOR:
		return u.FieldByName("XOR"), nil
	case AlgorithmNull:
		return reflect.Value{}, nil
	}
	return u.FieldByName("Sym"), nil
}

type SymModeU struct {
	Sym AlgorithmId
}

func (m SymModeU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (m SymModeU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmXOR:
		fallthrough
	case AlgorithmNull:
		return reflect.Value{}, nil
	}
	return u.FieldByName("Sym"), nil
}

type SensitiveCompositeU struct {
	RSA  PrivateKeyRSA
	ECC  ECCParameter
	Bits SensitiveData
	Sym  SymKey
}

func (s SensitiveCompositeU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (s SensitiveCompositeU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(AlgorithmId) {
	case AlgorithmRSA:
		return u.FieldByName("RSA"), nil
	case AlgorithmECC:
		return u.FieldByName("ECC"), nil
	case AlgorithmKeyedHash:
		return u.FieldByName("Bits"), nil
	case AlgorithmSymCipher:
		return u.FieldByName("Sym"), nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

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

func (c CapabilitiesU) StructFlags() StructFlags {
	return StructFlagUnion
}

func (c CapabilitiesU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(Capability) {
	case CapabilityAlgs:
		return u.FieldByName("Algorithms"), nil
	case CapabilityHandles:
		return u.FieldByName("Handles"), nil
	case CapabilityCommands:
		return u.FieldByName("Command"), nil
	case CapabilityPPCommands:
		return u.FieldByName("PPCommands"), nil
	case CapabilityAuditCommands:
		return u.FieldByName("AuditCommands"), nil
	case CapabilityPCRs:
		return u.FieldByName("AssignedPCR"), nil
	case CapabilityTPMProperties:
		return u.FieldByName("TPMProperties"), nil
	case CapabilityPCRProperties:
		return u.FieldByName("PCRProperties"), nil
	case CapabilityECCCurves:
		return u.FieldByName("ECCCurves"), nil
	case CapabilityAuthPolicies:
		return u.FieldByName("AuthPolicies"), nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

type TkCreation struct {
	Tag       StructTag
	Hierarchy Handle
	Digest    Digest
}

type CreationData struct {
	PCRSelect           PCRSelectionList
	PCRDigest           Digest
	Locality            Locality
	ParentNameAlg       AlgorithmId
	ParentName          Name
	ParentQualifiedName Name
	OutsideInfo         Data
}

func (c CreationData) StructFlags() StructFlags {
	return StructFlagSized
}

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

type TaggedPCRSelect struct {
	Tag    PropertyPCR
	Select PCRSelectionData
}

type SchemeHash struct {
	HashAlg AlgorithmId
}
type SchemeHMAC SchemeHash
type KeySchemeECDH SchemeHash
type KeySchemeECMQV SchemeHash
type SigSchemeRSASSA SchemeHash
type SigSchemeRSAPSS SchemeHash
type SigSchemeECDSA SchemeHash
type SigSchemeSM2 SchemeHash
type SigSchemeECSCHNORR SchemeHash
type EncSchemeOAEP SchemeHash
type SchemeMGF1 SchemeHash
type SchemeKDF1_SP800_56A SchemeHash
type SchemeKDF2 SchemeHash
type SchemeKDF1_SP800_108 SchemeHash

type SchemeECDAA struct {
	HashAlg AlgorithmId
	Count   uint16
}
type SigSchemeECDAA SchemeECDAA

type Empty struct{}
type EncSchemeRSAES Empty

type ECCPoint struct {
	X, Y ECCParameter
}

type SchemeXOR struct {
	HashAlg AlgorithmId
	KDF     AlgorithmId
}

type KeyedHashScheme struct {
	Scheme  AlgorithmId
	Details SchemeKeyedHashU
}

func (s KeyedHashScheme) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (s KeyedHashScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

type KeyedHashParams struct {
	Scheme KeyedHashScheme
}

type SymDefObject struct {
	Algorithm AlgorithmId
	KeyBits   KeyBitsU
	Mode      SymModeU
}

func (o SymDefObject) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (o SymDefObject) Selector(field reflect.StructField) interface{} {
	return o.Algorithm
}

type SymCipherParams struct {
	Sym SymDefObject
}

type RSAScheme struct {
	Scheme  AlgorithmId
	Details AsymSchemeU
}

func (s RSAScheme) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (s RSAScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

type RSAParams struct {
	Symmetric SymDefObject
	Scheme    RSAScheme
	KeyBits   uint16
	Exponent  uint32
}

type KDFScheme struct {
	Scheme  AlgorithmId
	Details KDFSchemeU
}

func (s KDFScheme) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (s KDFScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

type ECCScheme struct {
	Scheme  AlgorithmId
	Details AsymSchemeU
}

func (s ECCScheme) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (s ECCScheme) Selector(field reflect.StructField) interface{} {
	return s.Scheme
}

type ECCParams struct {
	Symmetric SymDefObject
	Scheme    ECCScheme
	CurveID   ECCCurve
	KDF       KDFScheme
}

type Public struct {
	Type       AlgorithmId
	NameAlg    AlgorithmId
	Attrs      ObjectAttributes
	AuthPolicy Digest
	Params     PublicParamsU
	Unique     PublicIDU
}

func (p Public) StructFlags() StructFlags {
	return StructFlagSized | StructFlagContainsUnion
}

func (p Public) Selector(field reflect.StructField) interface{} {
	switch field.Name {
	case "Params", "Unique":
		return p.Type
	}
	return nil
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

type NVPublic struct {
	Index      Handle
	NameAlg    AlgorithmId
	Attrs      NVAttributes
	AuthPolicy Digest
	Size       uint16
}

func (p NVPublic) StructFlags() StructFlags {
	return StructFlagSized
}

type SensitiveCreate struct {
	UserAuth Auth
	Data     SensitiveData
}

func (s SensitiveCreate) StructFlags() StructFlags {
	return StructFlagSized
}

type Sensitive struct {
	Type      AlgorithmId
	AuthValue Auth
	SeedValue Digest
	Sensitive SensitiveCompositeU
}

func (s Sensitive) StructFlags() StructFlags {
	return StructFlagSized | StructFlagContainsUnion
}

func (s Sensitive) Selector(field reflect.StructField) interface{} {
	return s.Type
}

type CapabilityData struct {
	Capability Capability
	Data       CapabilitiesU
}

func (d CapabilityData) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (d CapabilityData) Selector(field reflect.StructField) interface{} {
	return d.Capability
}

type AlgorithmProperty struct {
	Alg        AlgorithmId
	Properties AlgorithmAttributes
}

type TaggedProperty struct {
	Property Property
	Value    uint32
}

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
	size, known := digestSizes[p.HashAlg]
	if !known {
		return fmt.Errorf("unknown digest size for algorithm %v", p.HashAlg)
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
	size, known := digestSizes[p.HashAlg]
	if !known {
		return fmt.Errorf("unknown digest size for algorithm %d", p.HashAlg)
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

type TaggedPolicy struct {
	Handle     Handle
	PolicyHash TaggedHash
}

type AlgorithmList []AlgorithmId

func (l AlgorithmList) SliceType() SliceType {
	return SliceTypeList
}

type AlgorithmPropertyList []AlgorithmProperty

func (l AlgorithmPropertyList) SliceType() SliceType {
	return SliceTypeList
}

type CommandAttributesList []CommandAttributes

func (l CommandAttributesList) SliceType() SliceType {
	return SliceTypeList
}

type CommandCodeList []CommandCode

func (l CommandCodeList) SliceType() SliceType {
	return SliceTypeList
}

type ECCCurveList []ECCCurve

func (l ECCCurveList) SliceType() SliceType {
	return SliceTypeList
}

type HandleList []Handle

func (l HandleList) SliceType() SliceType {
	return SliceTypeList
}

type PCRSelectionList []PCRSelection

func (l PCRSelectionList) SliceType() SliceType {
	return SliceTypeList
}

type TaggedPolicyList []TaggedPolicy

func (l TaggedPolicyList) SliceType() SliceType {
	return SliceTypeList
}

type TaggedTPMPropertyList []TaggedProperty

func (l TaggedTPMPropertyList) SliceType() SliceType {
	return SliceTypeList
}

type TaggedPCRPropertyList []TaggedPCRSelect

func (l TaggedPCRPropertyList) SliceType() SliceType {
	return SliceTypeList
}

type Resource interface {
	Handle() Handle
}
