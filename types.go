// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"unsafe"
)

// 5.3) Miscellaneous Types
type AlgorithmId uint16
type KeyBits uint16

// 6) Constants
type TPMGenerated uint32
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
	Data interface{}
}

func (c CapabilitiesU) Algorithms() AlgorithmPropertyList {
	return c.Data.(AlgorithmPropertyList)
}

func (c CapabilitiesU) Handles() HandleList {
	return c.Data.(HandleList)
}

func (c CapabilitiesU) Command() CommandAttributesList {
	return c.Data.(CommandAttributesList)
}

func (c CapabilitiesU) PPCommands() CommandCodeList {
	return c.Data.(CommandCodeList)
}

func (c CapabilitiesU) AuditCommands() CommandCodeList {
	return c.Data.(CommandCodeList)
}

func (c CapabilitiesU) AssignedPCR() PCRSelectionList {
	return c.Data.(PCRSelectionList)
}

func (c CapabilitiesU) TPMProperties() TaggedTPMPropertyList {
	return c.Data.(TaggedTPMPropertyList)
}

func (c CapabilitiesU) PCRProperties() TaggedPCRPropertyList {
	return c.Data.(TaggedPCRPropertyList)
}

func (c CapabilitiesU) ECCCurves() ECCCurveList {
	return c.Data.(ECCCurveList)
}

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

type CapabilityData struct {
	Capability Capability
	Data       CapabilitiesU `tpm2:"selector:Capability"`
}

// 10.11 Clock/Counter Structures
type ClockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
}

type TimeInfo struct {
	Time      uint64
	ClockInfo ClockInfo
}

// 10.12 Attestation Structures
type TimeAttestInfo struct {
	Time            TimeInfo
	FirmwareVersion uint64
}

type CertifyInfo struct {
	Name          Name
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

func (a AttestU) Certify() *CertifyInfo {
	return a.Data.(*CertifyInfo)
}

func (a AttestU) Creation() *CreationInfo {
	return a.Data.(*CreationInfo)
}

func (a AttestU) Quote() *QuoteInfo {
	return a.Data.(*QuoteInfo)
}

func (a AttestU) CommandAudit() *CommandAuditInfo {
	return a.Data.(*CommandAuditInfo)
}

func (a AttestU) SessionAudit() *SessionAuditInfo {
	return a.Data.(*SessionAuditInfo)
}

func (a AttestU) Time() *TimeAttestInfo {
	return a.Data.(*TimeAttestInfo)
}

func (a AttestU) NV() *NVCertifyInfo {
	return a.Data.(*NVCertifyInfo)
}

type Attest struct {
	Magic           TPMGenerated
	Type            StructTag
	QualifiedSigner Name
	ExtraData       Data
	ClockInfo       ClockInfo
	FirmwareVersion uint64
	Attest          AttestU `tpm2:"selector:Type"`
}

type AttestRaw []byte

func (a AttestRaw) ToStruct() (*Attest, error) {
	var out Attest
	if _, err := UnmarshalFromBytes(a, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// 11) Algorithm Parameters and Structures

// 11.1) Symmetric
type AESKeyBits KeyBits
type SM4KeyBits KeyBits
type CamelliaKeyBits KeyBits

type SymKeyBitsU struct {
	Data interface{}
}

func (b SymKeyBitsU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmAES:
		return reflect.TypeOf(AESKeyBits(0)), nil
	case AlgorithmXOR:
		return reflect.TypeOf(AlgorithmId(0)), nil
	case AlgorithmNull:
		return nil, nil
	case AlgorithmSM4:
		return reflect.TypeOf(SM4KeyBits(0)), nil
	case AlgorithmCamellia:
		return reflect.TypeOf(CamelliaKeyBits(0)), nil
	}
	return reflect.TypeOf(KeyBits(0)), nil
}

func (b SymKeyBitsU) AES() AESKeyBits {
	return b.Data.(AESKeyBits)
}

func (b SymKeyBitsU) SM4() SM4KeyBits {
	return b.Data.(SM4KeyBits)
}

func (b SymKeyBitsU) Camellia() CamelliaKeyBits {
	return b.Data.(CamelliaKeyBits)
}

func (b SymKeyBitsU) Sym() KeyBits {
	return reflect.ValueOf(b.Data).Convert(reflect.TypeOf(KeyBits(0))).Interface().(KeyBits)
}

func (b SymKeyBitsU) XOR() AlgorithmId {
	return b.Data.(AlgorithmId)
}

type SymModeU struct {
	Data interface{}
}

func (m SymModeU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(AlgorithmId) {
	case AlgorithmXOR:
		fallthrough
	case AlgorithmNull:
		return nil, nil
	}
	return reflect.TypeOf(AlgorithmId(0)), nil
}

func (m SymModeU) AES() AlgorithmId {
	return m.Data.(AlgorithmId)
}

func (m SymModeU) SM4() AlgorithmId {
	return m.Data.(AlgorithmId)
}

func (m SymModeU) Camellia() AlgorithmId {
	return m.Data.(AlgorithmId)
}

func (m SymModeU) Sym() AlgorithmId {
	return m.Data.(AlgorithmId)
}

type SymDef struct {
	Algorithm AlgorithmId
	KeyBits   SymKeyBitsU `tpm2:"selector:Algorithm"`
	Mode      SymModeU    `tpm2:"selector:Algorithm"`
}

type SymDefObject struct {
	Algorithm AlgorithmId
	KeyBits   SymKeyBitsU `tpm2:"selector:Algorithm"`
	Mode      SymModeU    `tpm2:"selector:Algorithm"`
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

type sensitiveCreateSized struct {
	Ptr *SensitiveCreate `tpm2:"sized"`
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

func (d SchemeKeyedHashU) HMAC() *SchemeHMAC {
	return d.Data.(*SchemeHMAC)
}

func (d SchemeKeyedHashU) XOR() *SchemeXOR {
	return d.Data.(*SchemeXOR)
}

type KeyedHashScheme struct {
	Scheme  AlgorithmId
	Details SchemeKeyedHashU `tpm2:"selector:Scheme"`
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

func (s SigSchemeU) RSASSA() *SigSchemeRSASSA {
	return s.Data.(*SigSchemeRSASSA)
}

func (s SigSchemeU) RSAPSS() *SigSchemeRSAPSS {
	return s.Data.(*SigSchemeRSAPSS)
}

func (s SigSchemeU) ECDSA() *SigSchemeECDSA {
	return s.Data.(*SigSchemeECDSA)
}

func (s SigSchemeU) ECDAA() *SigSchemeECDAA {
	return s.Data.(*SigSchemeECDAA)
}

func (s SigSchemeU) SM2() *SigSchemeSM2 {
	return s.Data.(*SigSchemeSM2)
}

func (s SigSchemeU) ECSCHNORR() *SigSchemeECSCHNORR {
	return s.Data.(*SigSchemeECSCHNORR)
}

func (s SigSchemeU) HMAC() *SchemeHMAC {
	return s.Data.(*SchemeHMAC)
}

func (s SigSchemeU) Any() *SchemeHash {
	return (*SchemeHash)(unsafe.Pointer(reflect.ValueOf(s.Data).Pointer()))
}

type SigScheme struct {
	Scheme AlgorithmId
}

// 11.2.3 Key Derivation Schemes
type SchemeMGF1 SchemeHash
type SchemeKDF1_SP800_56A SchemeHash
type SchemeKDF2 SchemeHash
type SchemeKDF1_SP800_108 SchemeHash

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

func (s KDFSchemeU) MGF1() *SchemeMGF1 {
	return s.Data.(*SchemeMGF1)
}

func (s KDFSchemeU) KDF1_SP800_56A() *SchemeKDF1_SP800_56A {
	return s.Data.(*SchemeKDF1_SP800_56A)
}

func (s KDFSchemeU) KDF2() *SchemeKDF2 {
	return s.Data.(*SchemeKDF2)
}

func (s KDFSchemeU) KDF1_SP800_108() *SchemeKDF1_SP800_108 {
	return s.Data.(*SchemeKDF1_SP800_108)
}

type KDFScheme struct {
	Scheme  AlgorithmId
	Details KDFSchemeU `tpm2:"selector:Scheme"`
}

type KeySchemeECDH SchemeHash
type KeySchemeECMQV SchemeHash
type EncSchemeRSAES Empty
type EncSchemeOAEP SchemeHash

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

func (s AsymSchemeU) ECDH() *KeySchemeECDH {
	return s.Data.(*KeySchemeECDH)
}

func (s AsymSchemeU) ECMQV() *KeySchemeECMQV {
	return s.Data.(*KeySchemeECMQV)
}

func (s AsymSchemeU) RSASSA() *SigSchemeRSASSA {
	return s.Data.(*SigSchemeRSASSA)
}

func (s AsymSchemeU) RSAPSS() *SigSchemeRSAPSS {
	return s.Data.(*SigSchemeRSAPSS)
}

func (s AsymSchemeU) ECDSA() *SigSchemeECDSA {
	return s.Data.(*SigSchemeECDSA)
}

func (s AsymSchemeU) ECDAA() *SigSchemeECDAA {
	return s.Data.(*SigSchemeECDAA)
}

func (s AsymSchemeU) SM2() *SigSchemeSM2 {
	return s.Data.(*SigSchemeSM2)
}

func (s AsymSchemeU) ECSCHNORR() *SigSchemeECSCHNORR {
	return s.Data.(*SigSchemeECSCHNORR)
}

func (s AsymSchemeU) RSAES() *EncSchemeRSAES {
	return s.Data.(*EncSchemeRSAES)
}

func (s AsymSchemeU) OAEP() *EncSchemeOAEP {
	return s.Data.(*EncSchemeOAEP)
}

func (s AsymSchemeU) Any() *SchemeHash {
	return (*SchemeHash)(unsafe.Pointer(reflect.ValueOf(s.Data).Pointer()))
}

type AsymScheme struct {
	Scheme  AlgorithmId
	Details AsymSchemeU `tpm2:"selector:Scheme"`
}

// 11.2.4 RSA
type RSAScheme struct {
	Scheme  AlgorithmId
	Details AsymSchemeU `tpm2:"selector:Scheme"`
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
	Details AsymSchemeU `tpm2:"selector:Scheme"`
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

func (s SignatureU) RSASSA() *SignatureRSASSA {
	return s.Data.(*SignatureRSASSA)
}

func (s SignatureU) RSAPSS() *SignatureRSAPSS {
	return s.Data.(*SignatureRSAPSS)
}

func (s SignatureU) ECDSA() *SignatureECDSA {
	return s.Data.(*SignatureECDSA)
}

func (s SignatureU) ECDAA() *SignatureECDAA {
	return s.Data.(*SignatureECDAA)
}

func (s SignatureU) SM2() *SignatureSM2 {
	return s.Data.(*SignatureSM2)
}

func (s SignatureU) ECSCHNORR() *SignatureECSCHNORR {
	return s.Data.(*SignatureECSCHNORR)
}

func (s SignatureU) HMAC() *TaggedHash {
	return s.Data.(*TaggedHash)
}

func (s SignatureU) Any() *SchemeHash {
	return (*SchemeHash)(unsafe.Pointer(reflect.ValueOf(s.Data).Pointer()))
}

type Signature struct {
	SigAlg    AlgorithmId
	Signature SignatureU `tpm2:"selector:SigAlg"`
}

// 11.4) Key/Secret Exchange
type EncryptedSecret []byte

// 12) Key/Object Complex

// 12.2) Public Area Structures
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

func (p PublicIDU) KeyedHash() Digest {
	return p.Data.(Digest)
}

func (p PublicIDU) Sym() Digest {
	return p.Data.(Digest)
}

func (p PublicIDU) RSA() PublicKeyRSA {
	return p.Data.(PublicKeyRSA)
}

func (p PublicIDU) ECC() *ECCPoint {
	return p.Data.(*ECCPoint)
}

type KeyedHashParams struct {
	Scheme KeyedHashScheme
}

type AsymParams struct {
	Symmetric SymDefObject
	Scheme    AsymScheme
}

type RSAParams struct {
	Symmetric SymDefObject
	Scheme    RSAScheme
	KeyBits   KeyBits
	Exponent  uint32
}

type ECCParams struct {
	Symmetric SymDefObject
	Scheme    ECCScheme
	CurveID   ECCCurve
	KDF       KDFScheme
}

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

func (p PublicParamsU) KeyedHashDetail() *KeyedHashParams {
	return p.Data.(*KeyedHashParams)
}

func (p PublicParamsU) SymDetail() *SymCipherParams {
	return p.Data.(*SymCipherParams)
}

func (p PublicParamsU) RSADetail() *RSAParams {
	return p.Data.(*RSAParams)
}

func (p PublicParamsU) ECCDetail() *ECCParams {
	return p.Data.(*ECCParams)
}

func (p PublicParamsU) AsymDetail() *AsymParams {
	panic("not implemented")
	return nil
}

type Public struct {
	Type       AlgorithmId
	NameAlg    AlgorithmId
	Attrs      ObjectAttributes
	AuthPolicy Digest
	Params     PublicParamsU `tpm2:"selector:Type"`
	Unique     PublicIDU     `tpm2:"selector:Type"`
}

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

type publicSized struct {
	Ptr *Public `tpm2:"sized"`
}

// 12.3) Private Area Structures
type PrivateVendorSpecific []byte

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

func (s SensitiveCompositeU) RSA() PrivateKeyRSA {
	return s.Data.(PrivateKeyRSA)
}

func (s SensitiveCompositeU) ECC() ECCParameter {
	return s.Data.(ECCParameter)
}

func (s SensitiveCompositeU) Bits() SensitiveData {
	return s.Data.(SensitiveData)
}

func (s SensitiveCompositeU) Sym() SymKey {
	return s.Data.(SymKey)
}

func (s SensitiveCompositeU) Any() PrivateVendorSpecific {
	return reflect.ValueOf(s.Data).Convert(reflect.TypeOf((PrivateVendorSpecific)(nil))).Interface().(PrivateVendorSpecific)
}

type Sensitive struct {
	Type      AlgorithmId
	AuthValue Auth
	SeedValue Digest
	Sensitive SensitiveCompositeU `tpm2:"selector:Type"`
}

type sensitiveSized struct {
	Ptr *Sensitive `tpm2:"sized"`
}

type Private []byte

// 12.4) Identity Object
type IDObject struct {
	IntegrityHMAC Digest
	EncIdentity   Digest
}

// TPMS_ID_OBJECT.encIdentity is fully encrypted, including the 2-byte size field. The marshalling code does
// not know how to handle this struct on its own
func (i *IDObject) Marshal(buf io.Writer) error {
	return errors.New("IDObject cannot be marshalled")
}

func (i *IDObject) Unmarshal(buf io.Reader) error {
	var integSize uint16
	if err := binary.Read(buf, binary.BigEndian, &integSize); err != nil {
		return fmt.Errorf("cannot read size of integrityHMAC: %v", err)
	}

	i.IntegrityHMAC = make(Digest, integSize)
	if _, err := io.ReadFull(buf, i.IntegrityHMAC); err != nil {
		return fmt.Errorf("cannot read integrityHMAC: %v", err)
	}

	// This structure should only be unmarshalled from IDObjectRaw.ToStruct(). Consume the rest of the bytes.
	encIdentity, err := ioutil.ReadAll(buf)
	if err != nil {
		return fmt.Errorf("cannot read encIdentity: %v", err)
	}
	i.EncIdentity = encIdentity
	return nil
}

type IDObjectRaw []byte

func (i IDObjectRaw) ToStruct() (*IDObject, error) {
	var out IDObject
	if _, err := UnmarshalFromBytes(i, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

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

type creationDataSized struct {
	Ptr *CreationData `tpm2:"sized"`
}
