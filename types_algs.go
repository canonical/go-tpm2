// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"reflect"
	"unsafe"

	"github.com/canonical/go-tpm2/internal/union"
)

// This file contains types defined in section 11 (Algorithm Parameters
// and Structures) in part 2 of the library spec.

// 11.1) Symmetric

type SymKeyBitsUnionConstraint interface {
	uint16 | HashAlgorithmId | Empty
}

// SymKeyBitsUnion is a union type that corresponds to the TPMU_SYM_KEY_BITS type and is used to
// specify symmetric encryption key sizes. It stores a pointer to the underlying value. The selector
// type is [AlgorithmId]. The selector value [AlgorithmNull] is mapped to an empty value.
type SymKeyBitsUnion struct {
	contents union.Contents
}

// MakeSymKeyBitsUnion returns a SymKeyBitsUnion that contains the supplied value.
func MakeSymKeyBitsUnion[T SymKeyBitsUnionConstraint](contents T) SymKeyBitsUnion {
	return SymKeyBitsUnion{contents: union.NewContents(contents)}
}

// AES returns the value associated with selector value [AlgorithmAES]. It will panic if
// the underlying type is not uint16.
func (b SymKeyBitsUnion) AES() uint16 {
	return union.ContentsElem[uint16](b.contents)
}

// SM4 returns the value associated with selector value [AlgorithmSM4]. It will panic if
// the underlying type is not uint16.
func (b SymKeyBitsUnion) SM4() uint16 {
	return union.ContentsElem[uint16](b.contents)
}

// Camellia returns the value associated with selector value [AlgorithmCamellia]. It will panic if
// the underlying type is not uint16.
func (b SymKeyBitsUnion) Camellia() uint16 {
	return union.ContentsElem[uint16](b.contents)
}

// XOR returns the value associated with selector value [AlgorithmXOR]. It will panic if
// the underlying type is not HashAlgorithmId.
func (b SymKeyBitsUnion) XOR() HashAlgorithmId {
	return union.ContentsElem[HashAlgorithmId](b.contents)
}

// Sym returns the value associated with selector values [AlgorithmAES],
// [AlgorithmSM4] and [AlgorithmCamellia]. It will panic if the underlying type is not
// uint16.
func (b SymKeyBitsUnion) Sym() uint16 {
	return union.ContentsElem[uint16](b.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (b SymKeyBitsUnion) SelectMarshal(selector any) any {
	switch reflect.ValueOf(selector).Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES, AlgorithmSM4, AlgorithmCamellia:
		return union.ContentsMarshal[uint16](b.contents)
	case AlgorithmXOR:
		return union.ContentsMarshal[HashAlgorithmId](b.contents)
	case AlgorithmNull:
		return union.ContentsMarshal[Empty](b.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (b *SymKeyBitsUnion) SelectUnmarshal(selector any) any {
	switch reflect.ValueOf(selector).Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES, AlgorithmSM4, AlgorithmCamellia:
		return union.ContentsUnmarshal[uint16](&b.contents)
	case AlgorithmXOR:
		return union.ContentsUnmarshal[HashAlgorithmId](&b.contents)
	case AlgorithmNull:
		return union.ContentsUnmarshal[Empty](&b.contents)
	default:
		return nil
	}
}

type SymModeUnionConstraint interface {
	SymModeId | Empty
}

// SymModeUnion is a union type that corresponds to the TPMU_SYM_MODE type. It stores a pointer
// to the underlying value. The selector type is [AlgorithmId]. The selector values [AlgorithmXOR]
// and [AlgorithmNull] are mapped to an empty value.
type SymModeUnion struct {
	contents union.Contents
}

// MakeSymModeUnion returns a SymModeUnion that contains the supplied value.
func MakeSymModeUnion[T SymModeUnionConstraint](contents T) SymModeUnion {
	return SymModeUnion{contents: union.NewContents(contents)}
}

// AES returns the value associated with selector value [AlgorithmAES]. It will panic if
// the underlying type is not SymModeId.
func (m SymModeUnion) AES() SymModeId {
	return union.ContentsElem[SymModeId](m.contents)
}

// SM4 returns the value associated with selector value [AlgorithmSM4]. It will panic if
// the underlying type is not SymModeId.
func (m SymModeUnion) SM4() SymModeId {
	return union.ContentsElem[SymModeId](m.contents)
}

// Camellia returns the value associated with selector value [AlgorithmCamellia]. It will
// panic if the underlying type is not SymModeId.
func (m SymModeUnion) Camellia() SymModeId {
	return union.ContentsElem[SymModeId](m.contents)
}

// Sym returns the value associated with selector values [AlgorithmAES], [AlgorithmSM4] and
// [AlgorithmCamellia].  It will panic if the underlying type is not SymModeId.
func (m SymModeUnion) Sym() SymModeId {
	return union.ContentsElem[SymModeId](m.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (m SymModeUnion) SelectMarshal(selector any) any {
	switch reflect.ValueOf(selector).Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES, AlgorithmSM4, AlgorithmCamellia:
		return union.ContentsMarshal[SymModeId](m.contents)
	case AlgorithmXOR, AlgorithmNull:
		return union.ContentsMarshal[Empty](m.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (m *SymModeUnion) SelectUnmarshal(selector any) any {
	switch reflect.ValueOf(selector).Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES, AlgorithmSM4, AlgorithmCamellia:
		return union.ContentsUnmarshal[SymModeId](&m.contents)
	case AlgorithmXOR, AlgorithmNull:
		return union.ContentsUnmarshal[Empty](&m.contents)
	default:
		return nil
	}
}

// SymDef corresponds to the TPMT_SYM_DEF type, and is used to select the algorithm
// used for parameter encryption.
type SymDef struct {
	Algorithm SymAlgorithmId  // Symmetric algorithm
	KeyBits   SymKeyBitsUnion // Symmetric key size
	Mode      SymModeUnion    // Symmetric mode
}

// SymDefObject corresponds to the TPMT_SYM_DEF_OBJECT type, and is used to define an
// object's symmetric algorithm.
type SymDefObject struct {
	Algorithm SymObjectAlgorithmId // Symmetric algorithm
	KeyBits   SymKeyBitsUnion      // Symmetric key size
	Mode      SymModeUnion         // Symmetric mode
}

// SymKey corresponds to the TPM2B_SYM_KEY type.
type SymKey []byte

// SymCipherParams corresponds to the TPMS_SYMCIPHER_PARMS type, and contains the
// parameters for a symmetric object.
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

// SensitiveCreate corresponds to the TPMS_SENSITIVE_CREATE type and is used to define
// the values to be placed in the sensitive area of a created object.
type SensitiveCreate struct {
	UserAuth Auth          // Authorization value
	Data     SensitiveData // Secret data
}

// SensitiveData corresponds to the TPM2B_SENSITIVE_DATA type.
type SensitiveData []byte

// SchemeHash corresponds to the TPMS_SCHEME_HASH type, and is used for schemes that only
// require a hash algorithm to complete their definition.
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

const (
	KeyedHashSchemeHMAC KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmHMAC) // TPM_ALG_HMAC
	KeyedHashSchemeXOR  KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmXOR)  // TPM_ALG_XOR
	KeyedHashSchemeNull KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmNull) // TPM_ALG_NULL
)

// SchemeHMAC corresponds to the TPMS_SCHEME_HMAC type.
type SchemeHMAC = SchemeHash

// SchemeXOR corresponds to the TPMS_SCHEME_XOR type, and is used to define the XOR encryption
// scheme.
type SchemeXOR struct {
	HashAlg HashAlgorithmId // Hash algorithm used to digest the message
	KDF     KDFAlgorithmId  // Hash algorithm used for the KDF
}

type SchemeKeyedHashUnionConstraint interface {
	SchemeHMAC | SchemeXOR | Empty
}

// SchemeKeyedHashUnion is a union type that corresponds to the TPMU_SCHEME_KEYED_HASH type.
// It stores a pointer to the underlying value. The selector type is [KeyedHashSchemeId]. The
// selector value [KeyedHashSchemeNull] is mapped to an empty value.
type SchemeKeyedHashUnion struct {
	contents union.Contents
}

// MakeSchemeKeyedHashUnion returns a SchemeKeyedHashUnion that contains the supplied value.
func MakeSchemeKeyedHashUnion[T SchemeKeyedHashUnionConstraint](contents T) SchemeKeyedHashUnion {
	return SchemeKeyedHashUnion{contents: union.NewContents(contents)}
}

// HMAC returns a pointer to the value associated with the selector value [KeyedHashSchemeHMAC].
// It panics if the underlying type is not SchemeHMAC.
func (d SchemeKeyedHashUnion) HMAC() *SchemeHMAC {
	return union.ContentsPtr[SchemeHMAC](d.contents)
}

// XOR returns a pointer to the value associated with the selector value [KeyedHashSchemeXOR].
// It panics if the underlying type is not SchemeXOR.
func (d SchemeKeyedHashUnion) XOR() *SchemeXOR {
	return union.ContentsPtr[SchemeXOR](d.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (d SchemeKeyedHashUnion) SelectMarshal(selector any) any {
	switch selector.(KeyedHashSchemeId) {
	case KeyedHashSchemeHMAC:
		return union.ContentsMarshal[SchemeHMAC](d.contents)
	case KeyedHashSchemeXOR:
		return union.ContentsMarshal[SchemeXOR](d.contents)
	case KeyedHashSchemeNull:
		return union.ContentsMarshal[Empty](d.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (d *SchemeKeyedHashUnion) SelectUnmarshal(selector any) any {
	switch selector.(KeyedHashSchemeId) {
	case KeyedHashSchemeHMAC:
		return union.ContentsUnmarshal[SchemeHMAC](&d.contents)
	case KeyedHashSchemeXOR:
		return union.ContentsUnmarshal[SchemeXOR](&d.contents)
	case KeyedHashSchemeNull:
		return union.ContentsUnmarshal[Empty](&d.contents)
	default:
		return nil
	}
}

// KeyedHashScheme corresponds to the TPMT_KEYEDHASH_SCHEME type.
type KeyedHashScheme struct {
	Scheme  KeyedHashSchemeId    // Scheme selector
	Details SchemeKeyedHashUnion // Scheme specific parameters
}

// 11.2 Assymetric

// 11.2.1 Signing Schemes

type SigSchemeRSASSA = SchemeHash
type SigSchemeRSAPSS = SchemeHash
type SigSchemeECDSA = SchemeHash
type SigSchemeECDAA = SchemeECDAA
type SigSchemeSM2 = SchemeHash
type SigSchemeECSchnorr = SchemeHash

type SigSchemeUnionConstraint interface {
	SchemeHash | SchemeECDAA | Empty
}

// SigSchemeUnion is a union type that corresponds to the TPMU_SIG_SCHEME type. It stores
// a pointer to the underlying value. The selector type is [SigSchemeId]. The selector value
// [SigSchemeAlgNull] is mapped to an empty value.
type SigSchemeUnion struct {
	contents union.Contents
}

// MakeSigSchemeUnion returns a SigSchemeUnion that contains the supplied value.
func MakeSigSchemeUnion[T SigSchemeUnionConstraint](contents T) SigSchemeUnion {
	return SigSchemeUnion{contents: union.NewContents(contents)}
}

// RSASSA returns a pointer to the value associated with the selector value [SigSchemeAlgRSASSA].
// It will panic if the underlying type is not SigSchemeRSASSA.
func (s SigSchemeUnion) RSASSA() *SigSchemeRSASSA {
	return union.ContentsPtr[SigSchemeRSASSA](s.contents)
}

// RSAPSS returns a pointer to the value associated with the selector value [SigSchemeAlgRSAPSS].
// It will panic if the underlying type is not SigSchemeRSAPSS.
func (s SigSchemeUnion) RSAPSS() *SigSchemeRSAPSS {
	return union.ContentsPtr[SigSchemeRSAPSS](s.contents)
}

// ECDSA returns a pointer to the value associated with the selector value [SigSchemeAlgECDSA].
// It will panic if the underlying type is not SigSchemeECDSA.
func (s SigSchemeUnion) ECDSA() *SigSchemeECDSA {
	return union.ContentsPtr[SigSchemeECDSA](s.contents)
}

// ECDAA returns a pointer to the value associated with the selector value [SigSchemeAlgECDAA].
// It will panic if the underlying type is not SigSchemeECDAA.
func (s SigSchemeUnion) ECDAA() *SigSchemeECDAA {
	return union.ContentsPtr[SigSchemeECDAA](s.contents)
}

// SM2 returns a pointer to the value associated with the selector value [SigSchemeAlgSM2].
// It will panic if the underlying type is not SigSchemeSM2.
func (s SigSchemeUnion) SM2() *SigSchemeSM2 {
	return union.ContentsPtr[SigSchemeSM2](s.contents)
}

// ECSchnorr returns a pointer to the value associated with the selector value [SigSchemeAlgECSchnorr].
// It will panic if the underlying type is not SigSchemeECSchnorr.
func (s SigSchemeUnion) ECSchnorr() *SigSchemeECSchnorr {
	return union.ContentsPtr[SigSchemeECSchnorr](s.contents)
}

// HMAC returns a pointer to the value associated with the selector value [SigSchemeAlgHMAC].
// It will panic if the underlying type is not SchemeHMAC.
func (s SigSchemeUnion) HMAC() *SchemeHMAC {
	return union.ContentsPtr[SchemeHMAC](s.contents)
}

// Any returns the signature scheme as a *SchemeHash. It will panic if the underlying type
// is not a superset this.
func (s *SigSchemeUnion) Any() *SchemeHash {
	switch {
	case union.ContentsIs[SchemeHash](s.contents):
		return union.ContentsPtr[SchemeHash](s.contents)
	case union.ContentsIs[SigSchemeECDAA](s.contents):
		scheme := union.ContentsPtr[SigSchemeECDAA](s.contents)
		return *(**SchemeHash)(unsafe.Pointer(&scheme))
	default:
		panic("invalid type")
	}
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (s SigSchemeUnion) SelectMarshal(selector any) any {
	switch selector.(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return union.ContentsMarshal[SigSchemeRSASSA](s.contents)
	case SigSchemeAlgRSAPSS:
		return union.ContentsMarshal[SigSchemeRSAPSS](s.contents)
	case SigSchemeAlgECDSA:
		return union.ContentsMarshal[SigSchemeECDSA](s.contents)
	case SigSchemeAlgECDAA:
		return union.ContentsMarshal[SigSchemeECDAA](s.contents)
	case SigSchemeAlgSM2:
		return union.ContentsMarshal[SigSchemeSM2](s.contents)
	case SigSchemeAlgECSchnorr:
		return union.ContentsMarshal[SigSchemeECSchnorr](s.contents)
	case SigSchemeAlgHMAC:
		return union.ContentsMarshal[SchemeHMAC](s.contents)
	case SigSchemeAlgNull:
		return union.ContentsMarshal[Empty](s.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (s *SigSchemeUnion) SelectUnmarshal(selector any) any {
	switch selector.(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return union.ContentsUnmarshal[SigSchemeRSASSA](&s.contents)
	case SigSchemeAlgRSAPSS:
		return union.ContentsUnmarshal[SigSchemeRSAPSS](&s.contents)
	case SigSchemeAlgECDSA:
		return union.ContentsUnmarshal[SigSchemeECDSA](&s.contents)
	case SigSchemeAlgECDAA:
		return union.ContentsUnmarshal[SigSchemeECDAA](&s.contents)
	case SigSchemeAlgSM2:
		return union.ContentsUnmarshal[SigSchemeSM2](&s.contents)
	case SigSchemeAlgECSchnorr:
		return union.ContentsUnmarshal[SigSchemeECSchnorr](&s.contents)
	case SigSchemeAlgHMAC:
		return union.ContentsUnmarshal[SchemeHMAC](&s.contents)
	case SigSchemeAlgNull:
		return union.ContentsUnmarshal[Empty](&s.contents)
	default:
		return nil
	}
}

// SigScheme corresponds to the TPMT_SIG_SCHEME type.
type SigScheme struct {
	Scheme  SigSchemeId    // Scheme selector
	Details SigSchemeUnion // Scheme specific parameters
}

// 11.2.2 Encryption Schemes

type EncSchemeRSAES = Empty
type EncSchemeOAEP = SchemeHash

type KeySchemeECDH = SchemeHash
type KeySchemeECMQV = SchemeHash

// 11.2.3 Key Derivation Schemes

type SchemeMGF1 = SchemeHash
type SchemeKDF1_SP800_56A = SchemeHash
type SchemeKDF2 = SchemeHash
type SchemeKDF1_SP800_108 = SchemeHash

type KDFSchemeUnionConstraint interface {
	SchemeHash | Empty
}

// KDFSchemeUnion is a union type that corresponds to the TPMU_KDF_SCHEME type. It
// stores a pointer to the underlying value. The selector type is [KDFAlgorithmId]. The
// selector value [KDFAlgorithmNull] is mapped to an empty value.
type KDFSchemeUnion struct {
	contents union.Contents
}

// MakeKDFSchemeUnion returns a KDFSchemeUnion that contains the supplied value.
func MakeKDFSchemeUnion[T KDFSchemeUnionConstraint](contents T) KDFSchemeUnion {
	return KDFSchemeUnion{contents: union.NewContents(contents)}
}

// MGF1 returns a pointer to the value associated with the selector value [KDFAlgorithmMGF1].
// It will panic if the underlying type is not SchemeMGF1.
func (s KDFSchemeUnion) MGF1() *SchemeMGF1 {
	return union.ContentsPtr[SchemeMGF1](s.contents)
}

// KDF1_SP800_56A returns a pointer to the value associated with the selector value [KDFAlgorithmKDF1_SP800_56A].
// It will panic if the underlying type is not SchemeKDF1_SP800_56A.
func (s KDFSchemeUnion) KDF1_SP800_56A() *SchemeKDF1_SP800_56A {
	return union.ContentsPtr[SchemeKDF1_SP800_56A](s.contents)
}

// KDF2 returns a pointer to the value associated with the selector value [KDFAlgorithmKDF2].
// It will panic if the underlying type is not SchemeKDF2.
func (s KDFSchemeUnion) KDF2() *SchemeKDF2 {
	return union.ContentsPtr[SchemeKDF2](s.contents)
}

// KDF1_SP800_108 returns a pointer to the value associated with the selector value [KDFAlgorithmKDF1_SP800_108].
// It will panic if the underlying type is not SchemeKDF1_SP800_108.
func (s KDFSchemeUnion) KDF1_SP800_108() *SchemeKDF1_SP800_108 {
	return union.ContentsPtr[SchemeKDF1_SP800_108](s.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (s KDFSchemeUnion) SelectMarshal(selector any) any {
	switch selector.(KDFAlgorithmId) {
	case KDFAlgorithmMGF1:
		return union.ContentsMarshal[SchemeMGF1](s.contents)
	case KDFAlgorithmKDF1_SP800_56A:
		return union.ContentsMarshal[SchemeKDF1_SP800_56A](s.contents)
	case KDFAlgorithmKDF2:
		return union.ContentsMarshal[SchemeKDF2](s.contents)
	case KDFAlgorithmKDF1_SP800_108:
		return union.ContentsMarshal[SchemeKDF1_SP800_108](s.contents)
	case KDFAlgorithmNull:
		return union.ContentsMarshal[Empty](s.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (s *KDFSchemeUnion) SelectUnmarshal(selector any) any {
	switch selector.(KDFAlgorithmId) {
	case KDFAlgorithmMGF1:
		return union.ContentsUnmarshal[SchemeMGF1](&s.contents)
	case KDFAlgorithmKDF1_SP800_56A:
		return union.ContentsUnmarshal[SchemeKDF1_SP800_56A](&s.contents)
	case KDFAlgorithmKDF2:
		return union.ContentsUnmarshal[SchemeKDF2](&s.contents)
	case KDFAlgorithmKDF1_SP800_108:
		return union.ContentsUnmarshal[SchemeKDF1_SP800_108](&s.contents)
	case KDFAlgorithmNull:
		return union.ContentsUnmarshal[Empty](&s.contents)
	default:
		return nil
	}
}

// KDFScheme corresponds to the TPMT_KDF_SCHEME type.
type KDFScheme struct {
	Scheme  KDFAlgorithmId // Scheme selector
	Details KDFSchemeUnion // Scheme specific parameters.
}

// AsymSchemeId corresponds to the TPMI_ALG_ASYM_SCHEME type
type AsymSchemeId AlgorithmId

// IsValid determines if the scheme is a valid asymmetric scheme.
func (s AsymSchemeId) IsValid() bool {
	switch s {
	case AsymSchemeRSASSA:
	case AsymSchemeRSAES:
	case AsymSchemeRSAPSS:
	case AsymSchemeOAEP:
	case AsymSchemeECDSA:
	case AsymSchemeECDH:
	case AsymSchemeECDAA:
	case AsymSchemeSM2:
	case AsymSchemeECSchnorr:
	case AsymSchemeECMQV:
	default:
		return false
	}
	return true
}

// HasDigest determines if the asymmetric scheme is associated with
// a digest algorithm.
func (s AsymSchemeId) HasDigest() bool {
	switch s {
	case AsymSchemeRSASSA:
	case AsymSchemeRSAPSS:
	case AsymSchemeOAEP:
	case AsymSchemeECDSA:
	case AsymSchemeECDH:
	case AsymSchemeECDAA:
	case AsymSchemeSM2:
	case AsymSchemeECSchnorr:
	case AsymSchemeECMQV:
	default:
		return false
	}
	return true
}

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
	AsymSchemeECSchnorr AsymSchemeId = AsymSchemeId(AlgorithmECSchnorr) // TPM_ALG_ECSCHNORR
	AsymSchemeECMQV     AsymSchemeId = AsymSchemeId(AlgorithmECMQV)     // TPM_ALG_ECMQV
)

type AsymSchemeUnionConstraint interface {
	SchemeHash | Empty | SchemeECDAA
}

// AsymSchemeUnion is a union type that corresponds to the TPMU_ASYM_SCHEME type. It stores
// a pointer to the underlying value. The selector type is [AsymSchemeId]. The selector value
// [AsymSchemeNull] is mapped to an empty value.
type AsymSchemeUnion struct {
	contents union.Contents
}

// MakeAsymSchemeUnion returns a AsymSchemeUnion that contains the supplied value.
func MakeAsymSchemeUnion[T AsymSchemeUnionConstraint](contents T) AsymSchemeUnion {
	return AsymSchemeUnion{contents: union.NewContents(contents)}
}

// RSASSA returns a pointer to the value associated with the selector value [AsymSchemeRSASSA].
// It will panic if the underlying type is not SigSchemeRSASSA.
func (s AsymSchemeUnion) RSASSA() *SigSchemeRSASSA {
	return union.ContentsPtr[SigSchemeRSASSA](s.contents)
}

// RSAES returns a pointer to the value associated with the selector value [AsymSchemeRSAES].
// It will panic if the underlying type is not EncSchemeRSAES.
func (s AsymSchemeUnion) RSAES() *EncSchemeRSAES {
	return union.ContentsPtr[EncSchemeRSAES](s.contents)
}

// RSAPSS returns a pointer to the value associated with the selector value [AsymSchemeRSAPSS].
// It will panic if the underlying type is not SigSchemeRSAPSS.
func (s AsymSchemeUnion) RSAPSS() *SigSchemeRSAPSS {
	return union.ContentsPtr[SigSchemeRSAPSS](s.contents)
}

// OAEP returns a pointer to the value associated with the selector value [AsymSchemeOAEP].
// It will panic if the underlying type is not EncSchemeOAEP.
func (s AsymSchemeUnion) OAEP() *EncSchemeOAEP {
	return union.ContentsPtr[EncSchemeOAEP](s.contents)
}

// ECDSA returns a pointer to the value associated with the selector value [AsymSchemeECDSA].
// It will panic if the underlying type is not SigSchemeECDSA.
func (s AsymSchemeUnion) ECDSA() *SigSchemeECDSA {
	return union.ContentsPtr[SigSchemeECDSA](s.contents)
}

// ECDH returns a pointer to the value associated with the selector value [AsymSchemeECDH].
// It will panic if the underlying type is not KeySchemeECDH.
func (s AsymSchemeUnion) ECDH() *KeySchemeECDH {
	return union.ContentsPtr[KeySchemeECDH](s.contents)
}

// ECDAA returns a pointer to the value associated with the selector value [AsymSchemeECDAA].
// It will panic if the underlying type is not SigSchemeECDAA.
func (s AsymSchemeUnion) ECDAA() *SigSchemeECDAA {
	return union.ContentsPtr[SigSchemeECDAA](s.contents)
}

// SM2 returns a pointer to the value associated with the selector value [AsymSchemeSM2].
// It will panic if the underlying type is not SigSchemeSM2.
func (s AsymSchemeUnion) SM2() *SigSchemeSM2 {
	return union.ContentsPtr[SigSchemeSM2](s.contents)
}

// ECSchnorr returns a pointer to the value associated with the selector value [AsymSchemeECSchnorr].
// It will panic if the underlying type is not SigSchemeECSchnorr.
func (s AsymSchemeUnion) ECSchnorr() *SigSchemeECSchnorr {
	return union.ContentsPtr[SigSchemeECSchnorr](s.contents)
}

// ECMQV returns a pointer to the value associated with the selector value [AsymSchemeECMQV].
// It will panic if the underlying type is not KeySchemeECMQV.
func (s AsymSchemeUnion) ECMQV() *KeySchemeECMQV {
	return union.ContentsPtr[KeySchemeECMQV](s.contents)
}

// Any returns the asymmetric scheme as a *SchemeHash. It panics if the underlying type
// is not a superset of this.
func (s AsymSchemeUnion) Any() *SchemeHash {
	switch {
	case union.ContentsIs[SchemeHash](s.contents):
		return union.ContentsPtr[SchemeHash](s.contents)
	case union.ContentsIs[SigSchemeECDAA](s.contents):
		scheme := union.ContentsPtr[SigSchemeECDAA](s.contents)
		return *(**SchemeHash)(unsafe.Pointer(&scheme))
	default:
		panic("invalid type")
	}
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (s AsymSchemeUnion) SelectMarshal(selector any) any {
	switch reflect.ValueOf(selector).Convert(reflect.TypeOf(AsymSchemeId(0))).Interface().(AsymSchemeId) {
	case AsymSchemeRSASSA:
		return union.ContentsMarshal[SigSchemeRSASSA](s.contents)
	case AsymSchemeRSAES:
		return union.ContentsMarshal[EncSchemeRSAES](s.contents)
	case AsymSchemeRSAPSS:
		return union.ContentsMarshal[SigSchemeRSAPSS](s.contents)
	case AsymSchemeOAEP:
		return union.ContentsMarshal[EncSchemeOAEP](s.contents)
	case AsymSchemeECDSA:
		return union.ContentsMarshal[SigSchemeECDSA](s.contents)
	case AsymSchemeECDH:
		return union.ContentsMarshal[KeySchemeECDH](s.contents)
	case AsymSchemeECDAA:
		return union.ContentsMarshal[SigSchemeECDAA](s.contents)
	case AsymSchemeSM2:
		return union.ContentsMarshal[SigSchemeSM2](s.contents)
	case AsymSchemeECSchnorr:
		return union.ContentsMarshal[SigSchemeECSchnorr](s.contents)
	case AsymSchemeECMQV:
		return union.ContentsMarshal[KeySchemeECMQV](s.contents)
	case AsymSchemeNull:
		return union.ContentsMarshal[Empty](s.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (s *AsymSchemeUnion) SelectUnmarshal(selector any) any {
	switch reflect.ValueOf(selector).Convert(reflect.TypeOf(AsymSchemeId(0))).Interface().(AsymSchemeId) {
	case AsymSchemeRSASSA:
		return union.ContentsUnmarshal[SigSchemeRSASSA](&s.contents)
	case AsymSchemeRSAES:
		return union.ContentsUnmarshal[EncSchemeRSAES](&s.contents)
	case AsymSchemeRSAPSS:
		return union.ContentsUnmarshal[SigSchemeRSAPSS](&s.contents)
	case AsymSchemeOAEP:
		return union.ContentsUnmarshal[EncSchemeOAEP](&s.contents)
	case AsymSchemeECDSA:
		return union.ContentsUnmarshal[SigSchemeECDSA](&s.contents)
	case AsymSchemeECDH:
		return union.ContentsUnmarshal[KeySchemeECDH](&s.contents)
	case AsymSchemeECDAA:
		return union.ContentsUnmarshal[SigSchemeECDAA](&s.contents)
	case AsymSchemeSM2:
		return union.ContentsUnmarshal[SigSchemeSM2](&s.contents)
	case AsymSchemeECSchnorr:
		return union.ContentsUnmarshal[SigSchemeECSchnorr](&s.contents)
	case AsymSchemeECMQV:
		return union.ContentsUnmarshal[KeySchemeECMQV](&s.contents)
	case AsymSchemeNull:
		return union.ContentsUnmarshal[Empty](&s.contents)
	default:
		return nil
	}
}

// AsymScheme corresponds to the TPMT_ASYM_SCHEME type.
type AsymScheme struct {
	Scheme  AsymSchemeId    // Scheme selector
	Details AsymSchemeUnion // Scheme specific parameters
}

// 11.2.4 RSA

// RSASchemeId corresponds to the TPMI_ALG_RSA_SCHEME type.
type RSASchemeId AsymSchemeId

const (
	RSASchemeNull   RSASchemeId = RSASchemeId(AlgorithmNull)   // TPM_ALG_NULL
	RSASchemeRSASSA RSASchemeId = RSASchemeId(AlgorithmRSASSA) // TPM_ALG_RSASSA
	RSASchemeRSAES  RSASchemeId = RSASchemeId(AlgorithmRSAES)  // TPM_ALG_RSAES
	RSASchemeRSAPSS RSASchemeId = RSASchemeId(AlgorithmRSAPSS) // TPM_ALG_RSAPSS
	RSASchemeOAEP   RSASchemeId = RSASchemeId(AlgorithmOAEP)   // TPM_ALG_OAEP
)

// RSAScheme corresponds to the TPMT_RSA_SCHEME type.
type RSAScheme struct {
	Scheme  RSASchemeId     // Scheme selector
	Details AsymSchemeUnion // Scheme specific parameters.
}

// PublicKeyRSA corresponds to the TPM2B_PUBLIC_KEY_RSA type.
type PublicKeyRSA []byte

// PrivateKeyRSA corresponds to the TPM2B_PRIVATE_KEY_RSA type.
type PrivateKeyRSA []byte

// 11.2.5 ECC

// ECCParameter corresponds to the TPM2B_ECC_PARAMETER type.
type ECCParameter []byte

// ECCPoint corresponds to the TPMS_ECC_POINT type, and contains the coordinates
// that define an ECC point.
type ECCPoint struct {
	X ECCParameter // X coordinate
	Y ECCParameter // Y coordinate
}

// ECCSchemeId corresponds to the TPMI_ALG_ECC_SCHEME type.
type ECCSchemeId AsymSchemeId

const (
	ECCSchemeNull      ECCSchemeId = ECCSchemeId(AlgorithmNull)      // TPM_ALG_NULL
	ECCSchemeECDSA     ECCSchemeId = ECCSchemeId(AlgorithmECDSA)     // TPM_ALG_ECDSA
	ECCSchemeECDH      ECCSchemeId = ECCSchemeId(AlgorithmECDH)      // TPM_ALG_ECDH
	ECCSchemeECDAA     ECCSchemeId = ECCSchemeId(AlgorithmECDAA)     // TPM_ALG_ECDAA
	ECCSchemeSM2       ECCSchemeId = ECCSchemeId(AlgorithmSM2)       // TPM_ALG_SM2
	ECCSchemeECSchnorr ECCSchemeId = ECCSchemeId(AlgorithmECSchnorr) // TPM_ALG_ECSCHNORR
	ECCSchemeECMQV     ECCSchemeId = ECCSchemeId(AlgorithmECMQV)     // TPM_ALG_ECMQV
)

// ECCScheme corresponds to the TPMT_ECC_SCHEME type.
type ECCScheme struct {
	Scheme  ECCSchemeId     // Scheme selector
	Details AsymSchemeUnion // Scheme specific parameters.
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

type SignatureRSASSA = SignatureRSA
type SignatureRSAPSS = SignatureRSA
type SignatureECDSA = SignatureECC
type SignatureECDAA = SignatureECC
type SignatureSM2 = SignatureECC
type SignatureECSchnorr = SignatureECC

type SignatureUnionConstraint interface {
	SignatureRSA | SignatureECC | TaggedHash | Empty
}

// SignatureUnion is a union type that corresponds to TPMU_SIGNATURE. It stores a pointer
// to the underlying value. The selector type is [SigSchemeId]. The selector value [SigSchemeAlgNull]
// is mapped to an empty value.
type SignatureUnion struct {
	contents union.Contents
}

// MakeSignatureUnion returns a SignatureUnion containing the supplied value.
func MakeSignatureUnion[T SignatureUnionConstraint](contents T) SignatureUnion {
	return SignatureUnion{contents: union.NewContents(contents)}
}

// RSASSA returns a pointer to the value associated with the selector value [SigSchemeAlgRSASSA].
// It will panic if the underlying type is not SigSchemeRSASSA.
func (s SignatureUnion) RSASSA() *SignatureRSASSA {
	return union.ContentsPtr[SignatureRSASSA](s.contents)
}

// RSAPSS returns a pointer to the value associated with the selector value [SigSchemeAlgRSAPSS].
// It will panic if the underlying type is not SigSchemeRSAPSS.
func (s SignatureUnion) RSAPSS() *SignatureRSAPSS {
	return union.ContentsPtr[SignatureRSAPSS](s.contents)
}

// ECDSA returns a pointer to the value associated with the selector value [SigSchemeAlgECDSA].
// It will panic if the underlying type is not SigSchemeECDSA.
func (s SignatureUnion) ECDSA() *SignatureECDSA {
	return union.ContentsPtr[SignatureECDSA](s.contents)
}

// ECDAA returns a pointer to the value associated with the selector value [SigSchemeAlgECDAA].
// It will panic if the underlying type is not SigSchemeECDAA.
func (s SignatureUnion) ECDAA() *SignatureECDAA {
	return union.ContentsPtr[SignatureECDAA](s.contents)
}

// SM2 returns a pointer to the value associated with the selector value [SigSchemeAlgSM2].
// It will panic if the underlying type is not SigSchemeSM2.
func (s SignatureUnion) SM2() *SignatureSM2 {
	return union.ContentsPtr[SignatureSM2](s.contents)
}

// ECSchnorr returns a pointer to the value associated with the selector value [SigSchemeAlgECSchnorr].
// It will panic if the underlying type is not SigSchemeECSchnorr.
func (s SignatureUnion) ECSchnorr() *SignatureECSchnorr {
	return union.ContentsPtr[SignatureECSchnorr](s.contents)
}

// HMAC returns a pointer to the value associated with the selector value [SigSchemeAlgHMAC].
// It will panic if the underlying type is not TaggedHash.
func (s SignatureUnion) HMAC() *TaggedHash {
	return union.ContentsPtr[TaggedHash](s.contents)
}

// Any returns the signature as a *SchemeHash. It will panic if the underlying type is not a
// superset of this.
func (s SignatureUnion) Any() *SchemeHash {
	switch {
	case union.ContentsIs[SignatureRSA](s.contents):
		sig := union.ContentsPtr[SignatureRSA](s.contents)
		return *(**SchemeHash)(unsafe.Pointer(&sig))
	case union.ContentsIs[SignatureECC](s.contents):
		sig := union.ContentsPtr[SignatureECC](s.contents)
		return *(**SchemeHash)(unsafe.Pointer(&sig))
	case union.ContentsIs[TaggedHash](s.contents):
		sig := union.ContentsPtr[TaggedHash](s.contents)
		return *(**SchemeHash)(unsafe.Pointer(&sig))
	default:
		panic("invalid type")
	}
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (s SignatureUnion) SelectMarshal(selector any) any {
	switch selector.(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return union.ContentsMarshal[SignatureRSASSA](s.contents)
	case SigSchemeAlgRSAPSS:
		return union.ContentsMarshal[SignatureRSAPSS](s.contents)
	case SigSchemeAlgECDSA:
		return union.ContentsMarshal[SignatureECDSA](s.contents)
	case SigSchemeAlgECDAA:
		return union.ContentsMarshal[SignatureECDAA](s.contents)
	case SigSchemeAlgSM2:
		return union.ContentsMarshal[SignatureSM2](s.contents)
	case SigSchemeAlgECSchnorr:
		return union.ContentsMarshal[SignatureECSchnorr](s.contents)
	case SigSchemeAlgHMAC:
		return union.ContentsMarshal[TaggedHash](s.contents)
	case SigSchemeAlgNull:
		return union.ContentsMarshal[Empty](s.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (s *SignatureUnion) SelectUnmarshal(selector any) any {
	switch selector.(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return union.ContentsUnmarshal[SignatureRSASSA](&s.contents)
	case SigSchemeAlgRSAPSS:
		return union.ContentsUnmarshal[SignatureRSAPSS](&s.contents)
	case SigSchemeAlgECDSA:
		return union.ContentsUnmarshal[SignatureECDSA](&s.contents)
	case SigSchemeAlgECDAA:
		return union.ContentsUnmarshal[SignatureECDAA](&s.contents)
	case SigSchemeAlgSM2:
		return union.ContentsUnmarshal[SignatureSM2](&s.contents)
	case SigSchemeAlgECSchnorr:
		return union.ContentsUnmarshal[SignatureECSchnorr](&s.contents)
	case SigSchemeAlgHMAC:
		return union.ContentsUnmarshal[TaggedHash](&s.contents)
	case SigSchemeAlgNull:
		return union.ContentsUnmarshal[Empty](&s.contents)
	default:
		return nil
	}
}

// Signature corresponds to the TPMT_SIGNATURE type which represents a
// signature.
type Signature struct {
	SigAlg    SigSchemeId    // Signature algorithm
	Signature SignatureUnion // Actual signature
}

// HashAlg returns the digest algorithm used to create the signature. This will panic if
// the signature algorithm is not valid ([SigSchemeId.IsValid] returns false).
func (s *Signature) HashAlg() HashAlgorithmId {
	if !s.SigAlg.IsValid() {
		panic("invalid scheme")
	}

	return s.Signature.Any().HashAlg
}

// 11.4) Key/Secret Exchange

// EncryptedSecret corresponds to the TPM2B_ENCRYPTED_SECRET type.
type EncryptedSecret []byte
