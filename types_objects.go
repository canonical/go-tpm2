// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/canonical/go-tpm2/internal/union"
	"github.com/canonical/go-tpm2/mu"
)

// This file contains types defined in section 12 (Key/Object Complex)
// in part 2 of the library spec.

// ObjectTypeId corresponds to the TPMI_ALG_PUBLIC type.
type ObjectTypeId AlgorithmId

// IsAsymmetric determines if the type corresponds to an asymmetric
// object.
func (t ObjectTypeId) IsAsymmetric() bool {
	return t == ObjectTypeRSA || t == ObjectTypeECC
}

const (
	ObjectTypeRSA       ObjectTypeId = ObjectTypeId(AlgorithmRSA)       // TPM_ALG_RSA
	ObjectTypeKeyedHash ObjectTypeId = ObjectTypeId(AlgorithmKeyedHash) // TPM_ALG_KEYEDHASH
	ObjectTypeECC       ObjectTypeId = ObjectTypeId(AlgorithmECC)       // TPM_ALG_ECC
	ObjectTypeSymCipher ObjectTypeId = ObjectTypeId(AlgorithmSymCipher) // TPM_ALG_SYMCIPHER
)

type PublicIDUnionConstraint interface {
	Digest | PublicKeyRSA | ECCPoint
}

// PublicIDUnion is a union type that corresponds to the TPMU_PUBLIC_ID type. It stores
// a pointer to the underlying value. The selector type is [ObjectTypeId].
type PublicIDUnion struct {
	contents union.Contents
}

// MakePublicIDUnion returns a PublicIDUnion containing the supplied value.
func MakePublicIDUnion[T PublicIDUnionConstraint](contents T) PublicIDUnion {
	return PublicIDUnion{contents: union.NewContents(contents)}
}

// KeyedHash returns the value associated with the selector value ObjectTypeKeyedHash.
// It will panic if the underlying type is not Digest.
func (p PublicIDUnion) KeyedHash() Digest {
	return union.ContentsElem[Digest](p.contents)
}

// Sym returns the value associated with the selector value ObjectTypeSymCipher.
// It will panic if the underlying type is not Digest.
func (p PublicIDUnion) Sym() Digest {
	return union.ContentsElem[Digest](p.contents)
}

// RSA returns the value associated with the selector value ObjectTypeRSA.
// It will panic if the underlying type is not PublicKeyRSA.
func (p PublicIDUnion) RSA() PublicKeyRSA {
	return union.ContentsElem[PublicKeyRSA](p.contents)
}

// ECC returns a pointer to the value associated with the selector value ObjectTypeECC.
// It will panic if the underlying type is not ECCPoint.
func (p PublicIDUnion) ECC() *ECCPoint {
	return union.ContentsPtr[ECCPoint](p.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (p PublicIDUnion) SelectMarshal(selector any) any {
	switch selector.(ObjectTypeId) {
	case ObjectTypeRSA:
		return union.ContentsMarshal[PublicKeyRSA](p.contents)
	case ObjectTypeKeyedHash:
		return union.ContentsMarshal[Digest](p.contents)
	case ObjectTypeECC:
		return union.ContentsMarshal[ECCPoint](p.contents)
	case ObjectTypeSymCipher:
		return union.ContentsMarshal[Digest](p.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (p *PublicIDUnion) SelectUnmarshal(selector any) any {
	switch selector.(ObjectTypeId) {
	case ObjectTypeRSA:
		return union.ContentsUnmarshal[PublicKeyRSA](&p.contents)
	case ObjectTypeKeyedHash:
		return union.ContentsUnmarshal[Digest](&p.contents)
	case ObjectTypeECC:
		return union.ContentsUnmarshal[ECCPoint](&p.contents)
	case ObjectTypeSymCipher:
		return union.ContentsUnmarshal[Digest](&p.contents)
	default:
		return nil
	}
}

// KeyedHashParams corresponds to the TPMS_KEYEDHASH_PARMS type, and defines the public
// parameters for a keyedhash object.
type KeyedHashParams struct {
	Scheme KeyedHashScheme // Signing method for a keyed hash signing object
}

// AsymParams corresponds to the TPMS_ASYM_PARMS type, and defines the common public
// parameters for an asymmetric key.
type AsymParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For a key with the AttrSign attribute: a signing scheme.
	// For a key with the AttrDecrypt attribute: a key exchange protocol.
	// For a key with both AttrSign and AttrDecrypt attributes: AlgorithmNull.
	Scheme AsymScheme
}

// RSAParams corresponds to the TPMS_RSA_PARMS type, and defines the public parameters
// for an RSA key.
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

// ECCParams corresponds to the TPMS_ECC_PARMS type, and defines the public parameters for an
// ECC key.
type ECCParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For a key with the AttrSign attribute: a signing scheme.
	// For a key with the AttrDecrypt attribute: a key exchange protocol or AlgorithmNull.
	// For a storage key: AlgorithmNull.
	Scheme  ECCScheme
	CurveID ECCCurve  // ECC curve ID
	KDF     KDFScheme // Unused - always KDFAlgorithmNull
}

type PublicParamsUnionConstraint interface {
	KeyedHashParams | SymCipherParams | RSAParams | ECCParams
}

// PublicParamsUnion is a union type that corresponds to the TPMU_PUBLIC_PARMS type. It stores
// a pointer to the underlying value. The selector type is ]ObjectTypeId].
type PublicParamsUnion struct {
	contents union.Contents
}

// MakePublicParamsUnion returns a PublicParamsUnion containing the supplied value.
func MakePublicParamsUnion[T PublicParamsUnionConstraint](contents T) PublicParamsUnion {
	return PublicParamsUnion{contents: union.NewContents(contents)}
}

// KeyedHashDetail returns a pointer to the value associated with the selector value ObjectTypeKeyedHash.
// It will panic if the underlying type is not KeyedHashParams.
func (p PublicParamsUnion) KeyedHashDetail() *KeyedHashParams {
	return union.ContentsPtr[KeyedHashParams](p.contents)
}

// SymDetail returns a pointer to the value associated with the selector value ObjectTypeSymCipher.
// It will panic if the underlying type is not SymCipherParams.
func (p PublicParamsUnion) SymDetail() *SymCipherParams {
	return union.ContentsPtr[SymCipherParams](p.contents)
}

// RSADetail returns a pointer to the value associated with the selector value ObjectTypeRSA.
// It will panic if the underlying type is not RSAParams.
func (p PublicParamsUnion) RSADetail() *RSAParams {
	return union.ContentsPtr[RSAParams](p.contents)
}

// ECCDetail returns a pointer to the value associated with the selector value ObjectTypeECC.
// It will panic if the underlying type is not ECCParams.
func (p PublicParamsUnion) ECCDetail() *ECCParams {
	return union.ContentsPtr[ECCParams](p.contents)
}

// AsymParams returns the parameters as *AsymParams. It panics if the underlying type is not
// a superset of this.
func (p PublicParamsUnion) AsymDetail() *AsymParams {
	switch ptr := p.contents.(type) {
	case *RSAParams:
		return *(**AsymParams)(unsafe.Pointer(&ptr))
	case *ECCParams:
		return *(**AsymParams)(unsafe.Pointer(&ptr))
	default:
		panic("invalid type")
	}
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (p PublicParamsUnion) SelectMarshal(selector any) any {
	switch selector.(ObjectTypeId) {
	case ObjectTypeRSA:
		return union.ContentsMarshal[RSAParams](p.contents)
	case ObjectTypeKeyedHash:
		return union.ContentsMarshal[KeyedHashParams](p.contents)
	case ObjectTypeECC:
		return union.ContentsMarshal[ECCParams](p.contents)
	case ObjectTypeSymCipher:
		return union.ContentsMarshal[SymCipherParams](p.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (p *PublicParamsUnion) SelectUnmarshal(selector any) any {
	switch selector.(ObjectTypeId) {
	case ObjectTypeRSA:
		return union.ContentsUnmarshal[RSAParams](&p.contents)
	case ObjectTypeKeyedHash:
		return union.ContentsUnmarshal[KeyedHashParams](&p.contents)
	case ObjectTypeECC:
		return union.ContentsUnmarshal[ECCParams](&p.contents)
	case ObjectTypeSymCipher:
		return union.ContentsUnmarshal[SymCipherParams](&p.contents)
	default:
		return nil
	}
}

// PublicParams corresponds to the TPMT_PUBLIC_PARMS type.
type PublicParams struct {
	Type       ObjectTypeId      // Type specifier
	Parameters PublicParamsUnion // Algorithm details
}

// Public corresponds to the TPMT_PUBLIC type, and defines the public area for an object.
type Public struct {
	Type       ObjectTypeId      // Type of this object
	NameAlg    HashAlgorithmId   // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes  // Object attributes
	AuthPolicy Digest            // Authorization policy for this object
	Params     PublicParamsUnion // Type specific parameters
	Unique     PublicIDUnion     // Type specific unique identifier
}

// ComputeName computes the name of this object
func (p *Public) ComputeName() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	h := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(h, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	return mu.MustMarshalToBytes(p.NameAlg, mu.RawBytes(h.Sum(nil))), nil
}

func (p *Public) compareName(name Name) bool {
	n, err := p.ComputeName()
	if err != nil {
		return false
	}
	return bytes.Equal(n, name)
}

// Name implements [github.com/canonical/go-tpm2/objectutil.Named] and
// [github.com/canonical/go-tpm2/policyutil.Named].
//
// This computes the name from the public area. If the name cannot be computed
// then an invalid name is returned ([Name.Type] will return NameTypeInvalid).
func (p *Public) Name() Name {
	name, err := p.ComputeName()
	if err != nil {
		return Name{0, 0}
	}
	return name
}

func (p *Public) ToTemplate() (Template, error) {
	b, err := mu.MarshalToBytes(p)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal object: %v", err)
	}
	return b, nil
}

func (p *Public) isParent() bool {
	if !p.NameAlg.IsValid() {
		return false
	}
	return p.Attrs&(AttrRestricted|AttrDecrypt) == AttrRestricted|AttrDecrypt
}

// IsAsymmetric indicates that this public area is associated with an asymmetric
// key.
func (p *Public) IsAsymmetric() bool {
	return p.Type.IsAsymmetric()
}

// IsStorageParent indicates that this public area is associated with an object that can be
// a storage parent.
func (p *Public) IsStorageParent() bool {
	if !p.isParent() {
		return false
	}
	switch p.Type {
	case ObjectTypeRSA, ObjectTypeECC, ObjectTypeSymCipher:
		return true
	default:
		return false
	}
}

// IsDerivationParent indicates that this public area is associated with an object that can be
// a derivation parent.
func (p *Public) IsDerivationParent() bool {
	if !p.isParent() {
		return false
	}
	if p.Type != ObjectTypeKeyedHash {
		return false
	}
	return true
}

// Public returns a corresponding public key for the TPM public area.
// This will panic if the public area does not correspond to an asymmetric
// key.
func (p *Public) Public() crypto.PublicKey {
	switch p.Type {
	case ObjectTypeRSA:
		exp := int(p.Params.RSADetail().Exponent)
		if exp == 0 {
			exp = DefaultRSAExponent
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(p.Unique.RSA()),
			E: exp}
	case ObjectTypeECC:
		return &ecdsa.PublicKey{
			Curve: p.Params.ECCDetail().CurveID.GoCurve(),
			X:     new(big.Int).SetBytes(p.Unique.ECC().X),
			Y:     new(big.Int).SetBytes(p.Unique.ECC().Y)}
	default:
		panic("object is not a public key")
	}
}

// PublicDerived is similar to Public but can be used as a template to create a derived object
// with [TPMContext.CreateLoaded].
type PublicDerived struct {
	Type       ObjectTypeId      // Type of this object
	NameAlg    HashAlgorithmId   // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes  // Object attributes
	AuthPolicy Digest            // Authorization policy for this object
	Params     PublicParamsUnion // Type specific parameters

	// Unique contains the derivation values. These take precedence over any values specified
	// in SensitiveCreate.Data when creating a derived object,
	Unique *Derive
}

// ComputeName computes the name of this object
func (p *PublicDerived) ComputeName() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	h := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(h, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	return mu.MustMarshalToBytes(p.NameAlg, mu.RawBytes(h.Sum(nil))), nil
}

// Name implements [github.com/canonical/go-tpm2/objectutil.Named] and
// [github.com/canonical/go-tpm2/policyutil.Named].
//
// This computes the name from the public area. If the name cannot be computed
// then an invalid name is returned ([Name.Type] will return NameTypeInvalid).
func (p *PublicDerived) Name() Name {
	name, err := p.ComputeName()
	if err != nil {
		return Name{0, 0}
	}
	return name
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

// 12.3) Private Area Structures

// PrivateVendorSpecific corresponds to the TPM2B_PRIVATE_VENDOR_SPECIFIC type.
type PrivateVendorSpecific []byte

type SensitiveCompositeUnionConstraint interface {
	PrivateKeyRSA | ECCParameter | SensitiveData | SymKey
}

// SensitiveCompositeUnion is a union type that corresponds to the TPMU_SENSITIVE_COMPOSITE
// type. It stores a pointer to the underlying value. The selector type is [ObjectTypeId].
type SensitiveCompositeUnion struct {
	contents union.Contents
}

// MakeSensitiveCompositeUnion returns a SensitiveCompositeUnion containing the supplied value.
func MakeSensitiveCompositeUnion[T SensitiveCompositeUnionConstraint](contents T) SensitiveCompositeUnion {
	return SensitiveCompositeUnion{contents: union.NewContents(contents)}
}

// RSA returns the value associated with the selector value ObjectTypeRSA. It will
// panic if the underlying type is not PrivateKeyRSA.
func (s SensitiveCompositeUnion) RSA() PrivateKeyRSA {
	return union.ContentsElem[PrivateKeyRSA](s.contents)
}

// ECC returns the value associated with the selector value ObjectTypeECC. It will
// panic if the underlying type is not ECCParameter.
func (s SensitiveCompositeUnion) ECC() ECCParameter {
	return union.ContentsElem[ECCParameter](s.contents)
}

// Bits returns the value associated with the selector value ObjectTypeKeyedHash. It will
// panic if the underlying type is not SensitiveData.
func (s SensitiveCompositeUnion) Bits() SensitiveData {
	return union.ContentsElem[SensitiveData](s.contents)
}

// Sym returns the value associated with the selector value ObjectTypeSymCipher. It will
// panic if the underlying type is not SymKey.
func (s SensitiveCompositeUnion) Sym() SymKey {
	return union.ContentsElem[SymKey](s.contents)
}

// Any returns the sensitive data as PrivateVendorSpecific. It will panic if the
// underlying type cannot be converted to this.
func (s SensitiveCompositeUnion) Any() PrivateVendorSpecific {
	switch ptr := s.contents.(type) {
	case *PrivateKeyRSA:
		return PrivateVendorSpecific(*ptr)
	case *ECCParameter:
		return PrivateVendorSpecific(*ptr)
	case *SensitiveData:
		return PrivateVendorSpecific(*ptr)
	case *SymKey:
		return PrivateVendorSpecific(*ptr)
	default:
		panic("invalid type")
	}
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (s SensitiveCompositeUnion) SelectMarshal(selector any) any {
	switch selector.(ObjectTypeId) {
	case ObjectTypeRSA:
		return union.ContentsMarshal[PrivateKeyRSA](s.contents)
	case ObjectTypeECC:
		return union.ContentsMarshal[ECCParameter](s.contents)
	case ObjectTypeKeyedHash:
		return union.ContentsMarshal[SensitiveData](s.contents)
	case ObjectTypeSymCipher:
		return union.ContentsMarshal[SymKey](s.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmrshal].
func (s *SensitiveCompositeUnion) SelectUnmarshal(selector any) any {
	switch selector.(ObjectTypeId) {
	case ObjectTypeRSA:
		return union.ContentsUnmarshal[PrivateKeyRSA](&s.contents)
	case ObjectTypeECC:
		return union.ContentsUnmarshal[ECCParameter](&s.contents)
	case ObjectTypeKeyedHash:
		return union.ContentsUnmarshal[SensitiveData](&s.contents)
	case ObjectTypeSymCipher:
		return union.ContentsUnmarshal[SymKey](&s.contents)
	default:
		return nil
	}
}

// Sensitive corresponds to the TPMT_SENSITIVE type.
type Sensitive struct {
	Type      ObjectTypeId            // Same as the corresponding Type in the Public object
	AuthValue Auth                    // Authorization value
	SeedValue Digest                  // For a parent object, the seed value for protecting descendant objects
	Sensitive SensitiveCompositeUnion // Type specific private data
}

// Private corresponds to the TPM2B_PRIVATE type.
type Private []byte

// 12.4) Identity Object

// IDObject corresponds to the TPM2B_ID_OBJECT type.
type IDObject []byte
