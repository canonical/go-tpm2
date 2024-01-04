// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"

	"github.com/canonical/go-tpm2/internal/union"
	"github.com/canonical/go-tpm2/mu"
)

// This file contains types defined in section 10 (Structures) in
// part 2 of the library spec.

// Empty corresponds to the TPMS_EMPTY type.
type Empty struct{}

// EmptyValue is an instance of Empty.
var EmptyValue Empty

// 10.3) Hash/Digest structures

type TaggedHashUnionConstraint interface {
	[20]byte | [32]byte | [48]byte | [64]byte | Empty
}

// TaggedHashUnion is a union type that corresponds to the TPMU_HA type. The
// selector type is [HashAlgorithmId]. Mapping of selector values to fields is
// as follows:
//   - HashAlgorithmSHA1: SHA1
//   - HashAlgorithmSHA256: SHA256
//   - HashAlgorithmSHA384: SHA384
//   - HashAlgorithmSHA512: SHA512
//   - HashAlgorithmSHA3_256: SHA3_256
//   - HashAlgorithmSHA3_384: SHA3_384
//   - HashAlgorithmSHA3_512: SHA3_512
type TaggedHashUnion struct {
	contents union.Contents
}

func MakeTaggedHashUnion[T TaggedHashUnionConstraint](contents T) TaggedHashUnion {
	return TaggedHashUnion{contents: union.NewContents(contents)}
}

func (u *TaggedHashUnion) SHA1() [20]byte {
	return union.ContentsElem[[20]byte](u.contents)
}

func (u *TaggedHashUnion) SHA256() [32]byte {
	return union.ContentsElem[[32]byte](u.contents)
}

func (u *TaggedHashUnion) SHA384() [48]byte {
	return union.ContentsElem[[48]byte](u.contents)
}

func (u *TaggedHashUnion) SHA512() [64]byte {
	return union.ContentsElem[[64]byte](u.contents)
}

func (u *TaggedHashUnion) SM3_256() [32]byte {
	return union.ContentsElem[[32]byte](u.contents)
}

func (u *TaggedHashUnion) SHA3_256() [32]byte {
	return union.ContentsElem[[32]byte](u.contents)
}

func (u *TaggedHashUnion) SHA3_384() [48]byte {
	return union.ContentsElem[[48]byte](u.contents)
}

func (u *TaggedHashUnion) SHA3_512() [64]byte {
	return union.ContentsElem[[64]byte](u.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (u TaggedHashUnion) SelectMarshal(selector any) any {
	switch selector.(HashAlgorithmId) {
	case HashAlgorithmNull:
		return union.ContentsMarshal[Empty](u.contents)
	case HashAlgorithmSHA1:
		return union.ContentsMarshal[[20]byte](u.contents)
	case HashAlgorithmSHA256:
		return union.ContentsMarshal[[32]byte](u.contents)
	case HashAlgorithmSHA384:
		return union.ContentsMarshal[[48]byte](u.contents)
	case HashAlgorithmSHA512:
		return union.ContentsMarshal[[64]byte](u.contents)
	case HashAlgorithmSM3_256:
		return union.ContentsMarshal[[32]byte](u.contents)
	case HashAlgorithmSHA3_256:
		return union.ContentsMarshal[[32]byte](u.contents)
	case HashAlgorithmSHA3_384:
		return union.ContentsMarshal[[48]byte](u.contents)
	case HashAlgorithmSHA3_512:
		return union.ContentsMarshal[[64]byte](u.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (u *TaggedHashUnion) SelectUnmarshal(selector any) any {
	switch selector.(HashAlgorithmId) {
	case HashAlgorithmNull:
		return union.ContentsUnmarshal[Empty](&u.contents)
	case HashAlgorithmSHA1:
		return union.ContentsUnmarshal[[20]byte](&u.contents)
	case HashAlgorithmSHA256:
		return union.ContentsUnmarshal[[32]byte](&u.contents)
	case HashAlgorithmSHA384:
		return union.ContentsUnmarshal[[48]byte](&u.contents)
	case HashAlgorithmSHA512:
		return union.ContentsUnmarshal[[64]byte](&u.contents)
	case HashAlgorithmSM3_256:
		return union.ContentsUnmarshal[[32]byte](&u.contents)
	case HashAlgorithmSHA3_256:
		return union.ContentsUnmarshal[[32]byte](&u.contents)
	case HashAlgorithmSHA3_384:
		return union.ContentsUnmarshal[[48]byte](&u.contents)
	case HashAlgorithmSHA3_512:
		return union.ContentsUnmarshal[[64]byte](&u.contents)
	default:
		return nil
	}
}

// TaggedHash corresponds to the TPMT_HA type.
type TaggedHash struct {
	HashAlg    HashAlgorithmId // Algorithm of the digest contained with Digest
	DigestData TaggedHashUnion // Digest data
}

// MakeTaggedHash creates a new tagged hash that represents the specified
// digest. It will panic if the algorithm is invalid. The supplied digest
// should be the correct length - it will be padded if it's too short or
// truncated if it's too long.
func MakeTaggedHash(alg HashAlgorithmId, digest Digest) TaggedHash {
	var union TaggedHashUnion
	switch alg {
	case HashAlgorithmSHA1:
		var data [20]byte
		copy(data[:], digest)
		union = MakeTaggedHashUnion(data)
	case HashAlgorithmSHA256, HashAlgorithmSM3_256, HashAlgorithmSHA3_256:
		var data [32]byte
		copy(data[:], digest)
		union = MakeTaggedHashUnion(data)
	case HashAlgorithmSHA384, HashAlgorithmSHA3_384:
		var data [48]byte
		copy(data[:], digest)
		union = MakeTaggedHashUnion(data)
	case HashAlgorithmSHA512, HashAlgorithmSHA3_512:
		var data [64]byte
		copy(data[:], digest)
		union = MakeTaggedHashUnion(data)
	case HashAlgorithmNull:
		union = MakeTaggedHashUnion(EmptyValue)
	}

	return TaggedHash{HashAlg: alg, DigestData: union}
}

// Digest returns the value of this tagged hash. It will panic if the digest
// algorithm is invalid and not [HashAlgorithmNull]. It will be valid if this
// tagged hash was created by unmarshalling, else it is up to the caller to
// ensure that the HashAlg field is valid and the value is consistent with the
// contents of the DigestData field.
func (h *TaggedHash) Digest() Digest {
	if h.HashAlg == HashAlgorithmNull {
		return nil
	}

	out := make(Digest, h.HashAlg.Size())

	switch h.HashAlg {
	case HashAlgorithmSHA1:
		digest := h.DigestData.SHA1()
		copy(out, digest[:])
	case HashAlgorithmSHA256:
		digest := h.DigestData.SHA256()
		copy(out, digest[:])
	case HashAlgorithmSHA384:
		digest := h.DigestData.SHA384()
		copy(out, digest[:])
	case HashAlgorithmSHA512:
		digest := h.DigestData.SHA512()
		copy(out, digest[:])
	case HashAlgorithmSM3_256:
		digest := h.DigestData.SM3_256()
		copy(out, digest[:])
	case HashAlgorithmSHA3_256:
		digest := h.DigestData.SHA3_256()
		copy(out, digest[:])
	case HashAlgorithmSHA3_384:
		digest := h.DigestData.SHA3_384()
		copy(out, digest[:])
	case HashAlgorithmSHA3_512:
		digest := h.DigestData.SHA3_512()
		copy(out, digest[:])
	}

	return out
}

// 10.4 Sized Buffers

// Digest corresponds to the TPM2B_DIGEST type. The largest size of this supported
// by the TPM can be determined by calling [TPMContext.GetMaxDigest].
type Digest []byte

// Data corresponds to the TPM2B_DATA type. The largest size of this supported by
// the TPM can be determined by calling [TPMContext.GetMaxData].
type Data []byte

// Nonce corresponds to the TPM2B_NONCE type.
type Nonce = Digest

// Auth corresponds to the TPM2B_AUTH type.
type Auth = Digest

// Operand corresponds to the TPM2B_OPERAND type.
type Operand = Digest

const (
	// EventMaxSize indicates the maximum size of arguments of the Event type.
	EventMaxSize = 1024
)

// Event corresponds to the TPM2B_EVENT type. The largest size of this is indicated
// by EventMaxSize.
type Event []byte

// MaxBuffer corresponds to the TPM2B_MAX_BUFFER type. The largest size of this supported
// by the TPM can be determined by calling [TPMContext.GetInputBuffer].
type MaxBuffer []byte

// MaxNVBuffer corresponds to the TPM2B_MAX_NV_BUFFER type. The largest size of this
// supported by the TPM can be determined by calling [TPMContext.GetNVBufferMax].
type MaxNVBuffer []byte

// Timeout corresponds to the TPM2B_TIMEOUT type. The spec defines this
// as having a maximum size of 8 bytes. It is always 8 bytes in the
// reference implementation and so could be represented as a uint64,
// but we have to preserve the original buffer because there is no
// guarantees that it is always 8 bytes, and the actual TPM buffer
// must be recreated accurately in order for ticket validation to
// work correctly in [TPMContext.PolicyTicket].
type Timeout []byte

// Value returns the value as a uint64. The spec defines the TPM2B_TIMEOUT
// type as having a size of up to 8 bytes. If an implementation creates a
// larger value then the result of this is undefined.
func (t Timeout) Value() uint64 {
	return new(big.Int).SetBytes(t).Uint64()
}

// 10.5) Names

// Name corresponds to the TPM2B_NAME type.
type Name []byte

// MakeHandleName creates a Name from the specified handle. This will panic if the
// specified handle doesn't correspond to a PCR, session or permanent resource.
func MakeHandleName(handle Handle) Name {
	switch handle.Type() {
	case HandleTypePCR, HandleTypeHMACSession, HandleTypePolicySession, HandleTypePermanent:
		return mu.MustMarshalToBytes(handle)
	default:
		panic("invalid handle type")
	}
}

// NameType describes the type of a name.
type NameType int

const (
	// NameTypeInvalid means that a Name is invalid.
	NameTypeInvalid NameType = iota

	// NameTypeHandle means that a Name is a handle.
	NameTypeHandle

	// NameTypeDigest means that a Name is a digest.
	NameTypeDigest

	// NameTypeNone means that a Name is empty.
	NameTypeNone
)

// Name implements [github.com/canonical/go-tpm2/objectutil.Named].
func (n Name) Name() Name {
	return n
}

// IsValid determines if this name is valid.
func (n Name) IsValid() bool {
	return n.Type() != NameTypeInvalid
}

// Type determines the type of this name.
func (n Name) Type() NameType {
	switch {
	case len(n) == 0:
		return NameTypeNone
	case len(n) == binary.Size(Handle(0)):
		return NameTypeHandle
	case len(n) < binary.Size(HashAlgorithmId(0)):
		return NameTypeInvalid
	}

	alg := HashAlgorithmId(binary.BigEndian.Uint16(n))
	if !alg.IsValid() {
		return NameTypeInvalid
	}

	if len(n)-binary.Size(HashAlgorithmId(0)) != alg.Size() {
		return NameTypeInvalid
	}

	return NameTypeDigest
}

// Handle returns the handle of the resource that this name corresponds to. If
// Type does not return [NameTypeHandle], it will panic.
func (n Name) Handle() Handle {
	if n.Type() != NameTypeHandle {
		panic("name is not a handle")
	}
	return Handle(binary.BigEndian.Uint32(n))
}

// Algorithm returns the digest algorithm of this name. If Type does not return
// [NameTypeDigest], it will return [HashAlgorithmNull].
func (n Name) Algorithm() HashAlgorithmId {
	if n.Type() != NameTypeDigest {
		return HashAlgorithmNull
	}

	return HashAlgorithmId(binary.BigEndian.Uint16(n))
}

// Digest returns the name as a digest without the algorithm identifier. If
// Type does not return [NameTypeDigest], it will panic.
func (n Name) Digest() Digest {
	if n.Type() != NameTypeDigest {
		panic("name is not a valid digest")
	}
	return Digest(n[binary.Size(HashAlgorithmId(0)):])
}

// 10.6) PCR Structures

// PCRSelectBitmap correspnds to the TPMS_PCR_SELECT type, and is a bitmap
// that defines a selection of PCRs. Note that it is easier to work with the
// [PCRSelect] type instead, which is a slice of PCR indexes.
type PCRSelectBitmap struct {
	Bytes mu.Sized1Bytes
}

// ToPCRs converts this PCRSelectBitmap to a slice of PCR indexes.
func (b *PCRSelectBitmap) ToPCRs() (out PCRSelect) {
	for i, octet := range b.Bytes {
		for bit := uint(0); bit < 8; bit++ {
			if octet&(1<<bit) == 0 {
				continue
			}
			out = append(out, int((uint(i)*8)+bit))
		}
	}

	return out
}

// PCRSelect is a slice of PCR indexes. It makes it easier to work with the
// TPMS_PCR_SELECT type, which is a bitmap of PCR indices.
//
// This type can't be marshalled directly because there is no mechanism to
// specify a minimum size.
//
// It should either be converted to and from *[PCRSelectBitmap] for marshalling
// or used as part of the [PCRSelection] type (which makes it possible to
// specify the minimum size of the bitmap/
type PCRSelect []int

// ToBitmap converts this PCRSelect into its bitmap form, with the specified
// minimum size. If minsize is zero, a value of 3 will be used which aligns
// with PC client TPM devices.
func (d PCRSelect) ToBitmap(minsize uint8) (out *PCRSelectBitmap, err error) {
	if minsize == 0 {
		minsize = 3
	}
	out = &PCRSelectBitmap{Bytes: make([]byte, minsize)}

	for _, i := range d {
		if i < 0 {
			return nil, errors.New("invalid PCR index (< 0)")
		}

		octet := i / 8
		if octet >= math.MaxUint8 {
			return nil, errors.New("invalid PCR index (> 2040)")
		}

		for octet >= len(out.Bytes) {
			out.Bytes = append(out.Bytes, byte(0))
		}
		bit := uint(i % 8)
		out.Bytes[octet] |= 1 << bit
	}

	return out, nil
}

// Marshal implements [mu.CustomMarshaller.Marshal].
//
// Note that this type cannot be marshalled directly and will result in a
// panic if this is attempted.
func (d PCRSelect) Marshal(w io.Writer) error {
	panic("PCRSelect cannot be marshalled directly. Use it as part of PCRSelection or convert it to PCRSelectBitmap")
}

// Unmarshal implements [mu.CustomMarshaller.Unmarshal].
func (d *PCRSelect) Unmarshal(r io.Reader) error {
	var b PCRSelectBitmap
	if _, err := mu.UnmarshalFromReader(r, &b); err != nil {
		return err
	}
	*d = b.ToPCRs()
	return nil
}

// PCRSelection corresponds to the TPMS_PCR_SELECTION type.
type PCRSelection struct {
	Hash   HashAlgorithmId // Hash is the digest algorithm associated with the selection
	Select PCRSelect       // The selected PCRs

	// SizeOfSelect sets the minimum number of bytes in the serialized Select field
	// during marshalling, and is set to the actual number of bytes in the Select
	// field during unmarshalling.
	//
	// TPMs define a minimum size for a PCR selection, based on the number of PCRs
	// defined in its associated platform specification. Note that methods of
	// TPMContext that accept a PCRSelection will set this automatically.
	//
	// If set to zero during marshalling, a value of 3 will be assumed, which
	// aligns with PC client TPM devices.
	SizeOfSelect uint8
}

// Marshal implements [mu.CustomMarshaller.Marshal].
func (s PCRSelection) Marshal(w io.Writer) error {
	bmp, err := s.Select.ToBitmap(s.SizeOfSelect)
	if err != nil {
		return err
	}
	_, err = mu.MarshalToWriter(w, s.Hash, bmp)
	return err
}

// Unmarshal implements [mu.CustomMarshaller.Unmarshal].
func (s *PCRSelection) Unmarshal(r io.Reader) error {
	var b PCRSelectBitmap
	if _, err := mu.UnmarshalFromReader(r, &s.Hash, &b); err != nil {
		return err
	}
	s.Select = b.ToPCRs()
	s.SizeOfSelect = uint8(len(b.Bytes))
	return nil
}

// 10.7 Tickets

// TkCreation corresponds to the TPMT_TK_CREATION type. It is created by TPMContext.Create
// and TPMContext.CreatePrimary, and is used to cryptographically bind the CreationData to
// the created object.
type TkCreation struct {
	Tag       StructTag // Ticket structure tag (TagCreation)
	Hierarchy Handle    // The hierarchy of the object to which this ticket belongs.
	Digest    Digest    // HMAC computed using the proof value of Hierarchy
}

// TkVerified corresponds to the TPMT_TK_VERIFIED type. It is created by TPMContext.VerifySignature
// and provides evidence that the TPM has verified that a digest was signed by a specific key.
type TkVerified struct {
	Tag       StructTag // Ticket structure tag (TagVerified)
	Hierarchy Handle    // The hierarchy of the object to which this ticket belongs.
	Digest    Digest    // HMAC computed using the proof value of Hierarcht
}

// TkAuth corresponds to the TPMT_TK_AUTH type. It is created by TPMContext.PolicySigned
// and TPMContext.PolicySecret when the authorization has an expiration time.
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

// AlgorithmProperty corresponds to the TPMS_ALG_PROPERTY type. It is used to report
// the properties of an algorithm.
type AlgorithmProperty struct {
	Alg        AlgorithmId         // Algorithm identifier
	Properties AlgorithmAttributes // Attributes of the algorithm
}

// TaggedProperty corresponds to the TPMS_TAGGED_PROPERTY type. It is used to report
// the value of a property.
type TaggedProperty struct {
	Property Property // Property identifier
	Value    uint32   // Value of the property
}

// TaggedPCRSelect corresponds to the TPMS_TAGGED_PCR_SELECT type. It is used to
// report the PCR indexes associated with a property.
type TaggedPCRSelect struct {
	Tag    PropertyPCR // Property identifier
	Select PCRSelect   // PCRs associated with Tag
}

// TaggedPolicy corresponds to the TPMS_TAGGED_POLICY type. It is used to report
// the authorization policy for a permanent resource.
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

// WithMinSelectSize creates a copy of this list of selections with the minimum
// size of each selection in bytes set to the specified value. If this isn't
// used to change the default of zero, then 3 is assumed during marshalling
// which aligns with PC client TPM devices.
//
// Methods of TPMContext that accept a PCRSelectionList call this function
// already.
func (l PCRSelectionList) WithMinSelectSize(sz uint8) (out PCRSelectionList) {
	for _, s := range l {
		out = append(out, PCRSelection{Hash: s.Hash, Select: s.Select, SizeOfSelect: sz})
	}
	return out
}

// Sort will sort the list of PCR selections in order of ascending algorithm
// ID. A new list of selections is returned.
//
// This will return an error if the selection list cannot be marshalled to
// the TPM wire format.
func (l PCRSelectionList) Sort() (out PCRSelectionList, err error) {
	if err := mu.CopyValue(&out, l); err != nil {
		return nil, fmt.Errorf("invalid selection list: %w", err)
	}
	for i, s := range l {
		out[i].SizeOfSelect = s.SizeOfSelect
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out, nil
}

// MustSort will sort the list of PCR selections in order of ascending
// algorithm ID. A new list of selections is returned.
//
// This will panic if the selection list cannot be marshalled to the TPM wire
// format. Use mu.IsValid to check if it can actually be serialized correctly.
func (l PCRSelectionList) MustSort() (out PCRSelectionList) {
	var err error
	out, err = l.Sort()
	if err != nil {
		panic(err)
	}
	return out
}

// Merge will merge the PCR selections specified by l and r together and
// return a new set of PCR selections which contains a combination of both.
// For each PCR found in r that isn't found in l, it will be added to the
// first occurence of the corresponding PCR bank found in l if that exists,
// or otherwise a selection for that PCR bank will be appended to the result.
//
// This will return an error if either selection list cannot be marshalled
// to the TPM wire format.
func (l PCRSelectionList) Merge(r PCRSelectionList) (out PCRSelectionList, err error) {
	// Create a copy of the destination list
	if err := mu.CopyValue(&out, l); err != nil {
		return nil, fmt.Errorf("invalid destination selection list: %w", err)
	}
	for i, s := range l {
		out[i].SizeOfSelect = s.SizeOfSelect
	}

	// Iterate over each source selection
	for _, sr := range r {
		rbmp, err := sr.Select.ToBitmap(math.MaxUint8)
		if err != nil {
			return nil, fmt.Errorf("invalid source selection with digest %v: %w", sr.Hash, err)
		}

		dsti := -1
		var dstbmp *PCRSelectBitmap

		// Find a target selection in the destination list
		for i, sl := range out {
			if sl.Hash != sr.Hash {
				continue
			}

			lbmp, err := sl.Select.ToBitmap(math.MaxUint8)
			if err != nil {
				// This selection is proven to be valid already
				// because of the earlier copy.
				panic(err)
			}

			if dsti == -1 {
				dsti = i
				dstbmp = lbmp
			}

			// Avoid duplicated PCRs by clearing any in this source selection
			// that exist in any selection in the destination list.
			for j := 0; j < math.MaxUint8; j++ {
				rbmp.Bytes[j] &^= lbmp.Bytes[j]
			}
		}

		if dsti > -1 {
			// We already have a target selection. Set the PCRs from the
			// source selection
			for j := 0; j < math.MaxUint8; j++ {
				dstbmp.Bytes[j] |= rbmp.Bytes[j]
			}
			out[dsti].Select = dstbmp.ToPCRs()
		} else {
			// We don't have a target selection, so create one.
			var sr2 PCRSelection
			mu.MustCopyValue(&sr2, sr) // source proven to be valid earlier
			sr2.SizeOfSelect = sr.SizeOfSelect
			out = append(out, sr2)
		}
	}

	return out, nil
}

// MustMerge will merge the PCR selections specified by l and r together
// and return a new set of PCR selections which contains a combination of
// both. For each PCR found in r that isn't found in l, it will be added
// to the first occurence of the corresponding PCR bank found in l if that
// exists, or otherwise a selection for that PCR bank will be appended to
// the result.
//
// This will panic if either selection list cannot be marshalled to the TPM
// wire format. Use mu.IsValid to check if the values can actually be
// serialized correctly.
func (l PCRSelectionList) MustMerge(r PCRSelectionList) (out PCRSelectionList) {
	var err error
	out, err = l.Merge(r)
	if err != nil {
		panic(err)
	}
	return out
}

// Remove will remove the PCR selections in r from the PCR selections in l,
// and return a new set of selections.
//
// This will return an error if either selection list cannot be marshalled
// to the TPM wire format.
func (l PCRSelectionList) Remove(r PCRSelectionList) (out PCRSelectionList, err error) {
	// Create a copy of the original selection list
	if err := mu.CopyValue(&out, l); err != nil {
		return nil, fmt.Errorf("invalid original selection list: %w", err)
	}
	for i, s := range l {
		out[i].SizeOfSelect = s.SizeOfSelect
	}

	// Iterate over each selection to remove
	for _, sr := range r {
		rbmp, err := sr.Select.ToBitmap(math.MaxUint8)
		if err != nil {
			return nil, fmt.Errorf("invalid selection to remove with digest %v: %w", sr.Hash, err)
		}

		// Iterate over the destination selection list
		for i, sl := range out {
			if sl.Hash != sr.Hash {
				continue
			}

			lbmp, err := sl.Select.ToBitmap(math.MaxUint8)
			if err != nil {
				// This selection is proven to be valid already
				// because of the earlier copy.
				panic(err)
			}

			// Remove necessary PCRs from the destination selection
			for j := 0; j < math.MaxUint8; j++ {
				lbmp.Bytes[j] &^= rbmp.Bytes[j]
			}

			out[i].Select = lbmp.ToPCRs()
		}
	}

	// Remove any selections from the destination list that are now empty.
	for i, so := range out {
		if len(so.Select) > 0 {
			continue
		}
		if i < len(out)-1 {
			copy(out[i:], out[i+1:])
		}
		out = out[:len(out)-1]
	}

	return out, nil
}

// MustRemove will remove the PCR selections in r from the PCR selections
// in l, and return a new set of selections.
//
// This will panic if either selection list cannot be marshalled to the TPM
// wire format. Use mu.IsValid to check if the values can actually be
// serialized correctly.
func (l PCRSelectionList) MustRemove(r PCRSelectionList) (out PCRSelectionList) {
	var err error
	out, err = l.Remove(r)
	if err != nil {
		panic(err)
	}
	return out
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

// AlgorithmPropertyList is a slice of AlgorithmProperty values, and corresponds to
// the TPML_ALG_PROPERTY type.
type AlgorithmPropertyList []AlgorithmProperty

// TaggedTPMPropertyList is a slice of TaggedProperty values, and corresponds to the
// TPML_TAGGED_TPM_PROPERTY type.
type TaggedTPMPropertyList []TaggedProperty

// TaggedPCRPropertyList is a slice of TaggedPCRSelect values, and corresponds to the
// TPML_TAGGED_PCR_PROPERTY type.
type TaggedPCRPropertyList []TaggedPCRSelect

// ECCCurveList is a slice of ECCCurve values, and corresponds to the TPML_ECC_CURVE type.
type ECCCurveList []ECCCurve

// TaggedPolicyList is a slice of TaggedPolicy values, and corresponds to the
// TPML_TAGGED_POLICY type.
type TaggedPolicyList []TaggedPolicy

// 10.10) Capabilities Structures

type CapabilitiesUnionConstraint interface {
	AlgorithmPropertyList | HandleList | CommandAttributesList | CommandCodeList | PCRSelectionList | TaggedTPMPropertyList | TaggedPCRPropertyList | ECCCurveList | TaggedPolicyList
}

// CapabilitiesUnion is a union type that corresponds to the TPMU_CAPABILITIES type. The
// selector type is Capability. Mapping of selector values to fields is as follows:
//   - CapabilityAlgs: Algorithms
//   - CapabilityHandles: Handles
//   - CapabilityCommands: Command
//   - CapabilityPPCommands: PPCommands
//   - CapabilityAuditCommands: AuditCommands
//   - CapabilityPCRs: AssignedPCR
//   - CapabilityTPMProperties: TPMProperties
//   - CapabilityPCRProperties: PCRProperties
//   - CapabilityECCCurves: ECCCurves
//   - CapabilityAuthPolicies: AuthPolicies
type CapabilitiesUnion struct {
	contents union.Contents
}

func MakeCapabilitiesUnion[T CapabilitiesUnionConstraint](contents T) CapabilitiesUnion {
	return CapabilitiesUnion{contents: union.NewContents(contents)}
}

func (c *CapabilitiesUnion) Algorithms() AlgorithmPropertyList {
	return union.ContentsElem[AlgorithmPropertyList](c.contents)
}

func (c *CapabilitiesUnion) Handles() HandleList {
	return union.ContentsElem[HandleList](c.contents)
}

func (c *CapabilitiesUnion) Command() CommandAttributesList {
	return union.ContentsElem[CommandAttributesList](c.contents)
}

func (c *CapabilitiesUnion) PPCommands() CommandCodeList {
	return union.ContentsElem[CommandCodeList](c.contents)
}

func (c *CapabilitiesUnion) AuditCommands() CommandCodeList {
	return union.ContentsElem[CommandCodeList](c.contents)
}

func (c *CapabilitiesUnion) AssignedPCR() PCRSelectionList {
	return union.ContentsElem[PCRSelectionList](c.contents)
}

func (c *CapabilitiesUnion) TPMProperties() TaggedTPMPropertyList {
	return union.ContentsElem[TaggedTPMPropertyList](c.contents)
}

func (c *CapabilitiesUnion) PCRProperties() TaggedPCRPropertyList {
	return union.ContentsElem[TaggedPCRPropertyList](c.contents)
}

func (c *CapabilitiesUnion) ECCCurves() ECCCurveList {
	return union.ContentsElem[ECCCurveList](c.contents)
}

func (c *CapabilitiesUnion) AuthPolicies() TaggedPolicyList {
	return union.ContentsElem[TaggedPolicyList](c.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (c CapabilitiesUnion) SelectMarshal(selector any) any {
	switch selector.(Capability) {
	case CapabilityAlgs:
		return union.ContentsMarshal[AlgorithmPropertyList](c.contents)
	case CapabilityHandles:
		return union.ContentsMarshal[HandleList](c.contents)
	case CapabilityCommands:
		return union.ContentsMarshal[CommandAttributesList](c.contents)
	case CapabilityPPCommands:
		return union.ContentsMarshal[CommandCodeList](c.contents)
	case CapabilityAuditCommands:
		return union.ContentsMarshal[CommandCodeList](c.contents)
	case CapabilityPCRs:
		return union.ContentsMarshal[PCRSelectionList](c.contents)
	case CapabilityTPMProperties:
		return union.ContentsMarshal[TaggedTPMPropertyList](c.contents)
	case CapabilityPCRProperties:
		return union.ContentsMarshal[TaggedPCRPropertyList](c.contents)
	case CapabilityECCCurves:
		return union.ContentsMarshal[ECCCurveList](c.contents)
	case CapabilityAuthPolicies:
		return union.ContentsMarshal[TaggedPolicyList](c.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (c *CapabilitiesUnion) SelectUnmarshal(selector any) any {
	switch selector.(Capability) {
	case CapabilityAlgs:
		return union.ContentsUnmarshal[AlgorithmPropertyList](&c.contents)
	case CapabilityHandles:
		return union.ContentsUnmarshal[HandleList](&c.contents)
	case CapabilityCommands:
		return union.ContentsUnmarshal[CommandAttributesList](&c.contents)
	case CapabilityPPCommands:
		return union.ContentsUnmarshal[CommandCodeList](&c.contents)
	case CapabilityAuditCommands:
		return union.ContentsUnmarshal[CommandCodeList](&c.contents)
	case CapabilityPCRs:
		return union.ContentsUnmarshal[PCRSelectionList](&c.contents)
	case CapabilityTPMProperties:
		return union.ContentsUnmarshal[TaggedTPMPropertyList](&c.contents)
	case CapabilityPCRProperties:
		return union.ContentsUnmarshal[TaggedPCRPropertyList](&c.contents)
	case CapabilityECCCurves:
		return union.ContentsUnmarshal[ECCCurveList](&c.contents)
	case CapabilityAuthPolicies:
		return union.ContentsUnmarshal[TaggedPolicyList](&c.contents)
	default:
		return nil
	}
}

// CapabilityData corresponds to the TPMS_CAPABILITY_DATA type, and is returned by
// TPMContext.GetCapability.
type CapabilityData struct {
	Capability Capability        // Capability
	Data       CapabilitiesUnion // Capability data
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

// TimeAttestInfo corresponds to the TPMS_TIME_ATTEST_INFO type, and is returned by
// TPMContext.GetTime.
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

// CommandAuditInfo corresponds to the TPMS_COMMAND_AUDIT_INFO type, and is returned by
// TPMContext.GetCommandAuditDigest.
type CommandAuditInfo struct {
	AuditCounter  uint64      // Monotonic audit counter
	DigestAlg     AlgorithmId // Hash algorithm used for the command audit
	AuditDigest   Digest      // Current value of the audit digest
	CommandDigest Digest      // Digest of command codes being audited, using DigestAlg
}

// SessionAuditInfo corresponds to the TPMS_SESSION_AUDIT_INFO type, and is returned by
// TPMContext.GetSessionAuditDigest.
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

type AttestUnionConstraint interface {
	CertifyInfo | CreationInfo | QuoteInfo | CommandAuditInfo | SessionAuditInfo | TimeAttestInfo | NVCertifyInfo
}

// AttestUnion is a union type that corresponds to the TPMU_ATTEST type. The selector type is StructTag.
// Mapping of selector values to fields is as follows:
//   - TagAttestNV: NV
//   - TagAttestCommandAudit: CommandAudit
//   - TagAttestSessionAudit: SessionAudit
//   - TagAttestCertify: Certify
//   - TagAttestQuote: Quote
//   - TagAttestTime: Time
//   - TagAttestCreation: Creation
type AttestUnion struct {
	contents union.Contents
}

func MakeAttestUnion[T AttestUnionConstraint](contents T) AttestUnion {
	return AttestUnion{contents: union.NewContents(contents)}
}

func (a *AttestUnion) Certify() *CertifyInfo {
	return union.ContentsPtr[CertifyInfo](a.contents)
}

func (a *AttestUnion) Creation() *CreationInfo {
	return union.ContentsPtr[CreationInfo](a.contents)
}

func (a *AttestUnion) Quote() *QuoteInfo {
	return union.ContentsPtr[QuoteInfo](a.contents)
}

func (a *AttestUnion) CommandAudit() *CommandAuditInfo {
	return union.ContentsPtr[CommandAuditInfo](a.contents)
}

func (a *AttestUnion) SessionAudit() *SessionAuditInfo {
	return union.ContentsPtr[SessionAuditInfo](a.contents)
}

func (a *AttestUnion) Time() *TimeAttestInfo {
	return union.ContentsPtr[TimeAttestInfo](a.contents)
}

func (a *AttestUnion) NV() *NVCertifyInfo {
	return union.ContentsPtr[NVCertifyInfo](a.contents)
}

// SelectMarshal implements [mu.Union.SelectMarshal].
func (a AttestUnion) SelectMarshal(selector any) any {
	switch selector.(StructTag) {
	case TagAttestNV:
		return union.ContentsMarshal[NVCertifyInfo](a.contents)
	case TagAttestCommandAudit:
		return union.ContentsMarshal[CommandAuditInfo](a.contents)
	case TagAttestSessionAudit:
		return union.ContentsMarshal[SessionAuditInfo](a.contents)
	case TagAttestCertify:
		return union.ContentsMarshal[CertifyInfo](a.contents)
	case TagAttestQuote:
		return union.ContentsMarshal[QuoteInfo](a.contents)
	case TagAttestTime:
		return union.ContentsMarshal[TimeAttestInfo](a.contents)
	case TagAttestCreation:
		return union.ContentsMarshal[CreationInfo](a.contents)
	default:
		return nil
	}
}

// SelectUnmarshal implements [mu.Union.SelectUnmarshal].
func (a *AttestUnion) SelectUnmarshal(selector any) any {
	switch selector.(StructTag) {
	case TagAttestNV:
		return union.ContentsUnmarshal[NVCertifyInfo](&a.contents)
	case TagAttestCommandAudit:
		return union.ContentsUnmarshal[CommandAuditInfo](&a.contents)
	case TagAttestSessionAudit:
		return union.ContentsUnmarshal[SessionAuditInfo](&a.contents)
	case TagAttestCertify:
		return union.ContentsUnmarshal[CertifyInfo](&a.contents)
	case TagAttestQuote:
		return union.ContentsUnmarshal[QuoteInfo](&a.contents)
	case TagAttestTime:
		return union.ContentsUnmarshal[TimeAttestInfo](&a.contents)
	case TagAttestCreation:
		return union.ContentsUnmarshal[CreationInfo](&a.contents)
	default:
		return nil
	}
}

// Attest corresponds to the TPMS_ATTEST type, and is returned by the attestation commands. The
// signature of the attestation is over this structure.
type Attest struct {
	Magic           TPMGenerated // Always TPMGeneratedValue
	Type            StructTag    // Type of the attestation structure
	QualifiedSigner Name         // Qualified name of the signing key
	ExtraData       Data         // External information provided by the caller
	ClockInfo       ClockInfo    // Clock information
	FirmwareVersion uint64       // TPM vendor specific value indicating the version of the firmware
	Attested        AttestUnion  `tpm2:"selector:Type"` // Type specific attestation data
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
