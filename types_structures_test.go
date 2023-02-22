// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto"
	"encoding/binary"
	"io"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
)

type typesStructuresSuite struct{}

var _ = Suite(&typesStructuresSuite{})

func (s *typesStructuresSuite) TestMakeHandleNameOwner(c *C) {
	name := MakeHandleName(HandleOwner)
	c.Check(name, DeepEquals, Name(internal_testutil.DecodeHexString(c, "40000001")))
}

func (s *typesStructuresSuite) TestMakeHandleNameEndorsement(c *C) {
	name := MakeHandleName(HandleEndorsement)
	c.Check(name, DeepEquals, Name(internal_testutil.DecodeHexString(c, "4000000b")))
}

func (s *typesStructuresSuite) TestNameTypeNone(c *C) {
	var name Name
	c.Check(name.Type(), Equals, NameTypeNone)
}

func (s *typesStructuresSuite) TestNameTypeInvalid(c *C) {
	name := Name{0, 0}
	c.Check(name.Type(), Equals, NameTypeInvalid)
}

func (s *typesStructuresSuite) TestNameTypeInvalidTooShort(c *C) {
	name := Name{0xaa}
	c.Check(name.Type(), Equals, NameTypeInvalid)
}

func (s *typesStructuresSuite) TestNameTypeInvalidAlg(c *C) {
	name := Name{0xaa, 0xaa}
	name = append(name, make(Name, 32)...)
	c.Check(name.Type(), Equals, NameTypeInvalid)
}

func (s *typesStructuresSuite) TestNameTypeInvalidLength(c *C) {
	name := make(Name, 30)
	binary.BigEndian.PutUint16(name, uint16(HashAlgorithmSHA256))
	c.Check(name.Type(), Equals, NameTypeInvalid)
}

func (s *typesStructuresSuite) TestNameTypeHandle(c *C) {
	name := make(Name, 4)
	c.Check(name.Type(), Equals, NameTypeHandle)
}

func (s *typesStructuresSuite) TestNameTypeDigest(c *C) {
	name := make(Name, 34)
	binary.BigEndian.PutUint16(name, uint16(HashAlgorithmSHA256))
	c.Check(name.Type(), Equals, NameTypeDigest)
}

func (s *typesStructuresSuite) TestNameHandle1(c *C) {
	name := make(Name, 4)
	binary.BigEndian.PutUint32(name, uint32(HandleOwner))
	c.Check(name.Handle(), Equals, HandleOwner)
}

func (s *typesStructuresSuite) TestNameHandle2(c *C) {
	name := make(Name, 4)
	binary.BigEndian.PutUint32(name, 0x02000000)
	c.Check(name.Handle(), Equals, Handle(0x02000000))
}

func (s *typesStructuresSuite) TestNameHandlePanic(c *C) {
	name := make(Name, 3)
	c.Check(func() { name.Handle() }, PanicMatches, "name is not a handle")
}

func (s *typesStructuresSuite) TestNameAlgorithm1(c *C) {
	name := make(Name, 34)
	binary.BigEndian.PutUint16(name, uint16(HashAlgorithmSHA256))
	c.Check(name.Algorithm(), Equals, HashAlgorithmSHA256)
}

func (s *typesStructuresSuite) TestNameAlgorithm2(c *C) {
	name := make(Name, 22)
	binary.BigEndian.PutUint16(name, uint16(HashAlgorithmSHA1))
	c.Check(name.Algorithm(), Equals, HashAlgorithmSHA1)
}

func (s *typesStructuresSuite) TestNameAlgorithmInvalid(c *C) {
	name := make(Name, 4)
	binary.BigEndian.PutUint32(name, uint32(HandleOwner))
	c.Check(name.Algorithm(), Equals, HashAlgorithmNull)
}

func (s *typesStructuresSuite) TestNameDigest1(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	name := make(Name, 2)
	binary.BigEndian.PutUint16(name, uint16(HashAlgorithmSHA256))
	name = append(name, digest...)

	c.Check(name.Digest(), DeepEquals, Digest(digest))
}

func (s *typesStructuresSuite) TestNameDigest2(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	name := make(Name, 2)
	binary.BigEndian.PutUint16(name, uint16(HashAlgorithmSHA1))
	name = append(name, digest...)

	c.Check(name.Digest(), DeepEquals, Digest(digest))
}

func (s *typesStructuresSuite) TestNameDigestPanic(c *C) {
	name := make(Name, 2)
	binary.BigEndian.PutUint16(name, uint16(HashAlgorithmSHA256))
	c.Check(func() { name.Digest() }, PanicMatches, "name is not a valid digest")
}

func (s *typesStructuresSuite) TestPCRSelectBitmapToPCRs1(c *C) {
	a := PCRSelectBitmap{Bytes: []byte{144, 0, 128}}
	pcrs := a.ToPCRs()
	c.Check(pcrs, DeepEquals, PCRSelect{4, 7, 23})
}

func (s *typesStructuresSuite) TestPCRSelectBitmapToPCRs2(c *C) {
	a := PCRSelectBitmap{Bytes: []byte{16, 0, 128, 1}}
	pcrs := a.ToPCRs()
	c.Check(pcrs, DeepEquals, PCRSelect{4, 23, 24})
}

func (s *typesStructuresSuite) TestPCRSelectToBitmap1(c *C) {
	pcrs := PCRSelect{4, 7}
	bmp, err := pcrs.ToBitmap(3)
	c.Check(err, IsNil)
	c.Check(bmp, DeepEquals, &PCRSelectBitmap{Bytes: []byte{144, 0, 0}})
}

func (s *typesStructuresSuite) TestPCRSelectToBitmap2(c *C) {
	pcrs := PCRSelect{4, 7}
	bmp, err := pcrs.ToBitmap(1)
	c.Check(err, IsNil)
	c.Check(bmp, DeepEquals, &PCRSelectBitmap{Bytes: []byte{144}})
}

func (s *typesStructuresSuite) TestPCRSelectToBitmap3(c *C) {
	pcrs := PCRSelect{7, 23}
	bmp, err := pcrs.ToBitmap(3)
	c.Check(err, IsNil)
	c.Check(bmp, DeepEquals, &PCRSelectBitmap{Bytes: []byte{128, 0, 128}})
}

func (s *typesStructuresSuite) TestPCRSelectToBitmap4(c *C) {
	pcrs := PCRSelect{4, 7}
	bmp, err := pcrs.ToBitmap(0)
	c.Check(err, IsNil)
	c.Check(bmp, DeepEquals, &PCRSelectBitmap{Bytes: []byte{144, 0, 0}})
}

func (s *typesStructuresSuite) TestPCRSelectionToBitmapErr1(c *C) {
	pcrs := PCRSelect{7, -1}
	_, err := pcrs.ToBitmap(3)
	c.Check(err, ErrorMatches, `invalid PCR index \(< 0\)`)
}

func (s *typesStructuresSuite) TestPCRSelectionToBitmapErr2(c *C) {
	pcrs := PCRSelect{7, 2041}
	_, err := pcrs.ToBitmap(3)
	c.Check(err, ErrorMatches, `invalid PCR index \(> 2040\)`)
}

func (s *typesStructuresSuite) TestPCRSelectionMarshal1(c *C) {
	a := PCRSelection{
		Hash:         HashAlgorithmSHA256,
		Select:       []int{4, 7},
		SizeOfSelect: 3}
	out := mu.MustMarshalToBytes(a)
	c.Check(out, DeepEquals, internal_testutil.DecodeHexString(c, "000b03900000"))

	var b PCRSelection
	_, err := mu.UnmarshalFromBytes(out, &b)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, a)
}

func (s *typesStructuresSuite) TestPCRSelectionMarshal2(c *C) {
	a := PCRSelection{
		Hash:         HashAlgorithmSHA1,
		Select:       []int{4, 23},
		SizeOfSelect: 3}
	out := mu.MustMarshalToBytes(a)
	c.Check(out, DeepEquals, internal_testutil.DecodeHexString(c, "000403100080"))

	var b PCRSelection
	_, err := mu.UnmarshalFromBytes(out, &b)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, a)
}

func (s *typesStructuresSuite) TestPCRSelectionMarshal3(c *C) {
	a := PCRSelection{
		Hash:         HashAlgorithmSHA256,
		Select:       []int{4, 7, 24},
		SizeOfSelect: 3}
	out := mu.MustMarshalToBytes(a)
	c.Check(out, DeepEquals, internal_testutil.DecodeHexString(c, "000b0490000001"))

	var b PCRSelection
	_, err := mu.UnmarshalFromBytes(out, &b)
	c.Check(err, IsNil)
	a.SizeOfSelect = 4
	c.Check(b, DeepEquals, a)
}

func (s *typesStructuresSuite) TestPCRSelectionMarshal4(c *C) {
	a := PCRSelection{
		Hash:   HashAlgorithmSHA256,
		Select: []int{4, 7}}
	out := mu.MustMarshalToBytes(a)
	c.Check(out, DeepEquals, internal_testutil.DecodeHexString(c, "000b03900000"))

	var b PCRSelection
	_, err := mu.UnmarshalFromBytes(out, &b)
	c.Check(err, IsNil)
	a.SizeOfSelect = 3
	c.Check(b, DeepEquals, a)
}

func (s *typesStructuresSuite) TestPCRSelectionMarshal5(c *C) {
	a := PCRSelection{
		Hash:         HashAlgorithmSHA256,
		Select:       []int{4, 7},
		SizeOfSelect: 1}
	out := mu.MustMarshalToBytes(a)
	c.Check(out, DeepEquals, internal_testutil.DecodeHexString(c, "000b0190"))

	var b PCRSelection
	_, err := mu.UnmarshalFromBytes(out, &b)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, a)
}

func (s *typesStructuresSuite) TestPCRSelectionListMarshal1(c *C) {
	a := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{4, 7}, SizeOfSelect: 3}}
	out := mu.MustMarshalToBytes(a)
	c.Check(out, DeepEquals, internal_testutil.DecodeHexString(c, "00000001000b03900000"))

	var b PCRSelectionList
	_, err := mu.UnmarshalFromBytes(out, &b)
	c.Check(err, IsNil)
	c.Check(a, DeepEquals, b)
}

func (s *typesStructuresSuite) TestPCRSelectionListMarshal2(c *C) {
	a := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{4, 7}, SizeOfSelect: 3},
		{Hash: HashAlgorithmSHA1, Select: []int{4, 24}, SizeOfSelect: 3}}
	out := mu.MustMarshalToBytes(a)
	c.Check(out, DeepEquals, internal_testutil.DecodeHexString(c, "00000002000b0390000000040410000001"))

	var b PCRSelectionList
	_, err := mu.UnmarshalFromBytes(out, &b)
	c.Check(err, IsNil)
	a[1].SizeOfSelect = 4
	c.Check(a, DeepEquals, b)
}

func (s *typesStructuresSuite) TestPCRSelectionListWithMinSelectSize(c *C) {
	a := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{4, 7}},
		{Hash: HashAlgorithmSHA1, Select: []int{23}}}
	b := a.WithMinSelectSize(3)

	c.Check(b, DeepEquals, PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{4, 7}, SizeOfSelect: 3},
		{Hash: HashAlgorithmSHA1, Select: []int{23}, SizeOfSelect: 3}})
}

func (s *typesStructuresSuite) TestPCRSelectionListSort(c *C) {
	orig := PCRSelectionList{
		{Hash: HashAlgorithmSHA384, Select: []int{5, 3, 8}},
		{Hash: HashAlgorithmSHA256, Select: []int{1, 2, 0}},
		{Hash: HashAlgorithmSHA1, Select: []int{8, 3, 7, 4}},
		{Hash: HashAlgorithmSHA512, Select: []int{9, 10, 2, 1, 5}},
	}
	sorted, err := orig.Sort()
	c.Check(err, IsNil)
	expected := PCRSelectionList{
		{Hash: HashAlgorithmSHA1, Select: []int{3, 4, 7, 8}},
		{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2}},
		{Hash: HashAlgorithmSHA384, Select: []int{3, 5, 8}},
		{Hash: HashAlgorithmSHA512, Select: []int{1, 2, 5, 9, 10}},
	}
	c.Check(sorted, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListMerge1(c *C) {
	x := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 1}}}
	y := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{5, 1, 3}}}
	expected := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 5}}}
	merged, err := x.Merge(y)
	c.Check(err, IsNil)
	c.Check(merged, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListMerge2(c *C) {
	x := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3}},
		{Hash: HashAlgorithmSHA1, Select: []int{5, 8, 7, 23}},
	}
	y := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{5, 0, 9, 22}},
		{Hash: HashAlgorithmSHA1, Select: []int{2, 0, 7}},
	}
	expected := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 5, 9, 22}},
		{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 5, 7, 8, 23}},
	}
	merged, err := x.Merge(y)
	c.Check(err, IsNil)
	c.Check(merged, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListMerge3(c *C) {
	x := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3}},
		{Hash: HashAlgorithmSHA1, Select: []int{5, 8, 7, 23}},
	}
	y := PCRSelectionList{
		{Hash: HashAlgorithmSHA1, Select: []int{2, 0, 7}},
		{Hash: HashAlgorithmSHA256, Select: []int{5, 0, 9, 22}},
	}
	expected := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 5, 9, 22}},
		{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 5, 7, 8, 23}},
	}
	merged, err := x.Merge(y)
	c.Check(err, IsNil)
	c.Check(merged, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListMerge4(c *C) {
	x := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 1}}}
	y := PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{8, 1, 3}}}
	expected := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2}},
		{Hash: HashAlgorithmSHA1, Select: []int{1, 3, 8}},
	}
	merged, err := x.Merge(y)
	c.Check(err, IsNil)
	c.Check(merged, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListMerge5(c *C) {
	x := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{5, 2, 6}},
		{Hash: HashAlgorithmSHA256, Select: []int{0, 3, 1}},
	}
	y := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{3, 4, 2, 7}}}
	expected := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{2, 4, 5, 6, 7}},
		{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 3}},
	}
	merged, err := x.Merge(y)
	c.Check(err, IsNil)
	c.Check(merged, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListMerge6(c *C) {
	x := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{5, 2, 6}}}
	y := PCRSelectionList{
		{Hash: HashAlgorithmSHA256, Select: []int{3, 1}},
		{Hash: HashAlgorithmSHA256, Select: []int{2, 4, 0}},
	}
	expected := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6}}}
	merged, err := x.Merge(y)
	c.Check(err, IsNil)
	c.Check(merged, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListRemove1(c *C) {
	x := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}}
	y := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 4}}}
	expected := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{1, 5}}}
	removed, err := x.Remove(y)
	c.Check(err, IsNil)
	c.Check(removed, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListRemove2(c *C) {
	x := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}}
	y := PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 3, 4}}}
	expected := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}}
	removed, err := x.Remove(y)
	c.Check(err, IsNil)
	c.Check(removed, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestPCRSelectionListRemove3(c *C) {
	x := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}}
	y := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}}
	expected := PCRSelectionList{}
	removed, err := x.Remove(y)
	c.Check(err, IsNil)
	c.Check(removed, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestNewTaggedHashSHA1(c *C) {
	digest := internal_testutil.DecodeHexString(c, "e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e")

	expected := &TaggedHash{
		HashAlg:    HashAlgorithmSHA1,
		DigestData: new(TaggedHashU)}
	copy(expected.DigestData.SHA1[:], digest)

	h, err := NewTaggedHash(HashAlgorithmSHA1, digest)
	c.Assert(err, IsNil)
	c.Check(h, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestNewTaggedHashSHA256(c *C) {
	digest := internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")

	expected := &TaggedHash{
		HashAlg:    HashAlgorithmSHA256,
		DigestData: new(TaggedHashU)}
	copy(expected.DigestData.SHA256[:], digest)

	h, err := NewTaggedHash(HashAlgorithmSHA256, digest)
	c.Assert(err, IsNil)
	c.Check(h, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestNewTaggedHashError(c *C) {
	_, err := NewTaggedHash(HashAlgorithmSHA256, make([]byte, 20))
	c.Assert(err, ErrorMatches, "invalid digest size")
}

func (s *typesStructuresSuite) TestMakeTaggedHashSHA1(c *C) {
	digest := internal_testutil.DecodeHexString(c, "e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e")

	expected := TaggedHash{
		HashAlg:    HashAlgorithmSHA1,
		DigestData: new(TaggedHashU)}
	copy(expected.DigestData.SHA1[:], digest)

	h := MakeTaggedHash(HashAlgorithmSHA1, digest)
	c.Check(h, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestMakeTaggedHashSHA256(c *C) {
	digest := internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")

	expected := TaggedHash{
		HashAlg:    HashAlgorithmSHA256,
		DigestData: new(TaggedHashU)}
	copy(expected.DigestData.SHA256[:], digest)

	h := MakeTaggedHash(HashAlgorithmSHA256, digest)
	c.Check(h, DeepEquals, expected)
}

type testTaggedHashData struct {
	alg      HashAlgorithmId
	digest   Digest
	expected []byte
}

func (s *typesStructuresSuite) testTaggedHash(c *C, data *testTaggedHashData) {
	h, err := NewTaggedHash(data.alg, data.digest)
	c.Assert(err, IsNil)

	c.Check(h.HashAlg, Equals, data.alg)
	c.Check(h.Digest(), DeepEquals, data.digest)

	b, err := mu.MarshalToBytes(h)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, data.expected)

	var h2 *TaggedHash
	_, err = mu.UnmarshalFromBytes(b, &h2)
	c.Check(err, IsNil)
	c.Check(h2, DeepEquals, h)
}

func (s *typesStructuresSuite) TestTaggedHashSHA1(c *C) {
	s.testTaggedHash(c, &testTaggedHashData{
		alg:      HashAlgorithmSHA1,
		digest:   internal_testutil.DecodeHexString(c, "e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e"),
		expected: internal_testutil.DecodeHexString(c, "0004e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e")})
}

func (s *typesStructuresSuite) TestTaggedHashSHA256(c *C) {
	s.testTaggedHash(c, &testTaggedHashData{
		alg:      HashAlgorithmSHA256,
		digest:   internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		expected: internal_testutil.DecodeHexString(c, "000b4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")})
}

func (s *typesStructuresSuite) TestTaggedHashSHA384(c *C) {
	s.testTaggedHash(c, &testTaggedHashData{
		alg:      HashAlgorithmSHA384,
		digest:   internal_testutil.DecodeHexString(c, "d654902b550e334bb6898d5c4ab8ebe1aedc6c85368eafe28e0f89b62a74a23e1ed20abbc10c02ce321266384d444717"),
		expected: internal_testutil.DecodeHexString(c, "000cd654902b550e334bb6898d5c4ab8ebe1aedc6c85368eafe28e0f89b62a74a23e1ed20abbc10c02ce321266384d444717")})
}

func (s *typesStructuresSuite) TestTaggedHashSHA512(c *C) {
	s.testTaggedHash(c, &testTaggedHashData{
		alg:      HashAlgorithmSHA512,
		digest:   internal_testutil.DecodeHexString(c, "3abb6677af34ac57c0ca5828fd94f9d886c26ce59a8ce60ecf6778079423dccff1d6f19cb655805d56098e6d38a1a710dee59523eed7511e5a9e4b8ccb3a4686"),
		expected: internal_testutil.DecodeHexString(c, "000d3abb6677af34ac57c0ca5828fd94f9d886c26ce59a8ce60ecf6778079423dccff1d6f19cb655805d56098e6d38a1a710dee59523eed7511e5a9e4b8ccb3a4686")})
}

func (s *typesStructuresSuite) TestTaggedHashSHA3_256(c *C) {
	s.testTaggedHash(c, &testTaggedHashData{
		alg:      HashAlgorithmSHA3_256,
		digest:   internal_testutil.DecodeHexString(c, "bc4bb29ce739b5d97007946aa4fdb987012c647b506732f11653c5059631cd3d"),
		expected: internal_testutil.DecodeHexString(c, "0027bc4bb29ce739b5d97007946aa4fdb987012c647b506732f11653c5059631cd3d")})
}

func (s *typesStructuresSuite) TestTaggedHashSHA3_384(c *C) {
	s.testTaggedHash(c, &testTaggedHashData{
		alg:      HashAlgorithmSHA3_384,
		digest:   internal_testutil.DecodeHexString(c, "f07020242c5eb616c1702c60774735c868bd2b9eb071660166121723126e21589e1f7f21d871003b939247682166d0ea"),
		expected: internal_testutil.DecodeHexString(c, "0028f07020242c5eb616c1702c60774735c868bd2b9eb071660166121723126e21589e1f7f21d871003b939247682166d0ea")})
}

func (s *typesStructuresSuite) TestTaggedHashSHA3_512(c *C) {
	s.testTaggedHash(c, &testTaggedHashData{
		alg:      HashAlgorithmSHA3_512,
		digest:   internal_testutil.DecodeHexString(c, "51e0aa1b16f94bf933c1fd6efaa58c1eabe8a3009d1c6096fb0099bab4f52db69e713b224048f3ce693b83b2a8e8de4ca5c1ba9a08c526265366a448f6d057a4"),
		expected: internal_testutil.DecodeHexString(c, "002951e0aa1b16f94bf933c1fd6efaa58c1eabe8a3009d1c6096fb0099bab4f52db69e713b224048f3ce693b83b2a8e8de4ca5c1ba9a08c526265366a448f6d057a4")})
}

func (s *typesStructuresSuite) TestUnmarshalInvalidTaggedHash(c *C) {
	b := internal_testutil.DecodeHexString(c, "0003e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e")

	var h *TaggedHash
	_, err := mu.UnmarshalFromBytes(b, &h)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type tpm2.TaggedHashU: invalid selector value: TPM_ALG_TDES\n\n"+
		"=== BEGIN STACK ===\n"+
		"... tpm2.TaggedHash field DigestData\n"+
		"=== END STACK ===\n")
}

func (s *typesStructuresSuite) TestTaggedHashListBuilder(c *C) {
	d1, err := NewTaggedHash(HashAlgorithmSHA1, internal_testutil.DecodeHexString(c, "7448d8798a4380162d4b56f9b452e2f6f9e24e7a"))
	c.Assert(err, IsNil)
	d2, err := NewTaggedHash(HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"))
	c.Assert(err, IsNil)

	builder := NewTaggedHashListBuilder()
	c.Assert(builder, NotNil)

	c.Check(builder.Append(d1.HashAlg, d1.Digest()), Equals, builder)
	c.Check(builder.Append(d2.HashAlg, d2.Digest()), Equals, builder)

	l, err := builder.Finish()
	c.Check(err, IsNil)

	expected := TaggedHashList{*d1, *d2}

	c.Check(l, DeepEquals, expected)
}

func (s *typesStructuresSuite) TestTaggedHashListBuilderError(c *C) {
	builder := NewTaggedHashListBuilder()
	c.Assert(builder, NotNil)

	c.Check(builder.Append(HashAlgorithmSHA1, make([]byte, 20)), Equals, builder)
	c.Check(builder.Append(HashAlgorithmSHA256, make([]byte, 10)), Equals, builder)
	c.Check(builder.Append(HashAlgorithmSHA384, make([]byte, 48)), Equals, builder)
	c.Check(builder.Append(HashAlgorithmSHA512, nil), Equals, builder)

	_, err := builder.Finish()
	c.Check(err, ErrorMatches, "encountered error on digest 1: invalid digest size")
}
