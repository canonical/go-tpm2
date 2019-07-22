// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/sha1"
	"reflect"
	"testing"
)

type TestPublicIDUContainer struct {
	Alg    AlgorithmId
	Unique PublicIDU
}

func (c TestPublicIDUContainer) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (c TestPublicIDUContainer) Selector(field reflect.StructField) interface{} {
	return c.Alg
}

func TestPublicIDUnion(t *testing.T) {
	a := TestPublicIDUContainer{Alg: AlgorithmRSA, Unique: PublicIDU{RSA: PublicKeyRSA{0x01, 0x02, 0x03}}}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03}) {
		t.Fatalf("MarshalToBytes returned an unexpected byte sequence: %x", out)
	}

	var ao TestPublicIDUContainer
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	b := TestPublicIDUContainer{Alg: AlgorithmKeyedHash,
		Unique: PublicIDU{KeyedHash: Digest{0x04, 0x05, 0x06, 0x07}}}
	out, err = MarshalToBytes(b)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x08, 0x00, 0x04, 0x04, 0x05, 0x06, 0x07}) {
		t.Fatalf("MarshalToBytes returned an unexpected byte sequence: %x", out)
	}

	var bo TestPublicIDUContainer
	n, err = UnmarshalFromBytes(out, &bo)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(b, bo) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	c := TestPublicIDUContainer{Alg: AlgorithmNull,
		Unique: PublicIDU{KeyedHash: Digest{0x04, 0x05, 0x06, 0x07}}}
	_, err = MarshalToBytes(c)
	if err == nil {
		t.Fatalf("MarshaToBytes should fail to marshal a union with an invalid selector value")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestPublicIDUContainer: cannot marshal field "+
		"Unique: cannot marshal struct type tpm2.PublicIDU: error marshalling union struct: cannot "+
		"select union member: invalid selector value: TPM_ALG_NULL" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}

type TestSchemeKeyedHashUContainer struct {
	Scheme  AlgorithmId
	Details SchemeKeyedHashU
}

func (c TestSchemeKeyedHashUContainer) StructFlags() StructFlags {
	return StructFlagContainsUnion
}

func (c TestSchemeKeyedHashUContainer) Selector(field reflect.StructField) interface{} {
	return c.Scheme
}

func TestSchemeKeyedHashUnion(t *testing.T) {
	a := TestSchemeKeyedHashUContainer{
		Scheme:  AlgorithmHMAC,
		Details: SchemeKeyedHashU{HMAC: &SchemeHMAC{HashAlg: AlgorithmSHA256}}}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x05, 0x00, 0x0b}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestSchemeKeyedHashUContainer
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	b := TestSchemeKeyedHashUContainer{Scheme: AlgorithmNull}
	out, err = MarshalToBytes(b)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x10}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var bo TestSchemeKeyedHashUContainer
	n, err = UnmarshalFromBytes(out, &bo)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(b, bo) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	c := TestSchemeKeyedHashUContainer{Scheme: AlgorithmSHA256}
	out, err = MarshalToBytes(c)
	if err == nil {
		t.Fatalf("MarshaToBytes should fail to marshal a union with an invalid selector value")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestSchemeKeyedHashUContainer: cannot marshal "+
		"field Details: cannot marshal struct type tpm2.SchemeKeyedHashU: error marshalling union "+
		"struct: cannot select union member: invalid selector value: TPM_ALG_SHA256" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}

func TestPCRSelectionData(t *testing.T) {
	a := PCRSelectionData{4, 8, 9}
	out, err := MarshalToBytes(&a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x03, 0x10, 0x03, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
	}

	var ao PCRSelectionData
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	b := PCRSelectionData{4, 8, 9, 26}
	out, err = MarshalToBytes(&b)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x04, 0x10, 0x03, 0x00, 0x04}) {
		t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
	}
}

func TestPCRSelectionList(t *testing.T) {
	a := PCRSelectionList{PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{3, 6, 24}}}
	out, err := MarshalToBytes(&a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x04, 0x48, 0x00, 0x00, 0x01}) {
		t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
	}

	var ao PCRSelectionList
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestTaggedHash(t *testing.T) {
	digest := sha1.Sum([]byte("foo"))
	a := TaggedHash{HashAlg: AlgorithmSHA1, Digest: digest[:]}
	out, err := MarshalToBytes(&a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if len(out) != 22 {
		t.Errorf("MarshalToBytes returnd the wrong number of bytes (%d)", len(out))
	}
	if !bytes.Equal(out, []byte{0x00, 0x04, 0x0b, 0xee, 0xc7, 0xb5, 0xea, 0x3f, 0x0f, 0xdb, 0xc9, 0x5d, 0x0d,
		0xd4, 0x7f, 0x3c, 0x5b, 0xc2, 0x75, 0xda, 0x8a, 0x33}) {
		t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
	}

	var ao TaggedHash
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	b := TaggedHash{HashAlg: AlgorithmSHA256, Digest: digest[:]}
	_, err = MarshalToBytes(&b)
	if err == nil {
		t.Fatalf("MarshaToBytes should fail to marshal a TaggedHash with the wrong digest size")
	}
	if err.Error() != "cannot marshal type *tpm2.TaggedHash with custom marshaller: invalid digest size 20" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}

	c := TaggedHash{HashAlg: AlgorithmHMAC, Digest: digest[:]}
	_, err = MarshalToBytes(&c)
	if err == nil {
		t.Fatalf("MarshaToBytes should fail to marshal a TaggedHash with an unknown algorithm")
	}
	if err.Error() != "cannot marshal type *tpm2.TaggedHash with custom marshaller: cannot determine "+
		"digest size: unknown digest algorithm: TPM_ALG_HMAC" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}

	out2 := out[0:20]
	_, err = UnmarshalFromBytes(out2, &ao)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes should fail to unmarshal a TaggedHash that is too short")
	}
	if err.Error() != "cannot unmarshal type tpm2.TaggedHash with custom marshaller: cannot read digest: "+
		"EOF" {
		t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
	}

	out3 := append(out, []byte{0, 0, 0, 0}...)
	n, err = UnmarshalFromBytes(out3, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	out[1] = 0x05
	_, err = UnmarshalFromBytes(out, &ao)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes should fail to unmarshal a TaggedHash with an unknown algorithm")
	}
	if err.Error() != "cannot unmarshal type tpm2.TaggedHash with custom marshaller: cannot determine "+
		"digest size: unknown digest algorithm: TPM_ALG_HMAC" {
		t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
	}
}
