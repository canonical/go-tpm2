// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"reflect"
	"testing"
)

type TestPublicIDUContainer struct {
	Alg    AlgorithmId
	Unique PublicIDU `tpm2:"selector:Alg"`
}

func TestPublicIDUnion(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   TestPublicIDUContainer
		out  []byte
		err  string
	}{
		{
			desc: "RSA",
			in: TestPublicIDUContainer{Alg: AlgorithmRSA,
				Unique: PublicIDU{PublicKeyRSA{0x01, 0x02, 0x03}}},
			out: []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
		{
			desc: "KeyedHash",
			in: TestPublicIDUContainer{Alg: AlgorithmKeyedHash,
				Unique: PublicIDU{Digest{0x04, 0x05, 0x06, 0x07}}},
			out: []byte{0x00, 0x08, 0x00, 0x04, 0x04, 0x05, 0x06, 0x07},
		},
		{
			desc: "InvalidSelector",
			in: TestPublicIDUContainer{Alg: AlgorithmNull,
				Unique: PublicIDU{Digest{0x04, 0x05, 0x06, 0x07}}},
			err: "cannot marshal struct type tpm2.TestPublicIDUContainer: cannot marshal field " +
				"Unique: cannot marshal struct type tpm2.PublicIDU: error marshalling union " +
				"struct: cannot select union data type: invalid selector value: TPM_ALG_NULL",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := MarshalToBytes(data.in)
			if data.err != "" {
				if err == nil {
					t.Fatalf("MarshaToBytes was expected to fail")
				}
				if err.Error() != data.err {
					t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Fatalf("MarshalToBytes returned an unexpected byte sequence: %x", out)
			}

			var a TestPublicIDUContainer
			n, err := UnmarshalFromBytes(out, &a)
			if err != nil {
				t.Fatalf("UnmarshalFromBytes failed: %v", err)
			}
			if n != len(out) {
				t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
			}

			if !reflect.DeepEqual(data.in, a) {
				t.Errorf("UnmarshalFromBytes didn't return the original data")
			}
		})
	}
}

type TestSchemeKeyedHashUContainer struct {
	Scheme  AlgorithmId
	Details SchemeKeyedHashU `tpm2:"selector:Scheme"`
}

func TestSchemeKeyedHashUnion(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   TestSchemeKeyedHashUContainer
		out  []byte
		err  string
	}{
		{
			desc: "HMAC",
			in: TestSchemeKeyedHashUContainer{
				Scheme:  AlgorithmHMAC,
				Details: SchemeKeyedHashU{&SchemeHMAC{HashAlg: AlgorithmSHA256}}},
			out: []byte{0x00, 0x05, 0x00, 0x0b},
		},
		{
			desc: "Null",
			in:   TestSchemeKeyedHashUContainer{Scheme: AlgorithmNull},
			out:  []byte{0x00, 0x10},
		},
		{
			desc: "InvalidSelector",
			in:   TestSchemeKeyedHashUContainer{Scheme: AlgorithmSHA256},
			err: "cannot marshal struct type tpm2.TestSchemeKeyedHashUContainer: cannot marshal " +
				"field Details: cannot marshal struct type tpm2.SchemeKeyedHashU: error " +
				"marshalling union struct: cannot select union data type: invalid selector " +
				"value: TPM_ALG_SHA256",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := MarshalToBytes(data.in)
			if data.err != "" {
				if err == nil {
					t.Fatalf("MarshaToBytes was expected to fail")
				}
				if err.Error() != data.err {
					t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
			}

			var a TestSchemeKeyedHashUContainer
			n, err := UnmarshalFromBytes(out, &a)
			if err != nil {
				t.Fatalf("UnmarshalFromBytes failed: %v", err)
			}
			if n != len(out) {
				t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
			}

			if !reflect.DeepEqual(data.in, a) {
				t.Errorf("UnmarshalFromBytes didn't return the original data")
			}
		})
	}
}

func TestPCRSelectionData(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   PCRSelectionData
		out  []byte
	}{
		{
			desc: "1",
			in:   PCRSelectionData{4, 8, 9},
			out:  []byte{0x03, 0x10, 0x03, 0x00},
		},
		{
			desc: "2",
			in:   PCRSelectionData{4, 8, 9, 26},
			out:  []byte{0x04, 0x10, 0x03, 0x00, 0x04},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := MarshalToBytes(&data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
			}

			var a PCRSelectionData
			n, err := UnmarshalFromBytes(out, &a)
			if err != nil {
				t.Fatalf("UnmarshalFromBytes failed: %v", err)
			}
			if n != len(out) {
				t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
			}

			if !reflect.DeepEqual(data.in, a) {
				t.Errorf("UnmarshalFromBytes didn't return the original data")
			}
		})
	}
}

func TestPCRSelectionList(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   PCRSelectionList
		out  []byte
	}{
		{
			desc: "1",
			in: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{3, 6, 24}}},
			out: []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x04, 0x48, 0x00, 0x00, 0x01},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := MarshalToBytes(&data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
			}

			var a PCRSelectionList
			n, err := UnmarshalFromBytes(out, &a)
			if err != nil {
				t.Fatalf("UnmarshalFromBytes failed: %v", err)
			}
			if n != len(out) {
				t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
			}

			if !reflect.DeepEqual(data.in, a) {
				t.Errorf("UnmarshalFromBytes didn't return the original data")
			}
		})
	}
}

func TestTaggedHash(t *testing.T) {
	sha1Hash := sha1.Sum([]byte("foo"))
	sha256Hash := sha256.Sum256([]byte("foo"))

	for _, data := range []struct {
		desc string
		in   TaggedHash
		out  []byte
		err  string
	}{
		{
			desc: "SHA1",
			in:   TaggedHash{HashAlg: AlgorithmSHA1, Digest: sha1Hash[:]},
			out:  append([]byte{0x00, 0x04}, sha1Hash[:]...),
		},
		{
			desc: "SHA256",
			in:   TaggedHash{HashAlg: AlgorithmSHA256, Digest: sha256Hash[:]},
			out:  append([]byte{0x00, 0x0b}, sha256Hash[:]...),
		},
		{
			desc: "WrongDigestSize",
			in:   TaggedHash{HashAlg: AlgorithmSHA256, Digest: sha1Hash[:]},
			err:  "cannot marshal type *tpm2.TaggedHash with custom marshaller: invalid digest size 20",
		},
		{
			desc: "UnknownAlg",
			in:   TaggedHash{HashAlg: AlgorithmHMAC, Digest: sha1Hash[:]},
			err: "cannot marshal type *tpm2.TaggedHash with custom marshaller: cannot determine " +
				"digest size: unknown digest algorithm: TPM_ALG_HMAC",
		},
	} {
		out, err := MarshalToBytes(&data.in)
		if data.err != "" {
			if err == nil {
				t.Fatalf("Expected MarshalToBytes to fail")
			}
			if err.Error() != data.err {
				t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
			}
			return
		}

		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		if !bytes.Equal(out, data.out) {
			t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
		}

		var a TaggedHash
		n, err := UnmarshalFromBytes(out, &a)
		if err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}
		if n != len(out) {
			t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
		}

		if !reflect.DeepEqual(data.in, a) {
			t.Errorf("UnmarshalFromBytes didn't return the original data")
		}
	}

	t.Run("UnmarshalTruncated", func(t *testing.T) {
		in := TaggedHash{HashAlg: AlgorithmSHA256, Digest: sha256Hash[:]}
		out, err := MarshalToBytes(&in)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		out = out[0:32]
		_, err = UnmarshalFromBytes(out, &in)
		if err == nil {
			t.Fatalf("UnmarshalFromBytes should fail to unmarshal a TaggedHash that is too short")
		}
		if err.Error() != "cannot unmarshal type tpm2.TaggedHash with custom marshaller: cannot read "+
			"digest: EOF" {
			t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
		}
	})

	t.Run("UnmarshalFromLongerBuffer", func(t *testing.T) {
		in := TaggedHash{HashAlg: AlgorithmSHA256, Digest: sha256Hash[:]}
		out, err := MarshalToBytes(&in)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		out = append(out, []byte{0, 0, 0, 0}...)

		var a TaggedHash
		n, err := UnmarshalFromBytes(out, &a)
		if err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}
		if n != len(out) {
			t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
		}

		if !reflect.DeepEqual(in, a) {
			t.Errorf("UnmarshalFromBytes didn't return the original data")
		}
	})

	t.Run("UnmarshalUnknownAlg", func(t *testing.T) {
		in := TaggedHash{HashAlg: AlgorithmSHA256, Digest: sha256Hash[:]}
		out, err := MarshalToBytes(&in)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		out[1] = 0x05
		_, err = UnmarshalFromBytes(out, &in)
		if err == nil {
			t.Fatalf("UnmarshalFromBytes should fail to unmarshal a TaggedHash with an unknown " +
				"algorithm")
		}
		if err.Error() != "cannot unmarshal type tpm2.TaggedHash with custom marshaller: cannot "+
			"determine digest size: unknown digest algorithm: TPM_ALG_HMAC" {
			t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
		}
	})
}

func TestPublicName(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	pub, _, _, err := tpm.ReadPublic(primary)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	name, err := pub.Name()
	if err != nil {
		t.Fatalf("Public.Name() failed: %v", err)
	}

	// primary.Name() is what the TPM returned at object creation
	if !bytes.Equal(primary.Name(), name) {
		t.Errorf("Public.Name() returned an unexpected name")
	}
}

func TestNVPublicName(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	pub := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: AlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
		Size:    64}
	if err := tpm.NVDefineSpace(HandleOwner, nil, &pub, nil); err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	rc, err := tpm.WrapHandle(pub.Index)
	if err != nil {
		t.Fatalf("WrapHandle failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, rc, HandleOwner, nil)

	name, err := pub.Name()
	if err != nil {
		t.Fatalf("NVPublic.Name() failed: %v", err)
	}

	// rc.Name() is what the TPM returned from NVReadPublic
	if !bytes.Equal(rc.Name(), name) {
		t.Errorf("NVPublic.Name() returned an unexpected name")
	}
}

func TestPCRSelectionListSubtract(t *testing.T) {
	for _, data := range []struct {
		desc           string
		x, y, expected PCRSelectionList
	}{
		{
			desc: "1",
			x: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 2, 3, 4}}},
			expected: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{1, 5}}},
		},
		{
			desc: "2",
			x: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 2, 3, 4}}},
			expected: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
		},
		{
			desc: "3",
			x: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			expected: PCRSelectionList{},
		},
		{
			desc: "4",
			x: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1, 2, 3, 4, 5, 6}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{1, 3, 6}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 4, 5}}},
			expected: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 2, 4, 5}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{1, 2, 3}}},
		},
		{
			desc: "5",
			x: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1, 2, 3, 4, 5, 6}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{1, 3, 6}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			expected: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 2, 4, 5}}},
		},
		{
			desc: "6",
			x: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1, 2, 3, 4, 5, 6}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1, 2, 3, 4, 5, 6}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{0, 1, 2, 3, 4, 5}}},
			expected: PCRSelectionList{},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			data.x.subtract(data.y)
			if !reflect.DeepEqual(data.x, data.expected) {
				t.Errorf("Unexpected result %v", data.x)
			}
		})
	}
}
