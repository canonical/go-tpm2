// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"reflect"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"
)

func TestHandle(t *testing.T) {
	for _, data := range []struct {
		desc       string
		handle     Handle
		handleType HandleType
	}{
		{
			desc:       "PCR",
			handle:     0x0000000a,
			handleType: HandleTypePCR,
		},
		{
			desc:       "NVIndex",
			handle:     0x0180ff00,
			handleType: HandleTypeNVIndex,
		},
		{
			desc:       "HMACSession",
			handle:     0x02000001,
			handleType: HandleTypeHMACSession,
		},
		{
			desc:       "PolicySession",
			handle:     0x03000001,
			handleType: HandleTypePolicySession,
		},
		{
			desc:       "Permanent",
			handle:     HandleOwner,
			handleType: HandleTypePermanent,
		},
		{
			desc:       "Transient",
			handle:     0x80000003,
			handleType: HandleTypeTransient,
		},
		{
			desc:       "Persistent",
			handle:     0x81000000,
			handleType: HandleTypePersistent,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			if data.handle.Type() != data.handleType {
				t.Errorf("Unexpected handle type (got %x, expected %x)", data.handle.Type(), data.handleType)
			}
		})
	}
}

type TestPublicIDUContainer struct {
	Alg    ObjectTypeId
	Unique *PublicIDU `tpm2:"selector:Alg"`
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
			in: TestPublicIDUContainer{Alg: ObjectTypeRSA,
				Unique: &PublicIDU{RSA: PublicKeyRSA{0x01, 0x02, 0x03}}},
			out: []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
		{
			desc: "KeyedHash",
			in: TestPublicIDUContainer{Alg: ObjectTypeKeyedHash,
				Unique: &PublicIDU{KeyedHash: Digest{0x04, 0x05, 0x06, 0x07}}},
			out: []byte{0x00, 0x08, 0x00, 0x04, 0x04, 0x05, 0x06, 0x07},
		},
		{
			desc: "InvalidSelector",
			in: TestPublicIDUContainer{Alg: ObjectTypeId(AlgorithmNull),
				Unique: &PublicIDU{Sym: Digest{0x04, 0x05, 0x06, 0x07}}},
			out: []byte{0x00, 0x10},
			err: "cannot unmarshal argument at index 0: cannot process struct type tpm2_test.TestPublicIDUContainer: cannot process field " +
				"Unique from struct type tpm2_test.TestPublicIDUContainer: cannot process union type tpm2.PublicIDU, inside container type " +
				"tpm2_test.TestPublicIDUContainer: invalid selector value: TPM_ALG_NULL",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := mu.MarshalToBytes(data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Fatalf("MarshalToBytes returned an unexpected byte sequence: %x", out)
			}

			var a TestPublicIDUContainer
			n, err := mu.UnmarshalFromBytes(out, &a)
			if data.err != "" {
				if err == nil {
					t.Fatalf("UnmarshalFromBytes was expected to fail")
				}
				if err.Error() != data.err {
					t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
				}
			} else {
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
		})
	}
}

type TestSchemeKeyedHashUContainer struct {
	Scheme  KeyedHashSchemeId
	Details *SchemeKeyedHashU `tpm2:"selector:Scheme"`
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
				Scheme:  KeyedHashSchemeHMAC,
				Details: &SchemeKeyedHashU{HMAC: &SchemeHMAC{HashAlg: HashAlgorithmSHA256}}},
			out: []byte{0x00, 0x05, 0x00, 0x0b},
		},
		{
			desc: "Null",
			in:   TestSchemeKeyedHashUContainer{Scheme: KeyedHashSchemeNull, Details: &SchemeKeyedHashU{}},
			out:  []byte{0x00, 0x10},
		},
		{
			desc: "InvalidSelector",
			in:   TestSchemeKeyedHashUContainer{Scheme: KeyedHashSchemeId(HashAlgorithmSHA256)},
			out:  []byte{0x00, 0x0b},
			err: "cannot unmarshal argument at index 0: cannot process struct type tpm2_test.TestSchemeKeyedHashUContainer: cannot " +
				"process field Details from struct type tpm2_test.TestSchemeKeyedHashUContainer: cannot process union type " +
				"tpm2.SchemeKeyedHashU, inside container type tpm2_test.TestSchemeKeyedHashUContainer: invalid selector value: TPM_ALG_SHA256",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := mu.MarshalToBytes(data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
			}

			var a TestSchemeKeyedHashUContainer
			n, err := mu.UnmarshalFromBytes(out, &a)
			if data.err != "" {
				if err == nil {
					t.Fatalf("UnmarshaFromBytes was expected to fail")
				}
				if err.Error() != data.err {
					t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
				}
			} else {
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
		})
	}
}

func TestPCRSelect(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   PCRSelect
		out  []byte
	}{
		{
			desc: "1",
			in:   []int{4, 8, 9},
			out:  []byte{0x03, 0x10, 0x03, 0x00},
		},
		{
			desc: "2",
			in:   []int{4, 8, 9, 26},
			out:  []byte{0x04, 0x10, 0x03, 0x00, 0x04},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := mu.MarshalToBytes(&data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
			}

			var a PCRSelect
			n, err := mu.UnmarshalFromBytes(out, &a)
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
			in:   PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{3, 6, 24}}},
			out:  []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x04, 0x48, 0x00, 0x00, 0x01},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := mu.MarshalToBytes(&data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected byte sequence: %x", out)
			}

			var a PCRSelectionList
			n, err := mu.UnmarshalFromBytes(out, &a)
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
			in:   TaggedHash{HashAlg: HashAlgorithmSHA1, Digest: sha1Hash[:]},
			out:  append([]byte{0x00, 0x04}, sha1Hash[:]...),
		},
		{
			desc: "SHA256",
			in:   TaggedHash{HashAlg: HashAlgorithmSHA256, Digest: sha256Hash[:]},
			out:  append([]byte{0x00, 0x0b}, sha256Hash[:]...),
		},
		{
			desc: "WrongDigestSize",
			in:   TaggedHash{HashAlg: HashAlgorithmSHA256, Digest: sha1Hash[:]},
			err:  "cannot marshal argument at index 0: cannot process custom type tpm2.TaggedHash: invalid digest size 20",
		},
		{
			desc: "UnknownAlg",
			in:   TaggedHash{HashAlg: HashAlgorithmNull, Digest: sha1Hash[:]},
			err:  "cannot marshal argument at index 0: cannot process custom type tpm2.TaggedHash: cannot determine digest size for unknown algorithm TPM_ALG_NULL",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := mu.MarshalToBytes(&data.in)
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
			n, err := mu.UnmarshalFromBytes(out, &a)
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

	t.Run("UnmarshalTruncated", func(t *testing.T) {
		in := TaggedHash{HashAlg: HashAlgorithmSHA256, Digest: sha256Hash[:]}
		out, err := mu.MarshalToBytes(&in)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		out = out[0:32]
		_, err = mu.UnmarshalFromBytes(out, &in)
		if err == nil {
			t.Fatalf("UnmarshalFromBytes should fail to unmarshal a TaggedHash that is too short")
		}
		if err.Error() != "cannot unmarshal argument at index 0: cannot process custom type tpm2.TaggedHash: cannot read digest: unexpected EOF" {
			t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
		}
	})

	t.Run("UnmarshalFromLongerBuffer", func(t *testing.T) {
		in := TaggedHash{HashAlg: HashAlgorithmSHA256, Digest: sha256Hash[:]}
		out, err := mu.MarshalToBytes(&in)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		expectedN := len(out)
		out = append(out, []byte{0, 0, 0, 0}...)

		var a TaggedHash
		n, err := mu.UnmarshalFromBytes(out, &a)
		if err != nil {
			t.Fatalf("UnmarshalFromBytes failed: %v", err)
		}
		if n != expectedN {
			t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
		}

		if !reflect.DeepEqual(in, a) {
			t.Errorf("UnmarshalFromBytes didn't return the original data")
		}
	})

	t.Run("UnmarshalUnknownAlg", func(t *testing.T) {
		in := TaggedHash{HashAlg: HashAlgorithmSHA256, Digest: sha256Hash[:]}
		out, err := mu.MarshalToBytes(&in)
		if err != nil {
			t.Fatalf("MarshalToBytes failed: %v", err)
		}

		out[1] = 0x05
		_, err = mu.UnmarshalFromBytes(out, &in)
		if err == nil {
			t.Fatalf("UnmarshalFromBytes should fail to unmarshal a TaggedHash with an unknown algorithm")
		}
		if err.Error() != "cannot unmarshal argument at index 0: cannot process custom type tpm2.TaggedHash: cannot determine digest size "+
			"for unknown algorithm TPM_ALG_HMAC" {
			t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
		}
	})
}

func TestPublicName(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
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
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM(t, tpm)

	owner := tpm.OwnerHandleContext()

	pub := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead),
		Size:    64}
	rc, err := tpm.NVDefineSpace(owner, nil, &pub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, rc, owner)

	name, err := pub.Name()
	if err != nil {
		t.Fatalf("NVPublic.Name() failed: %v", err)
	}

	// rc.Name() is what the TPM returned from NVReadPublic
	if !bytes.Equal(rc.Name(), name) {
		t.Errorf("NVPublic.Name() returned an unexpected name")
	}
}

func TestPCRSelectionListSort(t *testing.T) {
	orig := PCRSelectionList{
		{Hash: HashAlgorithmSHA384, Select: []int{5, 3, 8}},
		{Hash: HashAlgorithmSHA256, Select: []int{1, 2, 0}},
		{Hash: HashAlgorithmSHA1, Select: []int{8, 3, 7, 4}},
		{Hash: HashAlgorithmSHA512, Select: []int{9, 10, 2, 1, 5}},
	}
	sorted := orig.Sort()
	expected := PCRSelectionList{
		{Hash: HashAlgorithmSHA1, Select: []int{3, 4, 7, 8}},
		{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2}},
		{Hash: HashAlgorithmSHA384, Select: []int{3, 5, 8}},
		{Hash: HashAlgorithmSHA512, Select: []int{1, 2, 5, 9, 10}},
	}

	if !reflect.DeepEqual(sorted, expected) {
		t.Errorf("Unexpected result: %v", sorted)
	}
	if !sorted.Equal(expected) {
		t.Errorf("Result should be equivalent")
	}
}

func TestPCRSelectionListEqual(t *testing.T) {
	for _, data := range []struct {
		desc  string
		l     PCRSelectionList
		r     PCRSelectionList
		equal bool
	}{
		{
			desc:  "DifferentLength",
			l:     PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{7}}, {Hash: HashAlgorithmSHA256, Select: []int{7}}},
			r:     PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{7}}},
			equal: false,
		},
		{
			desc:  "DifferentOrdering",
			l:     PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{7}}, {Hash: HashAlgorithmSHA256, Select: []int{7}}},
			r:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}, {Hash: HashAlgorithmSHA1, Select: []int{7}}},
			equal: false,
		},
		{
			desc:  "DifferentSelectionLength",
			l:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
			r:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
			equal: false,
		},
		{
			desc:  "DifferentSelection",
			l:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7, 9}}},
			r:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
			equal: false,
		},
		{
			desc:  "Match",
			l:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
			r:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
			equal: true,
		},
		{
			desc:  "MatchWithDifferentSelectionOrdering",
			l:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
			r:     PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{8, 7}}},
			equal: true,
		},
		{
			desc:  "MatchMultiple",
			l:     PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{0, 5, 2}}, {Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
			r:     PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{2, 0, 5}}, {Hash: HashAlgorithmSHA256, Select: []int{8, 7}}},
			equal: true,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			if data.l.Equal(data.r) != data.equal {
				t.Errorf("Equal returned the wrong result")
			}
		})
	}
}

func TestPCRSelectionListMerge(t *testing.T) {
	for _, data := range []struct {
		desc           string
		x, y, expected PCRSelectionList
	}{
		{
			desc:     "SingleSelection",
			x:        PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 1}}},
			y:        PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{5, 1, 3}}},
			expected: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 5}}},
		},
		{
			desc: "MultipleSelection/1",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3}},
				{Hash: HashAlgorithmSHA1, Select: []int{5, 8, 7}},
			},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{5, 0, 9}},
				{Hash: HashAlgorithmSHA1, Select: []int{2, 0, 7}},
			},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 5, 9}},
				{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 5, 7, 8}},
			},
		},
		{
			desc: "MultipleSelection/2",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3}},
				{Hash: HashAlgorithmSHA1, Select: []int{5, 8, 7}},
			},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{2, 0, 7}},
				{Hash: HashAlgorithmSHA256, Select: []int{5, 0, 9}},
			},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 5, 9}},
				{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 5, 7, 8}},
			},
		},
		{
			desc: "MismatchedLength",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3}},
				{Hash: HashAlgorithmSHA1, Select: []int{5, 8, 7}},
			},
			y: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{5, 0, 9}}},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 5, 9}},
				{Hash: HashAlgorithmSHA1, Select: []int{5, 7, 8}},
			},
		},
		{
			desc: "NewSelection",
			x:    PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 1}}},
			y:    PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{5, 1, 3}}},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2}},
				{Hash: HashAlgorithmSHA1, Select: []int{1, 3, 5}},
			},
		},
		{
			desc: "DuplicateSelection/1",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{5, 2, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 3, 1}},
			},
			y: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{3, 4, 2, 7}}},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{2, 4, 5, 6, 7}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 3}},
			},
		},
		{
			desc: "DuplicateSelection/2",
			x:    PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{5, 2, 6}}},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{3, 1}},
				{Hash: HashAlgorithmSHA256, Select: []int{2, 4, 0}},
			},
			expected: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			res := data.x.Merge(data.y)
			if !reflect.DeepEqual(res, data.expected) {
				t.Errorf("Unexpected result: %v", res)
			}
		})
	}
}

func TestPCRSelectionListRemove(t *testing.T) {
	for _, data := range []struct {
		desc           string
		x, y, expected PCRSelectionList
		err            string
	}{
		{
			desc:     "SingleSelection",
			x:        PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y:        PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 4}}},
			expected: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{1, 5}}},
		},
		{
			desc:     "None",
			x:        PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y:        PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 3, 4}}},
			expected: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
		},
		{
			desc:     "SingleSelectionEmptyResult",
			x:        PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y:        PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			expected: PCRSelectionList{},
		},
		{
			desc: "MultipleSelection/1",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{1, 3, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 4, 5}}},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 4, 5}},
				{Hash: HashAlgorithmSHA256, Select: []int{1, 2, 3}}},
		},
		{
			desc: "MultipleSelection/2",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 4, 5}},
				{Hash: HashAlgorithmSHA1, Select: []int{1, 3, 6}}},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 4, 5}},
				{Hash: HashAlgorithmSHA256, Select: []int{1, 2, 3}}},
		},
		{
			desc: "MultipleSectionEmptyResult/1",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{1, 3, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			expected: PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{0, 2, 4, 5}}},
		},
		{
			desc: "MultipleSelectionEmptyResult/2",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			expected: PCRSelectionList{},
		},
		{
			desc: "MismatchedLength",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}}},
			expected: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
		},
		{
			desc: "DuplicateSelection",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 4, 5}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}},
			},
			y: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{0, 2, 3, 4}}},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{1, 5}},
				{Hash: HashAlgorithmSHA256, Select: []int{1, 5}},
			},
		},
		{
			desc: "MultipleEmptySelection",
			x: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
			y: PCRSelectionList{{Hash: HashAlgorithmSHA1}, {Hash: HashAlgorithmSHA256}},
			expected: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6}},
				{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			res := data.x.Remove(data.y)
			if !reflect.DeepEqual(res, data.expected) {
				t.Errorf("Unexpected result %v", res)
			}
		})
	}
}
