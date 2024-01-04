// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"reflect"
	"testing"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

type typesObjectsSuite struct{}

var _ = Suite(&typesObjectsSuite{})

func (s *typesObjectsSuite) TestPublicIsStorageParentRSAValid(c *C) {
	pub := objectutil.NewRSAStorageKeyTemplate()
	c.Check(pub.IsStorageParent(), internal_testutil.IsTrue)
}

func (s *typesObjectsSuite) TestPublicIsStorageParentECCValid(c *C) {
	pub := objectutil.NewECCStorageKeyTemplate()
	c.Check(pub.IsStorageParent(), internal_testutil.IsTrue)
}

func (s *typesObjectsSuite) TestPublicIsStorageParentSymmetric(c *C) {
	pub := objectutil.NewSymmetricStorageKeyTemplate()
	c.Check(pub.IsStorageParent(), internal_testutil.IsTrue)
}

func (s *typesObjectsSuite) TestPublicIsStorageParentKeyedHash(c *C) {
	pub := objectutil.NewDerivationParentTemplate()
	c.Check(pub.IsStorageParent(), internal_testutil.IsFalse)
}

func (s *typesObjectsSuite) TestPublicIsStorageParentRSASign(c *C) {
	pub := objectutil.NewRSAAttestationKeyTemplate()
	c.Check(pub.IsStorageParent(), internal_testutil.IsFalse)
}

func (s *typesObjectsSuite) TestPublicIsStorageParentRSANoNameAlg(c *C) {
	pub := objectutil.NewRSAStorageKeyTemplate()
	pub.NameAlg = HashAlgorithmNull
	c.Check(pub.IsStorageParent(), internal_testutil.IsFalse)
}

type TestPublicIDUnionContainer struct {
	Alg    ObjectTypeId
	Unique PublicIDUnion
}

func TestPublicIDUnion(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   TestPublicIDUnionContainer
		out  []byte
		err  string
	}{
		{
			desc: "RSA",
			in: TestPublicIDUnionContainer{Alg: ObjectTypeRSA,
				Unique: MakePublicIDUnion(PublicKeyRSA{0x01, 0x02, 0x03})},
			out: []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
		{
			desc: "KeyedHash",
			in: TestPublicIDUnionContainer{Alg: ObjectTypeKeyedHash,
				Unique: MakePublicIDUnion(Digest{0x04, 0x05, 0x06, 0x07})},
			out: []byte{0x00, 0x08, 0x00, 0x04, 0x04, 0x05, 0x06, 0x07},
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

			var a TestPublicIDUnionContainer
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

	t.Run("InvalidSelector", func(t *testing.T) {
		var a TestPublicIDUnionContainer
		_, err := mu.UnmarshalFromBytes([]byte{0x00, 0x10}, &a)
		if err == nil {
			t.Fatalf("UnmarshaFromBytes was expected to fail")
		}
		if err.Error() != "cannot unmarshal argument 0 whilst processing element of type tpm2.PublicIDUnion: invalid selector value: TPM_ALG_NULL\n\n"+
			"=== BEGIN STACK ===\n"+
			"... tpm2_test.TestPublicIDUnionContainer field Unique\n"+
			"=== END STACK ===\n" {
			t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
		}
	})
}

func TestPublicName(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	pub, _, _, err := tpm.ReadPublic(primary)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	name, err := pub.ComputeName()
	if err != nil {
		t.Fatalf("Public.Name() failed: %v", err)
	}

	// primary.Name() is what the TPM returned at object creation
	if !bytes.Equal(primary.Name(), name) {
		t.Errorf("Public.Name() returned an unexpected name")
	}
}
