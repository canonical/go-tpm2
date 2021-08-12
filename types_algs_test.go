// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"reflect"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

type TestSchemeKeyedHashUContainer struct {
	Scheme  KeyedHashSchemeId
	Details *SchemeKeyedHashU
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
			err: "cannot unmarshal argument whilst processing element of type tpm2.SchemeKeyedHashU: invalid selector value: TPM_ALG_SHA256\n\n" +
				"=== BEGIN STACK ===\n" +
				"... tpm2_test.TestSchemeKeyedHashUContainer field Details\n" +
				"=== END STACK ===\n",
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
