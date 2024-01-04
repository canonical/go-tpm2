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

type TestSchemeKeyedHashUnionContainer struct {
	Scheme  KeyedHashSchemeId
	Details SchemeKeyedHashUnion
}

func TestSchemeKeyedHashUnion(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   TestSchemeKeyedHashUnionContainer
		out  []byte
		err  string
	}{
		{
			desc: "HMAC",
			in: TestSchemeKeyedHashUnionContainer{
				Scheme:  KeyedHashSchemeHMAC,
				Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})},
			out: []byte{0x00, 0x05, 0x00, 0x0b},
		},
		{
			desc: "Null",
			in:   TestSchemeKeyedHashUnionContainer{Scheme: KeyedHashSchemeNull, Details: MakeSchemeKeyedHashUnion(EmptyValue)},
			out:  []byte{0x00, 0x10},
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

			var a TestSchemeKeyedHashUnionContainer
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

	t.Run("InvalidSelector", func(t *testing.T) {
		var a TestSchemeKeyedHashUnionContainer
		_, err := mu.UnmarshalFromBytes([]byte{0x00, 0x0b}, &a)
		if err == nil {
			t.Fatalf("UnmarshaFromBytes was expected to fail")
		}
		if err.Error() != "cannot unmarshal argument 0 whilst processing element of type tpm2.SchemeKeyedHashUnion: invalid selector value: TPM_ALG_SHA256\n\n"+
			"=== BEGIN STACK ===\n"+
			"... tpm2_test.TestSchemeKeyedHashUnionContainer field Details\n"+
			"=== END STACK ===\n" {
			t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
		}
	})
}
