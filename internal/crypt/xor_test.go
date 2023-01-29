// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypt_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"testing"

	. "github.com/canonical/go-tpm2/internal/crypt"
)

func TestXORObfuscation(t *testing.T) {
	for _, data := range []struct {
		desc      string
		keyLength int
		alg       crypto.Hash
		data      []byte
	}{
		{
			desc:      "SHA256/1",
			keyLength: 32,
			alg:       crypto.SHA256,
			data:      []byte("secret data"),
		},
		{
			desc:      "SHA256/2",
			keyLength: 60,
			alg:       crypto.SHA256,
			data:      []byte("super secret data"),
		},
		{
			desc:      "SHA1/1",
			keyLength: 60,
			alg:       crypto.SHA1,
			data:      []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			key := make([]byte, data.keyLength)
			rand.Read(key)

			digestSize := data.alg.Size()

			contextU := make([]byte, digestSize)
			rand.Read(contextU)

			contextV := make([]byte, digestSize)
			rand.Read(contextV)

			var secret []byte
			secret = append(secret, data.data...)

			XORObfuscation(data.alg, key, contextU, contextV, secret)
			XORObfuscation(data.alg, key, contextU, contextV, secret)

			if !bytes.Equal(secret, data.data) {
				t.Errorf("Encrypt / decrypt with XOR obfuscation didn't produce the original data")
			}
		})
	}
}
