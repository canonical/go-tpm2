// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
)

// NewExternalSealedObject is a wrapper around [objectutil.NewSealedObject] that sets
// the noDA attribute.
//
// Deprecated: use [objectutil.NewSealedObject] with the
// [objectutil.WithoutDictionaryAttackProtection] option.
func NewExternalSealedObject(authValue tpm2.Auth, data []byte) (*tpm2.Public, *tpm2.Sensitive) {
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, data, authValue,
		objectutil.WithoutDictionaryAttackProtection())
	if err != nil {
		panic(err)
	}

	return pub, sensitive
}

// NewExternalRSAStoragePublicKey creates the public area for a RSA storage key from the supplied
// key.
func NewExternalRSAStoragePublicKey(key *rsa.PublicKey) *tpm2.Public {
	pub, err := objectutil.NewRSAPublicKey(key, objectutil.WithoutDictionaryAttackProtection())
	if err != nil {
		panic(err)
	}
	pub.Attrs |= (tpm2.AttrRestricted | tpm2.AttrDecrypt)
	pub.Attrs &^= tpm2.AttrSign
	pub.Params.RSADetail.Symmetric = tpm2.SymDefObject{
		Algorithm: tpm2.SymObjectAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}

	return pub
}

// NewExternalHMACKey is a wrapper around [objectutil.NewHMACKey] that sets the
// noDA attribute.
//
// Deprecated: use [objectutil.NewHMACKey] with the
// [objectutil.WithoutDictionaryAttackProtection] option.
func NewExternalHMACKey(authValue tpm2.Auth, key []byte) (*tpm2.Public, *tpm2.Sensitive) {
	pub, sensitive, err := objectutil.NewHMACKey(rand.Reader, key, authValue, objectutil.WithoutDictionaryAttackProtection())
	if err != nil {
		panic(err)
	}

	return pub, sensitive
}
