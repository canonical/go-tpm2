// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"crypto/rsa"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/util"
)

// NewExternalSealedObject is a wrapper around util.NewExternalSealedObject that sets
// the noDA attribute.
func NewExternalSealedObject(authValue tpm2.Auth, data []byte) (*tpm2.Public, *tpm2.Sensitive) {
	pub, sensitive := util.NewExternalSealedObject(tpm2.HashAlgorithmSHA256, authValue, data)
	pub.Attrs |= tpm2.AttrNoDA

	return pub, sensitive
}

// NewExternalRSAStoragePublicKey creates the public area for a RSA storage
// key from the supplied key.
func NewExternalRSAStoragePublicKey(key *rsa.PublicKey) *tpm2.Public {
	pub := util.NewExternalRSAPublicKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageDecrypt, nil, key)
	pub.Attrs |= tpm2.AttrRestricted
	pub.Params.RSADetail.Symmetric = tpm2.SymDefObject{
		Algorithm: tpm2.SymObjectAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}

	return pub
}

// NewExternalHMACKey is a wrapper around util.NewExternalHMACKey that sets the
// noDA attribute.
func NewExternalHMACKey(authValue tpm2.Auth, key []byte) (*tpm2.Public, *tpm2.Sensitive) {
	pub, sensitive := util.NewExternalHMACKey(tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA256, authValue, key)
	pub.Attrs |= tpm2.AttrNoDA

	return pub, sensitive
}
