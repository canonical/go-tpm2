// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
)

// NewRSAStorageKeyTemplate is a wrapper around templates.NewRSAStorageKeyWithDefaults
// that defines the noDA attribute.
func NewRSAStorageKeyTemplate() *tpm2.Public {
	template := templates.NewRSAStorageKeyWithDefaults()
	template.Attrs |= tpm2.AttrNoDA
	return template
}

// NewRestrictedRSASigningKeyTemplate is a wrapper around templates.NewRestrictedRSASigningKey
// that defines the noDA attribute, SHA256 for the name algorithm and 2048 bits for the key
// size.
func NewRestrictedRSASigningKeyTemplate(scheme *tpm2.RSAScheme) *tpm2.Public {
	template := templates.NewRestrictedRSASigningKey(tpm2.HashAlgorithmSHA256, scheme, 2048)
	template.Attrs |= tpm2.AttrNoDA
	return template
}

// NewRSAKeyTemplate is a wrapper around templates.NewRSAKey that defines the noDA attribute,
// SHA256 for the name algorithm and 2048 bits for the key size.
func NewRSAKeyTemplate(usage templates.KeyUsage, scheme *tpm2.RSAScheme) *tpm2.Public {
	template := templates.NewRSAKey(tpm2.HashAlgorithmSHA256, usage, scheme, 2048)
	template.Attrs |= tpm2.AttrNoDA
	return template
}

// NewSealedObject is a wrapper around templates.NewSealedObject that defines the noDA
// attribute.
func NewSealedObjectTemplate() *tpm2.Public {
	template := templates.NewSealedObject(tpm2.HashAlgorithmSHA256)
	template.Attrs |= tpm2.AttrNoDA
	return template
}

// NewECCStorageKeyTemplate is a wrapper around templates.NewECCStorageKeyWithDefaults
// that defines the noDA attribute.
func NewECCStorageKeyTemplate() *tpm2.Public {
	template := templates.NewECCStorageKeyWithDefaults()
	template.Attrs |= tpm2.AttrNoDA
	return template
}

// NewRestrictedECCSigningKeyTemplate is a wrapper around templates.NewRestrictedECCSigningKey
// that defines the noDA attribute, SHA256 for the name algorithm and NIST-P256 as the curve.
func NewRestrictedECCSigningKeyTemplate(scheme *tpm2.ECCScheme) *tpm2.Public {
	template := templates.NewRestrictedECCSigningKey(tpm2.HashAlgorithmSHA256, scheme, tpm2.ECCCurveNIST_P256)
	template.Attrs |= tpm2.AttrNoDA
	return template
}

// NewECCKeyTemplate is a wrapper around templates.NewECCKey that defines the noDA attribute,
// SHA256 for the name algorithm and NIST-P256 as the curve.
func NewECCKeyTemplate(usage templates.KeyUsage, scheme *tpm2.ECCScheme) *tpm2.Public {
	template := templates.NewECCKey(tpm2.HashAlgorithmSHA256, usage, scheme, tpm2.ECCCurveNIST_P256)
	template.Attrs |= tpm2.AttrNoDA
	return template
}
