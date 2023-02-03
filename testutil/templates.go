// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
)

func rsaSchemeOption(scheme *tpm2.RSAScheme) objectutil.PublicTemplateOption {
	schemeId := tpm2.RSASchemeNull
	hashAlg := tpm2.HashAlgorithmNull
	if scheme != nil {
		schemeId = scheme.Scheme
		if tpm2.AsymSchemeId(schemeId).HasDigest() {
			hashAlg = scheme.Details.Any(tpm2.AsymSchemeId(schemeId)).HashAlg
		}
	}
	return objectutil.WithRSAScheme(schemeId, hashAlg)
}

func eccSchemeOption(scheme *tpm2.ECCScheme) objectutil.PublicTemplateOption {
	schemeId := tpm2.ECCSchemeNull
	hashAlg := tpm2.HashAlgorithmNull
	if scheme != nil {
		schemeId = scheme.Scheme
		if tpm2.AsymSchemeId(schemeId).HasDigest() {
			hashAlg = scheme.Details.Any(tpm2.AsymSchemeId(schemeId)).HashAlg
		}
	}
	return objectutil.WithECCScheme(schemeId, hashAlg)
}

// NewRSAStorageKeyTemplate is a wrapper around [objectutil.NewRSAStorageKeyTemplate] that defines the
// noDA attribute.
func NewRSAStorageKeyTemplate() *tpm2.Public {
	return objectutil.NewRSAStorageKeyTemplate(objectutil.WithoutDictionaryAttackProtection())
}

// NewRestrictedRSASigningKeyTemplate is a wrapper around [objectutil.NewRSAAttestationKeyTemplate]
// that defines the noDA attribute.
func NewRestrictedRSASigningKeyTemplate(scheme *tpm2.RSAScheme) *tpm2.Public {
	options := []objectutil.PublicTemplateOption{objectutil.WithoutDictionaryAttackProtection()}
	if scheme != nil {
		options = append(options, rsaSchemeOption(scheme))
	}
	return objectutil.NewRSAAttestationKeyTemplate(options...)
}

// NewRSAKeyTemplate is a wrapper around [objectutil.NewRSAKeyTemplate] that defines the noDA
// attribute.
func NewRSAKeyTemplate(usage objectutil.Usage, scheme *tpm2.RSAScheme) *tpm2.Public {
	return objectutil.NewRSAKeyTemplate(usage,
		objectutil.WithoutDictionaryAttackProtection(),
		rsaSchemeOption(scheme))
}

// NewSealedObject is a wrapper around [objectutil.NewSealedObjectTemplate] that defines the noDA
// attribute.
func NewSealedObjectTemplate() *tpm2.Public {
	return objectutil.NewSealedObjectTemplate(objectutil.WithoutDictionaryAttackProtection())
}

// NewECCStorageKeyTemplate is a wrapper around [objectutil.NewECCStorageKeyTemplate] that defines the
// noDA attribute.
func NewECCStorageKeyTemplate() *tpm2.Public {
	return objectutil.NewECCStorageKeyTemplate(objectutil.WithoutDictionaryAttackProtection())
}

// NewRestrictedECCSigningKeyTemplate is a wrapper around [objectutil.NewECCAttestationKeyTemplate]
// that defines the noDA attribute.
func NewRestrictedECCSigningKeyTemplate(scheme *tpm2.ECCScheme) *tpm2.Public {
	options := []objectutil.PublicTemplateOption{objectutil.WithoutDictionaryAttackProtection()}
	if scheme != nil {
		options = append(options, eccSchemeOption(scheme))
	}
	return objectutil.NewECCAttestationKeyTemplate(options...)
}

// NewECCKeyTemplate is a wrapper around [objectutil.NewECCKeyTemplate] that defines the noDA
// attribute.
func NewECCKeyTemplate(usage objectutil.Usage, scheme *tpm2.ECCScheme) *tpm2.Public {
	return objectutil.NewECCKeyTemplate(usage,
		objectutil.WithoutDictionaryAttackProtection(),
		eccSchemeOption(scheme))
}
