// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Secion 20 - Signing and Signature Verification

// VerifySignature executes the TPM2_VerifySignature command to validate the provided signature against a message
// with the provided digest, using the key associated with keyContext. On success, a valid TkVerified structure
// will be returned. If the signature is invalid, then an error will be returned.
func (t *TPMContext) VerifySignature(keyContext ResourceContext, digest Digest, signature *Signature,
	sessions ...*Session) (*TkVerified, error) {
	if signature == nil {
		return nil, makeInvalidParamError("signature", "nil value")
	}

	var validation TkVerified
	if err := t.RunCommand(CommandVerifySignature, sessions, keyContext, Separator, digest, signature,
		Separator, Separator, &validation); err != nil {
		return nil, err
	}

	return &validation, nil
}

// Sign executes the TPM2_Sign command to sign the provided digest with the key associated with keyContext.
// The function requires the user auth role for keyContext, provided via keyContextAuth.
//
// If the scheme of the key associated with keyContext is AlgorithmNull, then inScheme must be provided to
// specify a valid signing scheme for the key. If the scheme of the key associated with keyContext is not
// AlgorithmNull, then inScheme may be nil. If it is provided, then the specified scheme must match that of the
// signing key.
//
// If the key associated with keyContext has the AttrRestricted attribute, then the validation parameter must
// be provided as proof that the supplied digest was created by the TPM. If the key associated with keyContext
// does not have the AttrRestricted attribute, then validation may be nil. If it is provided, it must be a valid
// ticket.
func (t *TPMContext) Sign(keyContext ResourceContext, digest Digest, inScheme *SigScheme, validation *TkHashcheck,
	keyContextAuth interface{}, sessions ...*Session) (*Signature, error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: AlgorithmNull}
	}
	if validation == nil {
		validation = &TkHashcheck{Tag: TagHashcheck, Hierarchy: HandleNull}
	}

	var signature Signature

	if err := t.RunCommand(CommandSign, sessions, ResourceWithAuth{Context: keyContext, Auth: keyContextAuth},
		Separator, digest, inScheme, validation, Separator, Separator, &signature); err != nil {
		return nil, err
	}

	return &signature, nil
}
