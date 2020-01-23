// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 18 - Attestation Commands

// Certify executes the TPM2_Certify command, which is used to prove that an object with a specific name is loaded in to the TPM.
// By producing an attestation, the TPM certifies that the object with a given name is loaded in to the TPM and consistent with a
// valid sensitive area.
//
// The objectContext parameter corresponds to the object for which to produce an attestation. The command requires authorization with
// the admin role for objectContext, provided via objectContextAuth.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with it. This command requires
// authorization with the user auth role for signContext, provided via signContextAuth.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a *TPMHandleError error with an error
// code of ErrorKey will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is AlgorithmNull, then inScheme must be provided
// to specify a valid signing scheme for the key. If it isn't, a *TPMParameterError error with an error code of ErrorScheme will be
// returned for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not AlgorithmNull, then inScheme may be nil. If
// it is provided, then the specified scheme must match that of the signing key, else a *TPMParameterError error with an error code of
// ErrorScheme will be returned for parameter index 2.
//
// On successful, it returns an attestation structure detailing the name of the object associated with objectContext. If signContext
// is not nil, the attestation structure will be signed by the associated key and returned too.
func (t *TPMContext) Certify(objectContext, signContext HandleContext, qualifyingData Data, inScheme *SigScheme, objectContextAuth, signContextAuth interface{}, sessions ...*Session) (AttestRaw, *Signature, error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	var certifyInfo AttestRaw
	var signature Signature

	if err := t.RunCommand(CommandCertify, sessions,
		HandleContextWithAuth{Context: objectContext, Auth: objectContextAuth}, HandleContextWithAuth{Context: signContext, Auth: signContextAuth}, Separator,
		qualifyingData, inScheme, Separator,
		Separator,
		&certifyInfo, &signature); err != nil {
		return nil, nil, err
	}

	return certifyInfo, &signature, nil
}

// CertifyCreation executes the TPM2_CertifyCreation command, which is used to prove the association between the object represented
// by objectContext and its creation data represented by creationHash. It does this by computing a ticket from creationHash and the
// name of the object represented by objectContext and then verifying that it matches the provided creationTicket, which was provided
// by the TPM at object creation time.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with it. This command requires
// authorization with the user auth role for signContext, provided via signContextAuth.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a *TPMHandleError error with an error
// code of ErrorKey will be returned for handle index 1.
//
// If signContext is not nil and if the scheme of the key associated with signContext is AlgorithmNull, then inScheme must be provided
// to specify a valid signing scheme for the key. If it isn't, a *TPMParameterError error with an error code of ErrorScheme will be
// returned for parameter index 3.
//
// If signContext is not nil and the scheme of the key associated with signContext is not AlgorithmNull, then inScheme may be nil. If
// it is provided, then the specified scheme must match that of the signing key, else a *TPMParameterError error with an error code of
// ErrorScheme will be returned for parameter index 3.
//
// If creationTicket corresponds to an invalid ticket, a *TPMParameterError error with an error code of ErrorTicket will be returned
// for parameter index 4.
//
// If the digest generated for signing is greater than or has a larger size than the modulus of the key associated with signContext, a
// *TPMError with an error code of ErrorValue will be returned.
//
// If successful, it returns an attestation structure. If signContext is not nil, the attestation structure will be signed by the
// associated key and returned too.
func (t *TPMContext) CertifyCreation(signContext, objectContext HandleContext, qualifyingData Data, creationHash Digest, inScheme *SigScheme, creationTicket *TkCreation, signContextAuth interface{}, sessions ...*Session) (AttestRaw, *Signature, error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	var certifyInfo AttestRaw
	var signature Signature

	if err := t.RunCommand(CommandCertifyCreation, sessions,
		HandleContextWithAuth{Context: signContext, Auth: signContextAuth}, objectContext, Separator,
		qualifyingData, creationHash, inScheme, creationTicket, Separator,
		Separator,
		&certifyInfo, &signature); err != nil {
		return nil, nil, err
	}

	return certifyInfo, &signature, nil
}

// Quote executes the TPM2_Quote command in order to quote a set of PCR values. The TPM will hash the set of PCRs specified by the
// pcrs parameter.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with it. This command requires
// authorization with the user auth role for signContext, provided via signContextAuth.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a *TPMHandleError error with an error
// code of ErrorKey will be returned for handle index 1.
//
// If signContext is not nil and if the scheme of the key associated with signContext is AlgorithmNull, then inScheme must be provided
// to specify a valid signing scheme for the key. If it isn't, a *TPMParameterError error with an error code of ErrorScheme will be
// returned for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not AlgorithmNull, then inScheme may be nil. If
// it is provided, then the specified scheme must match that of the signing key, else a *TPMParameterError error with an error code of
// ErrorScheme will be returned for parameter index 2.
//
// On successful, it returns an attestation structure containing the hash of the PCRs selected by the pcrs parameter. If signContext
// is not nil, the attestation structure will be signed by the associated key and returned too.
func (t *TPMContext) Quote(signContext HandleContext, qualifyingData Data, inScheme *SigScheme, pcrs PCRSelectionList, signContextAuth interface{}, sessions ...*Session) (AttestRaw, *Signature, error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	var quoted AttestRaw
	var signature Signature

	if err := t.RunCommand(CommandQuote, sessions,
		HandleContextWithAuth{Context: signContext, Auth: signContextAuth}, Separator,
		qualifyingData, inScheme, pcrs, Separator,
		Separator,
		&quoted, &signature); err != nil {
		return nil, nil, err
	}

	return quoted, &signature, nil
}

// GetSessionAuditDigest executes the TPM2_GetSessionAuditDigest to obtain the current digest of the audit session corresponding to
// sessionContext.
//
// The privacyAdminContext argument must be a HandleContext that corresponds to HandleEndorsement. This command requires authorization
// with the user auth role for privacyAdminContext, provided via privacyAdminContextAuth.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with it. This command requires
// authorization with the user auth role for signContext, provided via signContextAuth.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a *TPMHandleError error with an error
// code of ErrorKey will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is AlgorithmNull, then inScheme must be provided
// to specify a valid signing scheme for the key. If it isn't, a *TPMParameterError error with an error code of ErrorScheme will be
// returned for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not AlgorithmNull, then inScheme may be nil. If
// it is provided, then the specified scheme must match that of the signing key, else a *TPMParameterError error with an error code of
// ErrorScheme will be returned for parameter index 2.
//
// On success, it returns an attestation structure detailing the current audit digest for sessionContext. If signContext is not nil,
// the attestation structure will be signed by the associated key and returned too.
func (t *TPMContext) GetSessionAuditDigest(privacyAdminContext, signContext, sessionContext HandleContext, qualifyingData Data, inScheme *SigScheme, privacyAdminContextAuth, signContextAuth interface{}, sessions ...*Session) (AttestRaw, *Signature, error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	var auditInfo AttestRaw
	var signature Signature

	if err := t.RunCommand(CommandGetSessionAuditDigest, sessions,
		HandleContextWithAuth{Context: privacyAdminContext, Auth: privacyAdminContextAuth}, HandleContextWithAuth{Context: signContext, Auth: signContextAuth}, Separator,
		qualifyingData, inScheme, Separator,
		Separator,
		&auditInfo, &signature); err != nil {
		return nil, nil, err
	}

	return auditInfo, &signature, nil
}

// GetCommandAuditDigest executes the TPM2_GetCommandAuditDigest command to obtain the current command audit digest, the current
// audit digest algorithm and a digest of the list of commands being audited.
//
// The privacyContext argument must be a resorce context corresponding to HandleEndorsement. This command requires authorization with
// the user auth role for privacyContext, provided via privacyContextAuth.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with it. This command requires
// authorization with the user auth role for signContext, provided via signContextAuth.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a *TPMHandleError error with an error
// code of ErrorKey will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is AlgorithmNull, then inScheme must be provided
// to specify a valid signing scheme for the key. If it isn't, a *TPMParameterError error with an error code of ErrorScheme will be
// returned for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not AlgorithmNull, then inScheme may be nil. If
// it is provided, then the specified scheme must match that of the signing key, else a *TPMParameterError error with an error code of
// ErrorScheme will be returned for parameter index 2.
//
// On success, it returns an attestation structure detailing the current command audit digest, digest algorithm and a digest of the
// list of commands being audited. If signContext is not nil, the attestation structure will be signed by the associated key and
// returned too.
func (t *TPMContext) GetCommandAuditDigest(privacyContext, signContext HandleContext, qualifyingData Data, inScheme *SigScheme, privacyContextAuth, signContextAuth interface{}, sessions ...*Session) (AttestRaw, *Signature, error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	var auditInfo AttestRaw
	var signature Signature

	if err := t.RunCommand(CommandGetCommandAuditDigest, sessions,
		HandleContextWithAuth{Context: privacyContext, Auth: privacyContextAuth}, HandleContextWithAuth{Context: signContext, Auth: signContextAuth}, Separator,
		qualifyingData, inScheme, Separator,
		Separator,
		&auditInfo, &signature); err != nil {
		return nil, nil, err
	}

	return auditInfo, &signature, nil
}

// GetTime executes the TPM2_GetTime command in order to obtain the current values of time and clock.
//
// The privacyAdminContext argument must be a HandleContext that corresponds to HandleEndorsement. The command requires authorization
// with the user auth role for privacyAdminContext, provided via privacyAdminContextAuth.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with it. This command requires
// authorization with the user auth role for signContext, provided via signContextAuth.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a *TPMHandleError error with an error
// code of ErrorKey will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is AlgorithmNull, then inScheme must be provided
// to specify a valid signing scheme for the key. If it isn't, a *TPMParameterError error with an error code of ErrorScheme will be
// returned for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not AlgorithmNull, then inScheme may be nil. If
// it is provided, then the specified scheme must match that of the signing key, else a *TPMParameterError error with an error code of
// ErrorScheme will be returned for parameter index 2.
//
// On success, it returns an attestation structure detailing the current values of time and clock. If signContext is not nil, the
// attestation structure will be signed by the associated key and returned too.
func (t *TPMContext) GetTime(privacyAdminContext, signContext HandleContext, qualifyingData Data, inScheme *SigScheme, privacyAdminContextAuth, signContextAuth interface{}, sessions ...*Session) (AttestRaw, *Signature, error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	var timeInfo AttestRaw
	var signature Signature

	if err := t.RunCommand(CommandGetTime, sessions,
		HandleContextWithAuth{Context: privacyAdminContext, Auth: privacyAdminContextAuth}, HandleContextWithAuth{Context: signContext, Auth: signContextAuth}, Separator,
		qualifyingData, inScheme, Separator,
		Separator,
		&timeInfo, &signature); err != nil {
		return nil, nil, err
	}

	return timeInfo, &signature, nil
}
