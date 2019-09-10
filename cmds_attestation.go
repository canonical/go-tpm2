// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 18 - Attestation Commands

// func (t *TPMContext) Certify(objectContext, signContext ResourceContext, qualifyingData Data,
//	inScheme *SigScheme, sessions ...*Session) (AttestRaw, *Signature, error) {
// }

func (t *TPMContext) CertifyCreation(signContext, objectContext ResourceContext, qualifyingData Data,
	creationHash Digest, inScheme *SigScheme, creationTicket *TkCreation,
	signContextAuth interface{}, sessions ...*Session) (AttestRaw, *Signature, error) {
	if creationTicket == nil {
		return nil, nil, makeInvalidParamError("creationTicket", "nil value")
	}

	if signContext == nil {
		signContext = permanentContext(HandleNull)
	}
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: AlgorithmNull}
	}

	var certifyInfo AttestRaw
	var signature Signature

	if err := t.RunCommand(CommandCertifyCreation, sessions,
		ResourceWithAuth{Context: signContext, Auth: signContextAuth}, objectContext, Separator,
		qualifyingData, creationHash, inScheme, creationTicket, Separator, Separator, &certifyInfo,
		&signature); err != nil {
		return nil, nil, err
	}

	return certifyInfo, &signature, nil
}

// func (t *TPMContext) Quote(signContext ResourceContext, qualifyingData Data, inScheme *SigScheme,
//	pcrSelection PCRSelectionList, session ...*Session) (AttestRaw, *Signature, error) {
// }

// func (t *TPMContext) GetSessionAuditDigest(privacyAdminHandle Handle, signContext,
//	sessionContext ResourceContext, qualifyingData Data, inScheme *SigScheme, sessions ...*Session) (AttestRaw,
//	*Signature, error) {
// }

// func (t *TPMContext) GetCommandAuditDigest(privacyHandle Handle, signContext ResourceContext,
//	qualifyingData Data, inScheme *SigScheme, sessions ...*Session) (AttestRaw, *Signature, error) {
// }

// func (t *TPMContext) GetTime(privacyAdminHandle Handle, signContext ResourceContext, qualifyingData Data,
//	inScheme *SigScheme, sessions ...*Session) (AttestRaw, *Signature, error) {
// }
