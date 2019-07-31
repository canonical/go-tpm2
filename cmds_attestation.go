// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) CertifyCreation(signContext, objectContext ResourceContext, qualifyingData Data,
	creationHash Digest, inScheme *SigScheme, creationTicket *TkCreation,
	signContextAuth interface{}, sessions ...*Session) (*Attest, *Signature, error) {
	if creationTicket == nil {
		return nil, nil, makeInvalidParamError("creationTicket", "nil value")
	}

	if signContext == nil {
		signContext, _ = t.WrapHandle(HandleNull)
	}
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: AlgorithmNull}
	}

	var certifyInfo Attest2B
	var signature Signature

	if err := t.RunCommand(CommandCertifyCreation, sessions,
		ResourceWithAuth{Context: signContext, Auth: signContextAuth}, objectContext, Separator,
		qualifyingData, creationHash, inScheme, creationTicket, Separator, Separator, &certifyInfo,
		&signature); err != nil {
		return nil, nil, err
	}

	return (*Attest)(&certifyInfo), &signature, nil
}