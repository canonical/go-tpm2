// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 23 - Enhanced Authorization (EA) Commands

import (
	"errors"
	"fmt"
)

// func (t *TPMContext) PolicySigned(authObject, policySession ResourceContext, includeNonceTPM bool,
//	cpHashA Digest,	policyRef Nonce, expiration int32, auth *Signature, sessions ...*Session) (Timeout,
//	*TkAuth, error) {
// }

func (t *TPMContext) PolicySecret(authContext, policySession ResourceContext, cpHashA Digest, policyRef Nonce,
	expiration int32, authContextAuth interface{}, sessions ...*Session) (Timeout, *TkAuth, error) {
	if err := t.checkResourceContextParam(policySession); err != nil {
		return nil, nil, fmt.Errorf("invalid resource context for policySession: %v", err)
	}

	sessionContext, isSession := policySession.(SessionContext)
	if !isSession {
		return nil, nil, errors.New("invalid resource context for policySession: not a session context")
	}

	var timeout Timeout
	var policyTicket TkAuth

	if err := t.RunCommand(CommandPolicySecret, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, policySession, Separator,
		sessionContext.NonceTPM(), cpHashA, policyRef, expiration, Separator, Separator, &timeout,
		&policyTicket); err != nil {
		return nil, nil, err
	}

	return timeout, &policyTicket, nil
}

// func (t *TPMContext) PolicyTicket(policySession ResourceContext, timeout Timeout, cpHashA Digest,
//	policyRef Nonce, authName Name, ticket *TkAuth, sessions ...*Session) error {
// }

func (t *TPMContext) PolicyOR(policySession ResourceContext, pHashList DigestList) error {
	return t.RunCommand(CommandPolicyOR, nil, policySession, Separator, pHashList)
}

func (t *TPMContext) PolicyPCR(policySession ResourceContext, pcrDigest Digest, pcrs PCRSelectionList,
	sessions ...*Session) error {
	return t.RunCommand(CommandPolicyPCR, sessions, policySession, Separator, pcrDigest, pcrs)
}

// func (t *TPMContext) PolicyLocality(policySession ResourceContext, loclity Locality) error {
// }

// func (t *TPMContext) PolicyNV(authHandle, nvIndex, policySession ResourceContext, operandB Operand,
//	offset uint16, operation ArithmeticOp, sessions ...*Session) error {
// }

// func (t *TPMContext) PolicyCounterTimer(policySession ResourceContext, operandB Operand, offset uint16,
//	operation ArithmeticOp, sessions ...*Session) error {
// }

func (t *TPMContext) PolicyCommandCode(policySession ResourceContext, code CommandCode) error {
	return t.RunCommand(CommandPolicyCommandCode, nil, policySession, Separator, code)
}

// func (t *TPMContext) PolicyPhysicalPresence(policySession ResourceContext) error {
// }

// func (t *TPMContext) PolicyCpHash(policySession ResourceContext, cpHashA Digest, sessions ...*Session) error {
// }

// func (t *TPMContext) PolicyNameHash(policySession ResourceContext, nameHash Digest,
//	sessions ...*Session) error {
// }

// func (t *TPMContext) PolicyDuplicationSelect(policySession ResourceContext, objectName, newParentName Name,
//	includeObject bool, sessions ...*Session) error {
// }

// func (t *TPMContext) PolicyAuthorize(policySession ResourceContext, approvedPolicy Digest, policyRef Nonce,
//	keySign Name, checkTicket *TkVerified, sessions ...*Session) error {
// }

func (t *TPMContext) PolicyAuthValue(policySession ResourceContext) error {
	if err := t.checkResourceContextParam(policySession); err != nil {
		return fmt.Errorf("invalid resource context for policySession: %v", err)
	}

	sc, isSessionContext := policySession.(*sessionContext)
	if !isSessionContext {
		return errors.New("invalid resource context for policySession: not a session context")
	}

	if err := t.RunCommand(CommandPolicyAuthValue, nil, policySession); err != nil {
		return err
	}

	sc.policyHMACType = policyHMACTypeAuth
	return nil
}

func (t *TPMContext) PolicyPassword(policySession ResourceContext) error {
	if err := t.checkResourceContextParam(policySession); err != nil {
		return fmt.Errorf("invalid resource context for policySession: %v", err)
	}

	sc, isSessionContext := policySession.(*sessionContext)
	if !isSessionContext {
		return errors.New("invalid resource context for policySession: not a session context")
	}

	if err := t.RunCommand(CommandPolicyPassword, nil, policySession); err != nil {
		return err
	}

	sc.policyHMACType = policyHMACTypePassword
	return nil
}

func (t *TPMContext) PolicyGetDigest(policySession ResourceContext) (Digest, error) {
	var policyDigest Digest

	if err := t.RunCommand(CommandPolicyGetDigest, nil, policySession, Separator, Separator, Separator,
		&policyDigest); err != nil {
		return nil, err
	}

	return policyDigest, nil
}

// func (t *TPMContext) PolicyNvWritten(policySession ResourceContext, writtenSet bool) error {
// }

// func (t *TPMContext) PolicyTemplate(policySession ResourceContext, templateHash Digest,
//	sessions ...*Session) error {
// }

// func (t *TPMContext) PolicyAuthorizeNV(authHandle, nvIndex, policySession ResourceContext) error {
// }
