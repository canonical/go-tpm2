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

// PolicySecret executes the TPM2_PolicySecret command to include a secret-based authorization to the policy
// session associated with policySession. The command requires the user auth role for authContext, which is
// provided via authContextAuth.
//
// On successful completion, knowledge of the authorization value associated with authHandle is proven. The
// policy digest of the session associated with policySession will be extended to include the name of authContext
// and the value of policyRef.
//
// The cpHashA parameter allows the caller to provide a command parameter digest, which provides a mechanism to
// restrict the commands that the session associated with policySession may be used to authenticate. On
// successful completion, the value of cpHashA is recorded on the session context associated with policySession.
//
// If the expiration parameter is not 0, it sets a timeout in seconds since the start of the session by which the
// authorization will expire. If set to a negative number, a timeout value and corresponding ticket value will be
// returned if the session associated with policySession is not a trial session.
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

// PolicyOR executes the TPM2_PolicyOR command to allow a policy to be satisfied by different sets of conditions.
// If policySession does not correspond to a trial session, it determines if the current policy digest of the
// session context associated with policySession is contained in the list of digests specified via pHashList.
// If it is not, then an error is returned without making any changes to the session context.
//
// On successful completion, the policy digest of the session context associated with policySession is cleared,
// and then extended to include the concatenation of all of the digests contained in pHashList.
func (t *TPMContext) PolicyOR(policySession ResourceContext, pHashList DigestList) error {
	return t.RunCommand(CommandPolicyOR, nil, policySession, Separator, pHashList)
}

// PolicyPCR executes the TPM2_PolicyPCR command to gate a policy based on the values of the PCRs selected via
// the pcrs parameter. If no digest has been specified via the pcrDigest parameter, the policy digest of the
// session context associated with policySession will be extended to include the value of the PCR selection and a
// digest computed from the selected PCR contents.
//
// If pcrDigest is provided and policySession does not correspond to a trial session, the digest computed from
// the selected PCRs will be compared to this value and an error will be returned if they don't match, without
// making any changes to the session context. If policySession corresponds to a trial session, the digest computed
// from the selected PCRs is not compared to the value of pcrDigest - instead, the policy digest of the session
// is extended to include the value of the PCR selection and the value of pcrDigest.
func (t *TPMContext) PolicyPCR(policySession ResourceContext, pcrDigest Digest, pcrs PCRSelectionList,
	sessions ...*Session) error {
	return t.RunCommand(CommandPolicyPCR, sessions, policySession, Separator, pcrDigest, pcrs)
}

// func (t *TPMContext) PolicyLocality(policySession ResourceContext, loclity Locality) error {
// }

// PolicyNV executes the TPM2_PolicyNV command to gate a policy based on the contents of the NV index associated
// with nvIndex. The caller specifies a comparison operator via the operation parameter, and a value to which
// to compare the value of the NV index to via the operandB parameter. The offset parameter specifies the offset
// in to the NV index data from which the first operand begins.
//
// If the comparison fails and policySession does not correspond to a trial session, an error will be returned
// and no changes will be made to the session context associated with policySession.
//
// The command requires authorization to read the NV index, defined by the state of the AttrNVPPRead,
// AttrNVOwnerRead, AttrNVAuthRead and AttrNVPolicyRead attributes. The handle used for authorization is specified
// via authContext. If the NV index has the AttrNVPPRead attribute, authorization can be satisfied with
// HandlePlatform. If the NV index has the AttrNVOwnerRead attribute, authorization can be satisfied with
// HandleOwner. If the NV index has the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be
// satisfied with nvIndex. The command requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyRead attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the policy digest of the session context associated with policySession is extended to
// include the values of operandB, offset, operation and the name of nvIndex.
func (t *TPMContext) PolicyNV(authContext, nvIndex, policySession ResourceContext, operandB Operand,
	offset uint16, operation ArithmeticOp, authContextAuth interface{}, sessions ...*Session) error {
	return t.RunCommand(CommandPolicyNV, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, policySession, Separator,
		operandB, offset, operation)
}

// func (t *TPMContext) PolicyCounterTimer(policySession ResourceContext, operandB Operand, offset uint16,
//	operation ArithmeticOp, sessions ...*Session) error {
// }

// PolicyCommandCode executes the TPM2_PolicyCommandCode command to indicate that an authorization should be
// limited to a specific command. On successful completion, the policy digest of the session context associated
// with policySession will be extended to include the value of the specified command code, and the command code
// will be recorded on the session context.
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

// PolicyAuthValue executes the TPM2_PolicyAuthValue command to bind the policy to the authorization value of the
// entity on which the authorization is used. On successful completion, the policy digest of the session context
// associated with policySession will be extended to record that this assertion has been executed, and a flag
// will be set on the session context to indicate that the authorization value of the entity on which the
// authorization is used must be included in the key for computing the command HMAC when the authorization is
// used.
//
// When using policySession in a subsequent authorization, the AuthValue field of the Session struct that
// references policySession must be set to the authorization value of the entity being authorized.
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

// PolicyPassword executes the TPM2_PolicyPassword command to bind the policy to the authorization value of the
// entity on which the authorization is used. On successful completion, the policy digest of the session context
// associated with policySession will be extended to record that this assertion has been executed, and a flag
// will be set on the session context to indicate that the authorization value of the entity on which the
// authorization is used must be included in cleartext in the command authorization when the authorization is
// used.
//
// When using policySession in a subsequent authorization, the AuthValue field of the Session struct that
// references policySession must be set to the authorization value of the entity being authorized.
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

// PolicyGetDigest executes the TPM2_PolicyGetDigest command to return the current policy digest of the session
// context associated with policySession.
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
