// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 24 - Hierarchy Commands

import (
	"fmt"
)

// CreatePrimary executes the TPM2_CreatePrimary command to create a new primary object in the hierarchy corresponding to
// primaryObject.
//
// The primaryObject parameter should correspond to a hierarchy. The command requires authorization with the user auth role for
// primaryObject, with session based authorization provided via primaryObjectAuthSession.
//
// A template for the object is provided via the inPublic parameter. The Type field of inPublic defines the algorithm for the object.
// The NameAlg field defines the digest algorithm for computing the name of the object. The Attrs field defines the attributes of
// the object. The AuthPolicy field allows an authorization policy to be defined for the new object.
//
// Data that will form part of the sensitive area of the object can be provided via inSensitive, which is optional.
//
// If the Attrs field of inPublic does not have the AttrSensitiveDataOrigin attribute set, then the sensitive data in the created
// object is initialized with the data provided via the Data field of inSensitive.
//
// If the Attrs field of inPublic has the AttrSensitiveDataOrigin attribute set and Type is AlgorithmSymCipher, then the sensitive
// data in the created object is initialized with a TPM generated key. The size of this key is determined by the value of the Params
// field of inPublic. If Type is AlgorithmKeyedHash, then the sensitive data in the created object is initialized with a TPM
// generated value that is the same size as the name algorithm selected by the NameAlg field of inPublic.
//
// If the Type field of inPublic is AlgorithmRSA or AlgorithmECC, then the sensitive data in the created object is initialized with
// a TPM generated private key. The size of this is determined by the value of the Params field of inPublic.
//
// If the Type field of inPublic is AlgorithmKeyedHash and the Attrs field has AttrSensitiveDataOrigin, AttrSign and AttrDecrypt all
// clear, then the created object is a sealed data object.
//
// If the Attrs field of inPublic has the AttrRestricted and AttrDecrypt attributes set, and the Type field is not AlgorithmKeyedHash,
// then the newly created object will be a storage parent.
//
// If the Attrs field of inPublic has the AttrRestricted and AttrDecrypt attributes set, and the Type field is AlgorithmKeyedHash, then
// the newly created object will be a derivation parent.
//
// The authorization value for the created object is initialized to the value of the UserAuth field of inSensitive.
//
// If there are no available slots for new objects on the TPM, a *TPMWarning error with a warning code of WarningObjectMemory will
// be returned.
//
// If the attributes in the Attrs field of inPublic are inconsistent or inappropriate for the usage, a *TPMParameterError error with
// an error code of ErrorAttributes will be returned for parameter index 2.
//
// If the NameAlg field of inPublic is AlgorithmNull, then a *TPMParameterError error with an error code of ErrorHash will be returned
// for parameter index 2.
//
// If an authorization policy is defined via the AuthPolicy field of inPublic then the length of the digest must match the name
// algorithm selected via the NameAlg field, else a *TPMParameterError error with an error code of ErrorSize is returned for parameter
// index 2.
//
// If the scheme in the Params field of inPublic is inappropriate for the usage, a *TPMParameterError errow with an error code of
// ErrorScheme will be returned for parameter index 2.
//
// If the digest algorithm specified by the scheme in the Params field of inPublic is inappropriate for the usage, a
// *TPMParameterError error with an error code of ErrorHash will be returned for parameter index 2.
//
// If the Type field of inPublic is not AlgorithmKeyedHash, a *TPMParameterError error with an error code of ErrorSymmetric will be
// returned for parameter index 2 if the symmetric algorithm specified in the Params field of inPublic is inappropriate for the
// usage.
//
// If the Type field of inPublic is AlgorithmECC and the KDF scheme specified in the Params field of inPublic is not AlgorithmNull,
// a *TPMParameterError error with an error code of ErrorKDF will be returned for parameter index 2.
//
// If the length of the UserAuth field of inSensitive is longer than the name algorithm selected by the NameAlg field of inPublic, a
// *TPMParameterError error with an error code of ErrorSize will be returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmRSA and the Params field specifies an unsupported exponent, a *TPMError with an error
// code of ErrorRange will be returned. If the specified key size is an unsupported value, a *TPMError with an error code of
// ErrorValue will be returned.
//
// If the Type field of inPublic is AlgorithmSymCipher and the key size is an unsupported value, a *TPMError with an error code of
// ErrorKeySize will be returned. If the AttrSensitiveDataOrigin attribute is not set and the length of the Data field of inSensitive
// does not match the key size specified in the Params field of inPublic, a *TPMError with an error code of ErrorKeySize will be
// returned.
//
// If the Type field of inPublic is AlgorithmKeyedHash and the AttrSensitiveDataOrigin attribute is not set, a *TPMError with an error
// code of ErrorSize will be returned if the length of the Data field of inSensitive is longer than permitted for the digest algorithm
// selected by the specified scheme.
//
// On success, a ResourceContext instance will be returned that corresponds to the newly created object on the TPM. It will not be
// necessary to call ResourceContext.SetAuthValue on it - this function sets the correct authorization value so that it can be used in
// subsequent commands that require knowledge of the authorization value. If the Type field of inPublic is AlgorithmKeyedHash or
// AlgorithmSymCipher, then the returned *Public object will have a Unique field that is the digest of the sensitive data and the value
// of the object's seed in the sensitive area, computed using the object's name algorithm. If the Type field of inPublic is
// AlgorithmECC or AlgorithmRSA, then the returned *Public object will have a Unique field containing details about the public part of
// the key, computed from the private part of the key.
//
// The returned *CreationData will contain a digest computed from the values of PCRs selected by the creationPCR parameter at creation
// time in the PCRDigest field. It will also contain the provided outsideInfo in the OutsideInfo field. The returned *TkCreation ticket
// can be used to prove the association between the created object and the returned *CreationData via the TPMContext.CertifyCreation
// method.
func (t *TPMContext) CreatePrimary(primaryObject ResourceContext, inSensitive *SensitiveCreate, inPublic *Public, outsideInfo Data, creationPCR PCRSelectionList, primaryObjectAuthSession SessionContext, sessions ...SessionContext) (ResourceContext, *Public, *CreationData, Digest, *TkCreation, error) {
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	var objectHandle Handle

	var outPublic publicSized
	var creationData creationDataSized
	var creationHash Digest
	var creationTicket TkCreation
	var name Name

	if err := t.RunCommand(CommandCreatePrimary, sessions,
		ResourceContextWithSession{Context: primaryObject, Session: primaryObjectAuthSession}, Separator,
		sensitiveCreateSized{inSensitive}, publicSized{inPublic}, outsideInfo, creationPCR, Separator,
		&objectHandle, Separator,
		&outPublic, &creationData, &creationHash, &creationTicket, &name); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if objectHandle.Type() != HandleTypeTransient {
		return nil, nil, nil, nil, nil, &InvalidResponseError{CommandCreatePrimary,
			fmt.Sprintf("handle 0x%08x returned from TPM is the wrong type", objectHandle)}
	}
	if outPublic.Ptr == nil || !outPublic.Ptr.compareName(name) {
		return nil, nil, nil, nil, nil, &InvalidResponseError{CommandCreatePrimary,
			"name and public area returned from TPM are not consistent"}
	}

	public, err := outPublic.Ptr.clone()
	if err != nil {
		return nil, nil, nil, nil, nil, &InvalidResponseError{CommandCreatePrimary,
			fmt.Sprintf("cannot copy returned public area from TPM: %v", err)}
	}
	rc := makeObjectContext(objectHandle, name, public)
	rc.auth = make([]byte, len(inSensitive.UserAuth))
	copy(rc.auth, inSensitive.UserAuth)

	return rc, outPublic.Ptr, creationData.Ptr, creationHash, &creationTicket, nil
}

// Clear executes the TPM2_Clear command to remove all context associated with the current owner. The command requires knowledge of
// the authorization value for either the platform or lockout hierarchy. The hierarchy is specified by passing a ResourceContext
// corresponding to either HandlePlatform or HandleLockout to authContext. The command requires authorization with the user auth
// role for authContext, with session based authorization provided via authContextAuthSession.
//
// On successful completion, all NV indices and objects associated with the current owner will have been evicted and subsequent use of
// ResourceContext instances associated with these resources will fail. The authorization values of the storage, endorsement and
// lockout hierarchies will have been cleared. It isn't necessary to update the corresponding ResourceContext instances for these
// by calling ResourceContext.SetAuthValue in order to use them in subsequent commands that require knowledge of the authorization
// value for those permanent resources.
//
// If the TPM2_Clear command has been disabled, a *TPMError error will be returned with an error code of ErrorDisabled.
func (t *TPMContext) Clear(authContext ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	var s []*sessionParam
	s, err := t.validateAndAppendAuthSessionParam(s, ResourceContextWithSession{Context: authContext, Session: authContextAuthSession})
	if err != nil {
		return fmt.Errorf("error whilst processing handle with authorization for authContext: %v", err)
	}
	s, err = t.validateAndAppendExtraSessionParams(s, sessions)
	if err != nil {
		return fmt.Errorf("error whilst processing non-auth sessions: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandClear, s, []interface{}{authContext}, nil)

	for _, h := range []Handle{HandleOwner, HandleEndorsement, HandleLockout} {
		if rc, exists := t.permanentResources[h]; exists {
			rc.auth = nil
		}
	}

	if err != nil {
		return err
	}

	return t.processResponse(ctx, nil, nil)
}

// ClearControl executes the TPM2_ClearControl command to enable or disable execution of the TPM2_Clear command (via the
// TPMContext.Clear function).
//
// If disable is true, then this command will disable the execution of TPM2_Clear. In this case, the command requires knowledge of
// the authorization value for the platform or lockout hierarchy. The hierarchy is specified via the authContext parameter by
// passing a ResourceContext corresponding to either HandlePlatform or HandleLockout.
//
// If disable is false, then this command will enable execution of TPM2_Clear. In this case, the command requires knowledge of the
// authorization value for the platform hierarchy, and authContext must be a ResourceContext corresponding to HandlePlatform. If
// authContext is a HandleContext corresponding to HandleOwner, a *TPMError error with an error code of ErrorAuthFail will be
// returned.
//
// The command requires the authorization with the user auth role for authContext, with session based authorization provided via
// authContextAuthSession.
func (t *TPMContext) ClearControl(authContext ResourceContext, disable bool, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.RunCommand(CommandClearControl, sessions,
		ResourceContextWithSession{Context: authContext, Session: authContextAuthSession}, Separator,
		disable)
}

// HierarchyChangeAuth executes the TPM2_HierarchyChangeAuth command to change the authorization value for the hierarchy associated
// with the authContext parameter. The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession.
//
// If the value of newAuth is longer than the context integrity digest algorithm for the TPM, a *TPMParameterError error with an
// error code of ErrorSize will be returned.
//
// On successful completion, the authorization value of the hierarchy associated with authContext will be set to the value of
// newAuth, and authContext will be updated to reflect this - it isn't necessary to update authContext with
// ResourceContext.SetAuthValue in order to use it in subsequent commands that require knowledge of the authorization value for the
// resource.
func (t *TPMContext) HierarchyChangeAuth(authContext ResourceContext, newAuth Auth, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	var s []*sessionParam
	s, err := t.validateAndAppendAuthSessionParam(s, ResourceContextWithSession{Context: authContext, Session: authContextAuthSession})
	if err != nil {
		return fmt.Errorf("error whilst processing handle with authorization for authHandle: %v", err)
	}
	s, err = t.validateAndAppendExtraSessionParams(s, sessions)
	if err != nil {
		return fmt.Errorf("error whilst processing non-auth sessions: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandHierarchyChangeAuth, s, []interface{}{authContext}, []interface{}{newAuth})
	if err != nil {
		return err
	}

	// If the HMAC key for this command includes the auth value for authHandle, the TPM will respond with a HMAC generated with a key
	// that includes newAuth instead.
	authContext.SetAuthValue(newAuth)

	return t.processResponse(ctx, nil, nil)
}
