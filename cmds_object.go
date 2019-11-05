// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 12 - Object Commands

import (
	"bytes"
	"fmt"
)

// Create executes the TPM2_Create command to create a new ordinary object as a child of the storage parent associated with
// parentContext.
//
// The command requires authorization with the user auth role for parentContext, provided via parentContextAuth.
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
// If the object associated with parentContext is not a valid storage parent object, a *TPMHandleError error with an error code of
// ErrorType will be returned for handle index 1.
//
// If there are no available slots for new objects on the TPM, a *TPMWarning error with a warning code of WarningObjectMemory will
// be returned.
//
// If the Attrs field of inPublic as the AttrSensitiveDataOrigin attribute set and the Data field of inSensitive has a non-zero size,
// or the AttrSensitiveDataOrigin attribute is clear and the Data field of inSensitive has a zero size, a *TPMParameterError error
// with an error code of ErrorAttributes will be returned for parameter index 1.
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
// If the Type field of inPublic is not AlgorithmKeyedHash and the AttrRestricted, AttrFixedParent and AttrDecrypt attributes of
// Attrs are set, a *TPMParameterError error with an error code of ErrorHash will be returned for parameter index 2 if the NameAlg
// field of inPublic does not select the same name algorithm as the parent object. A *TPMParameterError error with an error code
// of ErrorSymmetric will be returned for parameter index 2 if the symmetric algorithm specified in the Params field of inPublic
// does not match the symmetric algorithm of the parent object.
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
// On success, the private and public parts of the newly created object will be returned. The newly created object will not exist on
// the TPM. If the Type field of inPublic is AlgorithmKeyedHash or AlgorithmSymCipher, then the returned *Public object will have a
// Unique field that is the digest of the sensitive data and the value of the object's seed in the sensitive area, computed using the
// object's name algorithm. If the Type field of inPublic is AlgorithmECC or AlgorithmRSA, then the returned *Public object will
// have a Unique field containing details about the public part of the key, computed from the private part of the key.
//
// The returned *CreationData will contain a digest computed from the values of PCRs selected by the creationPCR parameter at creation
// time in the PCRDigest field. It will also contain the provided outsideInfo in the OutsideInfo field. The returned *TkCreation ticket
// can be used to prove the association between the created object and the returned *CreationData via the TPMContext.CertifyCreation
// method.
func (t *TPMContext) Create(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic *Public, outsideInfo Data, creationPCR PCRSelectionList, parentContextAuth interface{}, sessions ...*Session) (Private, *Public, *CreationData, Digest, *TkCreation, error) {
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	var outPrivate Private
	var outPublic publicSized
	var creationData creationDataSized
	var creationHash Digest
	var creationTicket TkCreation

	if err := t.RunCommand(CommandCreate, sessions,
		ResourceWithAuth{Context: parentContext, Auth: parentContextAuth}, Separator,
		sensitiveCreateSized{inSensitive}, publicSized{inPublic}, outsideInfo, creationPCR, Separator,
		Separator,
		&outPrivate, &outPublic, &creationData, &creationHash, &creationTicket); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return outPrivate, outPublic.Ptr, creationData.Ptr, creationHash, &creationTicket, nil
}

// Load executes the TPM2_Load command in order to load both the public and private parts of an object in to the TPM.
//
// The parentContext parameter corresponds to the parent key. The command requires authorization with the user auth role for
// parentContext, provided via parentContextAuth.
//
// The object to load is specified by providing the inPrivate and inPublic arguments.
//
// If there are no available slots for new objects on the TPM, a *TPMWarning error with a warning code of WarningObjectMemory will
// be returned.
//
// If inPrivate is empty, a *TPMParameterError error with an error code of ErrorSize will be returned for parameter index 1.
//
// If parentContext does not correspond to a storage parent, a *TPMHandleError error with an error code of ErrorType will be returned.
//
// If the name algorithm associated with inPublic is invalid, a *TPMParameterError error with an error code of ErrorHash will be
// returned for parameter index 2.
//
// If the integrity value or IV for inPrivate cannot be unmarshalled correctly, a *TPMParameterError error with an error code of
// either ErrorSize or ErrorInsufficient will be returned for parameter index 1. If the integrity check of inPrivate fails, a
// *TPMParameterError error with an error code of ErrorIntegrity will be returned for parameter index 1. If the size of the IV
// for inPrivate doesn't match the block size for the encryption algorithm, a *TPMParameterError error with an error code of
// ErrorValue will be returned for parameter index 1.
//
// TPM2_Load performs many of the same validations of the public attributes as TPM2_Create, and may return similar error codes as
// *TPMParameterError for parameter index 2.
//
// If the object associated with parentContext has the AttrFixedTPM attribute clear, some additional validation of the decrypted
// sensitive data is performed as detailed below.
//
// If the Type field of inPublic does not match the type specified in the sensitive data, a *TPMParameterError error with an error
// code of ErrorType is returned for parameter index 1. If the authorization value in the sensitive area is larger than the name
// algorithm, a *TPMParameterError error with an error code of ErrorSize is returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmRSA and the size of the modulus in the Unique field is inconsistent with the size
// specified in the Params field, a *TPMParameterError error with an error code of ErrorKey will be returned for parameter index 2.
// If the value of the exponent in the Params field is invalid, a *TPMParameterError error with an error code of ErrorValue will
// be returned for parameter index 2. If the size of private key in the sensitive area is not the correct size, a *TPMParameterError
// error with an error code of ErrorKeySize will be returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmECC and the private key in the sensitive area is invalid, a *TPMParameterError error
// with an error code of ErrorKeySize will be returned for parameter index 1. If the public point specified in the Unique field of
// inPublic does not belong to the private key, a *TPMError with an error code of ErrorBinding will be returned.
//
// If the Type field of inPublic is AlgorithmSymCipher and the size of the symmetric key in the sensitive area is inconsistent with
// the symmetric algorithm specified in the Params field of inPublic, a *TPMParameterError error with an error code of ErrorKeySize
// will be returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmKeyedHash and the size of the sensitive data is larger than permitted for the digest
// algorithm selected by the scheme defined in the Params field of inPublic, a *TPMParameterError error with an error code of
// ErrorKeySize will be returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmSymCipher or AlgorithmKeyedHash and the size of seed value in the sensitive area does
// not match the name algorithm, a *TPMError error with an error code of ErrorKeySize will be returned. If the digest in the Unique
// field of inPublic is inconsistent with the value of the sensitive data and the seed value, a *TPMError with an error code of
// ErrorBinding will be returned.
//
// If the loaded object is a storage parent and the size of the seed value in the sensitive area isn't sufficient for the selected
// name algorithm, a *TPMParameterError error with an error code of ErrorSize will be returned for parameter index 1.
//
// On success, a ResourceContext corresponding to the newly loaded transient object will be returned.
func (t *TPMContext) Load(parentContext ResourceContext, inPrivate Private, inPublic *Public, parentContextAuth interface{}, sessions ...*Session) (ResourceContext, Name, error) {
	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoad, sessions,
		ResourceWithAuth{Context: parentContext, Auth: parentContextAuth}, Separator,
		inPrivate, publicSized{inPublic}, Separator,
		&objectHandle, Separator,
		&name); err != nil {
		return nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	inPublic.copyTo(&objectContext.public)
	t.addResourceContext(objectContext)

	return objectContext, name, nil
}

// LoadExternal executes the TPM2_LoadExternal command in order to load an object that is not a protected object in to the TPM.
// The object is specified by providing the inPrivate and inPublic arguments, although inPrivate is optional. If only the public
// part is to be loaded, the hierarchy parameter must specify a hierarchy to associate the loaded object with so that tickets can
// be created properly. If both the public and private parts are to be loaded, then hierarchy should be HandleNull.
//
// If there are no available slots for new objects on the TPM, a *TPMWarning error with a warning code of WarningObjectMemory will
// be returned.
//
// If the hierarchy specified by the hierarchy parameter is disabled, a *TPMParameterError error with an error code of ErrorHierarchy
// will be returned for parameter index 3.
//
// If inPrivate is provided and hierarchy is not HandleNull, a *TPMParameterError error with an error code of ErrorHierarchy will be
// returned for parameter index 3.
//
// If inPrivate is provided and the Attrs field of inPublic has either AttrFixedTPM, AttrFixedParent or AttrRestricted attribute set,
// a *TPMParameterError error with an error code of ErrorAttributes will be returned for parameter index 2.
//
// TPM2_LoadExternal performs many of the same validations of the public attributes as TPM2_Create, and may return similar error
// codes as *TPMParameterError for parameter index 2.
//
// If inPrivate is provided and the Type field of inPublic does not match the type specified in the sensitive data, a
// *TPMParameterError error with an error code of ErrorType is returned for parameter index 1. If the authorization value in the
// sensitive area is larger than the name algorithm, a *TPMParameterError error with an error code of ErrorSize is returned for
// parameter index 1.
//
// If the Type field of inPublic is AlgorithmRSA and the size of the modulus in the Unique field is inconsistent with the size
// specified in the Params field, a *TPMParameterError error with an error code of ErrorKey will be returned for parameter index 2.
// If the value of the exponent in the Params field is invalid, a *TPMParameterError error with an error code of ErrorValue will
// be returned for parameter index 2. If inPrivate is provided and the size of private key in the sensitive area is not the correct
// size, a *TPMParameterError error with an error code of ErrorKeySize will be returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmECC, inPrivate is provided and the private key in the sensitive area is invalid, a
// *TPMParameterError error with an error code of ErrorKeySize will be returned for parameter index 1. If the public point specified
// in the Unique field of inPublic does not belong to the private key, a *TPMError with an error code of ErrorBinding will be
// returned.
//
// If the Type field of inPublic is AlgorithmECC, inPrivate is not provided and the size of the public key in the Unique field of
// inPublic is inconsistent with the value of the Params field of inPublic, a *TPMParameterError error with an error code of ErrorKey
// is returned for parameter index 2. If the public point is not on the curve specified in the Params field of inPublic, a
// *TPMParameterError error with an error code of ErrorECCPoint will be returned for parameter index 2.
//
// If the Type field of inPublic is AlgorithmSymCipher, inPrivate is provided and the size of the symmetric key in the sensitive area
// is inconsistent with the symmetric algorithm specified in the Params field of inPublic, a *TPMParameterError error with an error
// code of ErrorKeySize will be returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmKeyedHash, inPrivate is provided and the size of the sensitive data is larger than
// permitted for the digest algorithm selected by the scheme defined in the Params field of inPublic, a *TPMParameterError error
// with an error code of ErrorKeySize will be returned for parameter index 1.
//
// If the Type field of inPublic is AlgorithmSymCipher or AlgorithmKeyedHash and inPrivate has not been provided, a *TPMParameterError
// error with an error code of ErrorKey will be returned for parameter index 2 if the size of the digest in the Unique field of
// inPublic does not match the selected name algorithm.
//
// If the Type field of inPublic is AlgorithmSymCipher or AlgorithmKeyedHash, inPrivate has been provided and the size of seed value
// in the sensitive area does not match the name algorithm, a *TPMError error with an error code of ErrorKeySize will be returned.
// If the digest in the Unique field of inPublic is inconsistent with the value of the sensitive data and the seed value, a
// *TPMError with an error code of ErrorBinding will be returned.
//
// On success, a ResourceContext corresponding to the newly loaded transient object will be returned.
func (t *TPMContext) LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle, sessions ...*Session) (ResourceContext, Name, error) {
	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoadExternal, sessions,
		Separator,
		sensitiveSized{inPrivate}, publicSized{inPublic}, hierarchy, Separator,
		&objectHandle, Separator,
		&name); err != nil {
		return nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	inPublic.copyTo(&objectContext.public)
	t.addResourceContext(objectContext)

	return objectContext, name, nil
}

// ReadPublic executes the TPM2_ReadPublic command to read the public area of the object associated with objectContext.
//
// If objectContext corresponds to a sequence object, a *TPMError with an error code of ErrorSequence will be returned.
//
// On success, the public part of the object is returned, along with the object's name and qualified name.
func (t *TPMContext) ReadPublic(objectContext ResourceContext, sessions ...*Session) (*Public, Name, Name, error) {
	var outPublic publicSized
	var name Name
	var qualifiedName Name
	if err := t.RunCommand(CommandReadPublic, sessions,
		objectContext, Separator,
		Separator,
		Separator,
		&outPublic, &name, &qualifiedName); err != nil {
		return nil, nil, nil, err
	}
	if n, err := outPublic.Ptr.Name(); err != nil {
		return nil, nil, nil, &InvalidResponseError{CommandReadPublic, fmt.Sprintf("cannot compute name of returned public area: %v", err)}
	} else if !bytes.Equal(n, name) {
		return nil, nil, nil, &InvalidResponseError{CommandReadPublic, "name and public area don't match"}
	}
	return outPublic.Ptr, name, qualifiedName, nil
}

// ActivateCredential executes the TPM2_ActivateCredential command to associate a certificate with the object associated with
// activateContext.
//
// The activateContext parameter corresponds to an object to which credentialBlob is to be associated. It would typically be an
// attestation key, and the issusing certificate authority would have validated that this object has the expected properties of an
// attestation key (it is a restricted, non-duplicable signing key) before issuing the credential. Authorization with the admin role
// is required for activateContext, provided via activateContextAuth.
//
// The credentialBlob is an encrypted and integrity protected credential issued by a certificate authority. It is encrypted with a key
// derived from a seed generated by the certificate authority, and the name of the object associated with activateContext. It is
// integrity protected by prepending a HMAC of the encrypted data and the name of the object associated with activateContext, using
// the same seed as the HMAC key.
//
// The keyContext parameter corresponds to an asymmetric restricted decrypt that was used to encrypt the seed value, which is provided
// via the secret parameter in encrypted form. It is typically an endorsement key, and the issuing certificate authority would have
// verified that it is a valid endorsement key by verifying the associated endorsement certificate. Authorization with the user auth
// role is required for keyContext, provided via keyContextAuth.
//
// If keyContext does not correspond to an asymmetric restricted decrypt key, a *TPMHandleError error with an error code of ErrorType
// is returned for handle index 2.
//
// If recovering the seed from secret fails, a *TPMParameterError error with an error code of ErrorScheme, ErrorValue, ErrorSize or
// ErrorECCPoint may be returned for parameter index 2.
//
// If the integrity value of IV for credentialBlob cannot be unmarshalled correctly or any other errors occur during unmarshalling
// of credentialBlob, a *TPMParameterError error with an error code of either ErrorSize or ErrorInsufficient will be returned for
// parameter index 1. If the integrity check of credentialBlob fails, a *TPMParameterError error with an error code of ErrorIntegrity
// will be returned for parameter index 1. If the size of the IV for credentialBlob doesn't match the block size for the encryption
// algorithm, a *TPMParameterError error with an error code of ErrorValue will be returned for parameter index 1.
//
// On success, the decrypted credential is returned. This is typically used to decrypt a certificate associated with activateContext,
// which was issued by a certificate authority.
func (t *TPMContext) ActivateCredential(activateContext, keyContext ResourceContext, credentialBlob IDObjectRaw, secret EncryptedSecret, activateContextAuth, keyContextAuth interface{}, sessions ...*Session) (Digest, error) {
	var certInfo Digest
	if err := t.RunCommand(CommandActivateCredential, sessions,
		ResourceWithAuth{Context: activateContext, Auth: activateContextAuth}, ResourceWithAuth{Context: keyContext, Auth: keyContextAuth}, Separator,
		credentialBlob, secret, Separator,
		Separator,
		&certInfo); err != nil {
		return nil, err
	}
	return certInfo, nil
}

// MakeCredential executes the TPM2_MakeCredential command to allow the TPM to perform the actions of a certificate authority, in
// order to create an activation credential.
//
// The object associated with context must be the public part of a storage key, which would typically be the endorsement key of the
// TPM from which the request originates. The certificate authority would normally be in receipt of the TPM manufacturer issued
// endorsement certificate corresponding to this key and would have validated this. The certificate is an assertion from the
// manufacturer that the key is a valid endorsement key (a restricted, non-duplicable decrypt key) that is resident on a genuine TPM.
//
// The credential parameter is the activation credential, which would typically be used to protect the generated certificate. The
// objectName parameter is the name of object for which a certificate is requested. The public part of this object would normally be
// validated by the certificate authority to ensure that it has the properties expected of an attestation key (it is a restricted,
// non-duplicable signing key).
//
// If context does not correspond to an asymmetric restricted decrypt key, a *TPMHandleError error with an error code of ErrorType is
// returned.
//
// If the size of credential is larger than the name algorithm associated with context, a *TPMParameterError error with an error code
// of ErrorSize will be returned for parameter index 1.
//
// If the algorithm of the object associated with context is AlgorithmECC, a *TPMError with an error code of ErrorKey will be returned
// if the ECC key is invalid. If the algorithm of the object associated with context is AlgorithmRSA, a *TPMError with an error code
// of ErrorScheme will be returned if the padding scheme is invalid or not supported.
//
// On success, the encrypted activation credential is returned as IDObjectRaw. The activation credential is encrypted with a key
// derived from a randomly generated seed and objectName, and an integrity HMAC of the encrypted credential and objectName is
// prepended using a HMAC key derived from the same seed. The seed is encrypted using the public key associated with context, and
// returned as EncryptedSecret.
//
// The certificate authority would typically protect the certificate it generates with the unencrypted credential, and then return the
// protected certificate, the encrypted credential blob and the encrypted seed to the requesting party. The seed and credential values
// can only be recovered on the TPM associated with the endorsement certificate that the requesting party provided if the object
// associated with objectName is resident on it.
func (t *TPMContext) MakeCredential(context ResourceContext, credential Digest, objectName Name, sessions ...*Session) (IDObjectRaw, EncryptedSecret, error) {
	var credentialBlob IDObjectRaw
	var secret EncryptedSecret
	if err := t.RunCommand(CommandMakeCredential, sessions,
		context, Separator,
		credential, objectName, Separator,
		Separator,
		&credentialBlob, &secret); err != nil {
		return nil, nil, err
	}
	return credentialBlob, secret, nil
}

// Unseal executes the TPM2_Unseal command to decrypt the sealed data object associated with itemContext and retrieve its sensitive
// data. The command requires authorization with the user auth role for itemContext, provided via itemContextAuth.
//
// If the type of object associated with itemContext is not AlgorithmKeyedHash, a *TPMHandleError error with an error code of
// ErrorType will be returned. If the object associated with itemContext has either the AttrDecrypt, AttrSign or AttrRestricted
// attributes set, a *TPMHandlerError error with an error code of ErrorAttributes will be returned.
//
// On success, the object's sensitive data is returned in decrypted form.
func (t *TPMContext) Unseal(itemContext ResourceContext, itemContextAuth interface{}, sessions ...*Session) (SensitiveData, error) {
	var outData SensitiveData

	if err := t.RunCommand(CommandUnseal, sessions,
		ResourceWithAuth{Context: itemContext, Auth: itemContextAuth}, Separator,
		Separator,
		Separator,
		&outData); err != nil {
		return nil, err
	}

	return outData, nil
}

// ObjectChangeAuth executes the TPM2_ObjectChangeAuth to change the authorization value of the object associated with objectContext.
// This command requires authorization with the admin role for objectContext, provided via objectContextAuth.
//
// The new authorization value is provided via newAuth. The parentContext parameter must correspond to the parent object for
// objectContext. No authorization is required for parentContext.
//
// If the object associated with objectContext is a sequence object, a *TPMHandleError error with an error code of ErrorType will
// be returned for handle index 1.
//
// If the length of newAuth is longer than the name algorithm for objectContext, a *TPMParameterError error with an error code of
// ErrorSize will be returned.
//
// If the object associated with parentContext is not the parent object of objectContext, a *TPMHandleError error with an error code
// of ErrorType will be returned for handle index 2.
//
// On success, this returns a new private area for the object associated with objectContext. This function does not make any changes
// to the version of the object that is currently loaded in to the TPM.
func (t *TPMContext) ObjectChangeAuth(objectContext, parentContext ResourceContext, newAuth Auth, objectContextAuth interface{}, sessions ...*Session) (Private, error) {
	var outPrivate Private

	if err := t.RunCommand(CommandObjectChangeAuth, sessions,
		ResourceWithAuth{Context: objectContext, Auth: objectContextAuth}, parentContext, Separator,
		newAuth, Separator,
		Separator,
		&outPrivate); err != nil {
		return nil, err
	}

	return outPrivate, nil
}

// CreateLoaded executes the TPM2_CreateLoaded command to create a new primary, ordinary or derived object. To create a new primary
// object, parentContext should correspond to a hierarchy. To create a new ordinary object, parentContext should correspond to a
// storage parent. To create a new derived object, parentContext should correspond to a derivation parent.
//
// The command requires authorization with the user auth role for parentContext.
//
// A template for the object is provided via the inPublic parameter. The Type field of inPublic defines the algorithm for the object.
// The NameAlg field defines the digest algorithm for computing the name of the object. The Attrs field defines the attributes of
// the object. The AuthPolicy field allows an authorization policy to be defined for the new object.
//
// Data that will form part of the sensitive area of the object can be provided via inSensitive, which is optional.
//
// If parentContext does not correspond to a derivation parent and the Attrs field of inPublic does not have the
// AttrSensitiveDataOrigin attribute set, then the sensitive data in the created object is initialized with the data provided via the
// Data field of inSensitive.
//
// If the Attrs field of inPublic has the AttrSensitiveDataOrigin attribute set and Type is AlgorithmSymCipher, then the sensitive
// data in the created object is initialized with a TPM generated key. The size of this key is determined by the value of the Params
// field of inPublic. If Type is AlgorithmKeyedHash, then the sensitive data in the created object is initialized with a TPM
// generated value that is the same size as the name algorithm selected by the NameAlg field of inPublic.
//
// If the Type field of inPublic is AlgorithmRSA then the sensitive data in the created object is initialized with a TPM generated
// private key. The size of this is determined by the value of the Params field of inPublic.
//
// If the Type field of inPublic is AlgorithmECC and parentContext does not correspond to a derivation parent, then the sensitive data
// in the created object is initialized with a TPM generated private key. The size of this is determined by the value of the Params
// field of inPublic.
//
// If parentContext corresponds to a derivation parent, the sensitive data in the created object is initialized with a value derived
// from the parent object's private seed, and the derivation values specified in either the Unique field of inPublic or the Data
// field of inSensitive.
//
// If the Type field of inPublic is AlgorithmKeyedHash, the Attrs field has AttrSensitiveDataOrigin, AttrSign and AttrDecrypt all
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
// If parentContext corresponds to an object and it isn't a valid storage parent or derivation parent, *TPMHandleError error with an
// error code of ErrorType will be returned for handle index 1.
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
// If the Type field of inPublic is not AlgorithmKeyedHash and the AttrRestricted, AttrFixedParent and AttrDecrypt attributes of
// Attrs are set, a *TPMParameterError error with an error code of ErrorHash will be returned for parameter index 2 if the NameAlg
// field of inPublic does not select the same name algorithm as the parent object. A *TPMParameterError error with an error code
// of ErrorSymmetric will be returned for parameter index 2 if the symmetric algorithm specified in the Params field of inPublic
// does not match the symmetric algorithm of the parent object.
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
// On success, a ResourceContext instance will be returned that corresponds to the newly created object on the TPM, along with the
// private and public parts. If the Type field of inPublic is AlgorithmKeyedHash or AlgorithmSymCipher, then the returned *Public
// object will have a Unique field that is the digest of the sensitive data and the value of the object's seed in the sensitive area,
// computed using the object's name algorithm. If the Type field of inPublic is AlgorithmECC or AlgorithmRSA, then the returned
// *Public object will have a Unique field containing details about the public part of the key, computed from the private part of the
// key.
func (t *TPMContext) CreateLoaded(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic PublicTemplate, parentContextAuth interface{}, sessions ...*Session) (ResourceContext, Private, *Public, Name, error) {
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	if inPublic == nil {
		return nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	inTemplate, err := inPublic.ToTemplate()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot marshal public template: %v", err)
	}

	var objectHandle Handle
	var outPrivate Private
	var outPublic publicSized
	var name Name

	if err := t.RunCommand(CommandCreateLoaded, sessions,
		ResourceWithAuth{Context: parentContext, Auth: parentContextAuth}, Separator,
		sensitiveCreateSized{inSensitive}, inTemplate, Separator,
		&objectHandle, Separator,
		&outPrivate, &outPublic, &name); err != nil {
		return nil, nil, nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	outPublic.Ptr.copyTo(&objectContext.public)
	t.addResourceContext(objectContext)

	return objectContext, outPrivate, outPublic.Ptr, name, nil
}
