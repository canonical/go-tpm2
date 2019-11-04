// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 31 - Non-volatile Storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

func (t *TPMContext) initNVMaxBufferSize() {
	if t.maxNVBufferSize > 0 {
		return
	}
	props, err := t.GetCapabilityTPMProperties(PropertyNVBufferMax, 1)
	switch {
	case err == nil && len(props) > 0:
		t.maxNVBufferSize = uint16(props[0].Value)
	default:
		t.maxNVBufferSize = 512
	}
}

// NVDefineSpace executes the TPM2_NV_DefineSpace command to reserve space to hold the data associated with a NV index described by
// the publicInfo parameter. The Index field of publicInfo defines the handle at which the index should be reserved. The NameAlg
// field defines the digest algorithm for computing the name of the NV index. The Attrs field is used to describe attributes for
// the index, as well as its type. An authorization policy for the index can be defined using the AuthPolicy field of publicInfo.
// The Size field defines the size of the index.
//
// The auth parameter specifies an authorization value for the NV index.
//
// The authHandle parameter specifies the hierarchy used for authorization, and should be HandlePlatform or HandleOwner. The command
// requires authorization with the user auth role for the specified hierarchy, provided via authHandleAuth.
//
// If the Attrs field of publicInfo has AttrNVPolicyDelete set but TPM2_NV_UndefineSpaceSpecial isn't supported, or the Attrs field
// defines a type that is unsupported, a *TPMParameterError error with an error code of ErrorAttributes will be returned for parameter
// index 2.
//
// If the AuthPolicy field of publicInfo defines an authorization policy digest then the digest length must match the size of the
// name algorithm defined by the NameAlg field of publicInfo, else a *TPMParameterError error with an error code of ErrorSize will
// be returned for parameter index 2.
//
// If the length of auth is greater than the name algorithm selected by the NameAlg field of the publicInfo parameter, a
// *TPMParameterError error with an error code of ErrorSize will be returned for parameter index 1.
//
// If authHandle specifies HandlePlatform but the AttrPhEnableNV attribute is clear, a *TPMHandleError error with an error code of
// ErrorHierarchy will be returned.
//
// If the type indicated by the Attrs field of publicInfo isn't supported by the TPM, a *TPMParameterError error with an error code of
// ErrorAttributes will be returned for parameter index 2.
//
// If the type defined by publicInfo is NVTypeCounter, NVTypeBits, NVTypePinPass or NVTypePinFail, the Size field of publicInfo must
// be 8. If the type defined by publicInfo is NVTypeExtend, the Size field of publicInfo must match the size of the name algorithm
// defined by the NameAlg field. If the size is unexpected, or the size for an index of type NVTypeOrdinary is too large, a
// *TPMParameterError error with an error code of ErrorSize will be returned for parameter index 2.
//
// If the type defined by publicInfo is NVTypeCounter, then the Attrs field must not have the AttrNVClearStClear attribute set, else
// a *TPMParameterError error with an error code of ErrorAttributes will be returned for parameter index 2.
//
// If the type defined by publicInfo is NVTypePinFail, then the Attrs field must have the AttrNVNoDA attribute set. If the type is
// either NVTypePinPass or NVTypePinFail, then the Attrs field must have the AttrNVAuthWrite, AttrNVGlobalLock and AttrNVWriteDefine
// attributes clear, else a *TPMParameterError error with an error code of ErrorAttributes will be returned for parameter index 2.
//
// If the Attrs field of publicInfo has either AttrNVWriteLocked, AttrNVReadLocked or AttrNVWritten set, a *TPMParameterError error
// with an error code of ErrorAttributes will be returned for parameter index 2.
//
// The Attrs field of publicInfo must have one of either AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite or AttrNVPolicyWrite set,
// and must also have one of either AttrNVPPRead, AttrNVOwnerRead, AttrNVAuthRead or AttrNVPolicyRead set. If there is no way to read
// or write an index, a *TPMParameterError error with an error code of ErrorAttributes will be returned for parameter index 2.
//
// If the Attrs field of publicInfo has AttrNVClearStClear set, a *TPMParameterError error with an error code of ErrorAttributes will
// be returned for parameter index 2 if AttrNVWriteDefine is set.
//
// If authHandle specifies HandlePlatform, then the Attrs field of publicInfo must have the AttrNVPlatformCreate attribute set. If
// authHandle specifies HandleOwner, then the AttrNVPlatformCreate attributes must be clear, else a *TPMHandleError error with an
// error code of ErrorAttributes will be returned.
//
// If the Attrs field of publicInfo has the AttrNVPolicyDelete attribute set, then HandlePlatform must be used for authorization via
// authHandle, else a *TPMParameterError error with an error code of ErrorAttributes will be returned for parameter index 2.
//
// If an index is already defined at the location specified by the Index field of publicInfo, a *TPMError error with an error code of
// ErrorNVDefined will be returned.
//
// If there is insufficient space for the index, a *TPMError error with an error code of ErrorNVSpace will be returned.
//
// On successful completion, the NV index will be defined and a ResourceContext can be created for it using the TPMContext.WrapHandle
// function, specifying the value of the Index field of publicInfo as the handle.
func (t *TPMContext) NVDefineSpace(authHandle Handle, auth Auth, publicInfo *NVPublic, authHandleAuth interface{}, sessions ...*Session) error {
	return t.RunCommand(CommandNVDefineSpace, sessions,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, Separator,
		auth, nvPublicSized{publicInfo})
}

// NVUndefineSpace executes the TPM2_NV_UndefineSpace command to remove the NV index associated with nvIndex, and free the resources
// used by it. If the index has the AttrNVPolicyDelete attribute set, then a *TPMHandleError error with an error code of
// ErrorAttributes will be returned for handle index 2.
//
// The authHandle parameter specifies the hierarchy used for authorization and should be either HandlePlatform or HandleOwner. The
// command requires authorization with the user auth role for the specified hierarchy, provided via authHandleAuth.
//
// If authHandle is HandleOwner and the NV index has the AttrNVPlatformCreate attribute set, then a *TPMError error with an error code
// of ErrorNVAuthorization will be returned.
//
// On successful completion, nvIndex will be invalidated.
func (t *TPMContext) NVUndefineSpace(authHandle Handle, nvIndex ResourceContext, authHandleAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVUndefineSpace, sessions,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, nvIndex); err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)
	return nil
}

// NVUndefineSpace executes the TPM2_NV_UndefineSpaceSpecial command to remove the NV index associated with nvIndex, and free the
// resources used by it. If the NV index does not have the AttrNVPolicyDelete attribute set, then a *TPMHandleError error with an
// error code of ErrorAttributes will be returned for handle index 1.
//
// The platform parameter must be HandlePlatform. The command requires authorization with the user auth role for the platform
// hierarchy, provided via platformAuth. The command requires authorization with the admin role for nvIndex, provided via nvIndexAuth.
//
// On successful completion, nvIndex will be invalidated.
func (t *TPMContext) NVUndefineSpaceSpecial(nvIndex ResourceContext, platform Handle, nvIndexAuth *Session, platformAuth interface{}, sessions ...*Session) error {
	var s []*sessionParam
	s, err := t.validateAndAppendSessionParam(s, ResourceWithAuth{Context: nvIndex, Auth: nvIndexAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing resource context with authorization for nvIndex: %v", err)
	}
	s, err = t.validateAndAppendSessionParam(s, HandleWithAuth{Handle: platform, Auth: platformAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing handle with authorization for platform: %v", err)
	}
	s, err = t.validateAndAppendSessionParam(s, sessions)
	if err != nil {
		return fmt.Errorf("error whilst processing non-auth sessions: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandNVUndefineSpaceSpecial, s, nvIndex, platform)
	if err != nil {
		return err
	}

	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		// If the HMAC key for this command includes the auth value for authHandle (eg,
		// if the PolicyAuthValue assertion was executed), the TPM will respond with a HMAC
		// generated with a key based on an empty auth value.
		ctx.sessionParams[0].session = authSession.copyWithNewAuthIfRequired(nil)
	}

	if err := t.processResponse(ctx); err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)
	return nil
}

func (t *TPMContext) nvReadPublic(nvIndex Handle, sessions ...*Session) (*NVPublic, Name, error) {
	var nvPublic nvPublicSized
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, sessions,
		nvIndex, Separator,
		Separator,
		Separator,
		&nvPublic, &nvName); err != nil {
		return nil, nil, err
	}
	if n, err := nvPublic.Ptr.Name(); err != nil {
		return nil, nil, &InvalidResponseError{CommandNVReadPublic, fmt.Sprintf("cannot compute name of returned public area: %v", err)}
	} else if !bytes.Equal(n, nvName) {
		return nil, nil, &InvalidResponseError{CommandNVReadPublic, "name and public area don't match"}
	}
	return nvPublic.Ptr, nvName, nil
}

// NVReadPublic executes the TPM2_NV_ReadPublic command to read the public area of the NV index associated with nvIndex.
func (t *TPMContext) NVReadPublic(nvIndex ResourceContext, sessions ...*Session) (*NVPublic, Name, error) {
	if err := t.checkResourceContextParam(nvIndex); err != nil {
		return nil, nil, fmt.Errorf("invalid resource context for nvIndex: %v", err)
	}

	return t.nvReadPublic(nvIndex.Handle(), sessions...)
}

// NVWrite executes the TPM2_NV_Write command to write data to the NV index associated with nvIndex, at the specified offset.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite and
// AttrNVPolicyWrite attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPWrite
// attribute, authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization
// can be satisfied with HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth.
// If the resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyWrite attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If data is too large to be written in a single command, this function will re-execute the TPM2_NV_Write command until all data is
// written. As a consequence, any *Session instances provided should have the AttrContinueSession attribute defined. An error will
// be returned if the write will require more than one command execution and there are sessions without the AttrContinueSession
// attribute defined. If authContextAuth is a *Session instance that references a bound session and this is the first write to this
// index, the first write will break the session binding. In this case, the AuthValue field should be set to the authorization value
// of the resource associated with authContext to avoid a partial write when the write is split across multiple commands.
//
// If the index has the AttrNVWriteLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// If the type of the index is NVTypeCounter, NVTypeBits or NVTypeExtend, a *TPMError error with an error code fo ErrorAttributes
// will be returned.
//
// If the value of offset is outside of the bounds of the index, a *TPMParameterError error with an error code of ErrorValue will be
// returned for parameter index 2.
//
// If the length of the data and the specified offset would result in a write outside of the bounds of the index, or if the index
// has the AttrNVWriteAll attribute set and the size of the data doesn't match the size of the index, a *TPMError error with an error
// code of ErrorNVRange will be returned.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been written to.
func (t *TPMContext) NVWrite(authContext, nvIndex ResourceContext, data MaxNVBuffer, offset uint16, authContextAuth interface{}, sessions ...*Session) error {
	t.initNVMaxBufferSize()

	remaining := uint16(len(data))
	total := uint16(0)

	if remaining > t.maxNVBufferSize {
		session, ok := authContextAuth.(*Session)
		if ok && session.Attrs&AttrContinueSession == 0 {
			return makeInvalidParamError("authContextAuth", "the AttrContinueSession attribute is required for a split write")
		}

		for i, s := range sessions {
			if s.Attrs&AttrContinueSession == 0 {
				return makeInvalidParamError("sessions", fmt.Sprintf("the AttrContineSession attribute is required for session at index %d for "+
					"a split write", i))
			}
		}
	}

	for remaining > 0 {
		s := remaining
		if s > t.maxNVBufferSize {
			s = t.maxNVBufferSize
		}

		if err := t.RunCommand(CommandNVWrite, sessions,
			ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
			data[total:total+s], offset+total); err != nil {
			return err
		}

		nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)

		total += s
		remaining -= s
	}

	return nil
}

// NVSetPinCounterParams is a helper function for NVWrite for updating the contents of the NV pin pass or NV pin fail index associated
// with nvIndex. If the type of nvIndex is not NVTypePinPass of NVTypePinFail, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite and
// AttrNVPolicyWrite attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPWrite
// attribute, authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization
// can be satisfied with HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth.
// If the resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyWrite attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index has the AttrNVWriteLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been written to.
func (t *TPMContext) NVSetPinCounterParams(authContext, nvIndex ResourceContext, params *NVPinCounterParams, authContextAuth interface{}, sessions ...*Session) error {
	context, isNv := nvIndex.(*nvIndexContext)
	if !isNv {
		return errors.New("nvIndex does not correspond to a NV index")
	}
	if context.public.Attrs.Type() != NVTypePinPass && context.public.Attrs.Type() != NVTypePinFail {
		return errors.New("nvIndex does not correspond to a PIN pass or PIN fail index")
	}
	data, err := MarshalToBytes(params)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal PIN counter parameters: %v", err))
	}
	return t.NVWrite(authContext, nvIndex, data, 0, authContextAuth, sessions...)
}

// NVIncrement executes the TPM2_NV_Increment command to increment the counter associated with nvIndex.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite and
// AttrNVPolicyWrite attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPWrite
// attribute, authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization
// can be satisfied with HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth.
// If the resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyWrite attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index has the AttrNVWriteLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// If the type of the index is not NVTypeCounter, a *TPMHandleError error with an error code of ErrorAttributes will be returned for
// handle index 2.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been written to.
func (t *TPMContext) NVIncrement(authContext, nvIndex ResourceContext, authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVIncrement, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

// NVExtend executes the TPM2_NV_Extend command to extend data to the NV index associated with nvIndex, using the index's name
// algorithm.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite and
// AttrNVPolicyWrite attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPWrite
// attribute, authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization
// can be satisfied with HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth.
// If the resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyWrite attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index has the AttrNVWriteLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// If the type of the index is not NVTypeExtend, a *TPMHandleError error with an error code of ErrorAttributes will be returned for
// handle index 2.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been written to.
func (t *TPMContext) NVExtend(authContext, nvIndex ResourceContext, data MaxNVBuffer, authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVExtend, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		data); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

// NVSetBits executes the TPM2_NV_SetBits command to OR the value of bits with the contents of the NV index associated with nvIndex.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite and
// AttrNVPolicyWrite attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPWrite
// attribute, authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization
// can be satisfied with HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth.
// If the resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyWrite attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index has the AttrNVWriteLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// If the type of the index is not NVTypeBits, a *TPMHandleError error with an error code of ErrorAttributes will be returned for
// handle index 2.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been written to.
func (t *TPMContext) NVSetBits(authContext, nvIndex ResourceContext, bits uint64, authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVSetBits, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		bits); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

// NVWriteLock executes the TPM2_NV_WriteLock command to inhibit further writes to the NV index associated with nvIndex.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite and
// AttrNVPolicyWrite attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPWrite
// attribute, authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization
// can be satisfied with HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth.
// If the resource associated with authContext is not permitted to authorize this command, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyWrite attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index has neither the AttrNVWriteDefine or AttrNVWriteStClear attributes set, then a *TPMHandleError error with an error
// code of ErrorAttributes will be returned for handle index 2.
//
// On successful completion, the AttrNVWriteLocked attribute will be set. It will be cleared again (and writes will be reenabled) on
// the next TPM reset or TPM restart unless the index has the AttrNVWriteDefine attribute set and AttrNVWritten attribute is set.
func (t *TPMContext) NVWriteLock(authContext, nvIndex ResourceContext, authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVWriteLock, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWriteLocked)
	return nil
}

// NVGlobalWriteLock executes the TPM2_NV_GlobalWriteLock command to inhibit further writes for all NV indexes that have the
// AttrNVGlobalLock attribute set.
//
// The authHandle parameter specifies a hierarchy, and should be either HandlePlatform or HandleOwner. The command requires the user
// auth role for authHandle, provided via authHandleAuth.
//
// On successful completion, the AttrNVWriteLocked attribute will be set for all NV indexes that have the AttrNVGlobalLock attribute
// set. If an index also has the AttrNVWriteDefine attribute set, this will permanently inhibit further writes unless AttrNVWritten
// is clear.
func (t *TPMContext) NVGlobalWriteLock(authHandle Handle, authHandleAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVGlobalWriteLock, sessions,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}); err != nil {
		return err
	}

	for _, rc := range t.resources {
		nvRc, isNV := rc.(*nvIndexContext)
		if !isNV {
			continue
		}

		if nvRc.public.Attrs&AttrNVGlobalLock > 0 {
			nvRc.setAttr(AttrNVWriteLocked)
		}
	}
	return nil
}

// NVRead executes the TPM2_NV_Read command to read the contents of the NV index associated with nvIndex. The amount of data to read,
// and the offset within the index are defined by the size and offset parameters.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead, AttrNVAuthRead and AttrNVPolicyRead
// attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPRead attribute,
// authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerRead attribute, authorization can be
// satisfied with HandleOwner. If the NV index has the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied
// with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth. If the
// resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyRead attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the requested data can not be read in a single command, this function will re-execute the TPM2_NV_Read command until all data
// is read. As a consequence, any *Session instances provided should have the AttrContinueSession attribute defined.
//
// If the index has the AttrNVReadLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// If the index has not been initialized (ie, the AttrNVWritten attribute is not set), a *TPMError error with an error code of
// ErrorNVUninitialized will be returned.
//
// If the value of size is too large, a *TPMParameterError error with an error code of ErrorValue will be returned for parameter
// index 1.
//
// If the value of offset falls outside of the bounds of the index, a *TPMParameterError error with an error code of ErrorValue will
// be returned for parameter index 2.
//
// If the data selection falls outside of the bounds of the index, a *TPMError error with an error code of ErrorNVRange will be
// returned.
//
// On successful completion, the requested data will be returned.
func (t *TPMContext) NVRead(authContext, nvIndex ResourceContext, size, offset uint16, authContextAuth interface{}, sessions ...*Session) (MaxNVBuffer, error) {
	t.initNVMaxBufferSize()

	data := make(MaxNVBuffer, size)
	total := uint16(0)
	remaining := size

	for remaining > 0 {
		s := remaining
		if s > t.maxNVBufferSize {
			s = t.maxNVBufferSize
		}

		var tmpData MaxNVBuffer

		if err := t.RunCommand(CommandNVRead, sessions,
			ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
			s, offset+total, Separator,
			Separator,
			&tmpData); err != nil {
			return nil, err
		}

		copy(data[total:], tmpData)
		total += s
		remaining -= s
	}

	return data, nil
}

// NVReadCounter is a helper function for NVRead for reading the contents of the NV counter index associated with nvIndex. If the
// type of nvIndex is not NVTypeCounter, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead, AttrNVAuthRead and AttrNVPolicyRead
// attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPRead attribute,
// authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerRead attribute, authorization can be
// satisfied with HandleOwner. If the NV index has the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied
// with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth. If the
// resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyRead attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index has the AttrNVReadLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// If the index has not been initialized (ie, the AttrNVWritten attribute is not set), a *TPMError error with an error code of
// ErrorNVUninitialized will be returned.
//
// On successful completion, the current counter value will be returned.
func (t *TPMContext) NVReadCounter(authContext, nvIndex ResourceContext, authContextAuth interface{}, sessions ...*Session) (uint64, error) {
	context, isNv := nvIndex.(*nvIndexContext)
	if !isNv {
		return 0, errors.New("nvIndex does not correspond to a NV index")
	}
	if context.public.Attrs.Type() != NVTypeCounter {
		return 0, errors.New("nvIndex does not correspond to a counter")
	}
	data, err := t.NVRead(authContext, nvIndex, 8, 0, authContextAuth, sessions...)
	if err != nil {
		return 0, err
	}
	if len(data) != binary.Size(uint64(0)) {
		return 0, &InvalidResponseError{CommandNVRead, fmt.Sprintf("unexpected number of bytes returned (got %d)", len(data))}
	}
	return binary.BigEndian.Uint64(data), nil
}

// NVReadPinCounterParams is a helper function for NVRead for reading the contents of the NV pin pass or NV pin fail index associated
// with nvIndex. If the type of nvIndex is not NVTypePinPass of NVTypePinFail, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead, AttrNVAuthRead and AttrNVPolicyRead
// attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPRead attribute,
// authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerRead attribute, authorization can be
// satisfied with HandleOwner. If the NV index has the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied
// with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth. If the
// resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyRead attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index has the AttrNVReadLocked attribute set, a *TPMError error with an error code of ErrorNVLocked will be returned.
//
// If the index has not been initialized (ie, the AttrNVWritten attribute is not set), a *TPMError error with an error code of
// ErrorNVUninitialized will be returned.
//
// On successful completion, the current PIN count and limit will be returned.
func (t *TPMContext) NVReadPinCounterParams(authContext, nvIndex ResourceContext, authContextAuth interface{}, sessions ...*Session) (*NVPinCounterParams, error) {
	context, isNv := nvIndex.(*nvIndexContext)
	if !isNv {
		return nil, errors.New("nvIndex does not correspond to a NV index")
	}
	if context.public.Attrs.Type() != NVTypePinPass && context.public.Attrs.Type() != NVTypePinFail {
		return nil, errors.New("nvIndex does not correspond to a PIN pass or PIN fail index")
	}
	data, err := t.NVRead(authContext, nvIndex, 8, 0, authContextAuth, sessions...)
	if err != nil {
		return nil, err
	}
	var res NVPinCounterParams
	if _, err := UnmarshalFromBytes(data, &res); err != nil {
		return nil, &InvalidResponseError{CommandNVRead, fmt.Sprintf("cannot unmarshal response bytes: %v", err)}
	}
	return &res, nil
}

// NVReadLock executes the TPM2_NV_ReadLock command to inhibit further reads of the NV index associated with nvIndex.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead, AttrNVAuthRead and AttrNVPolicyRead
// attributes. The handle used for authorization is specified via authContext. If the NV index has the AttrNVPPRead attribute,
// authorization can be satisfied with HandlePlatform. If the NV index has the AttrNVOwnerRead attribute, authorization can be
// satisfied with HandleOwner. If the NV index has the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied
// with nvIndex. The command requires authorization with the user auth role for authContext, provided via authContextAuth. If the
// resource associated with authContext is not permitted to authorize this access, a *TPMError error with an error code of
// ErrorNVAuthorization will be returned.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can be satisfied by
// supplying the authorization value for the index (either directly or using a HMAC session). If nvIndex is being used for
// authorization and the AttrNVPolicyRead attribute is defined, the authorization can be satisfied using a policy session with a
// digest that matches the authorization policy for the index.
//
// If the index doesn't have the AttrNVReadStClear attribute set, then a *TPMHandleError error with an error code of ErrorAttributes
// will be returned for handle index 2.
//
// On successful completion, the AttrNVReadLocked attribute will be set. It will be cleared again (and reads will be reenabled) on
// the next TPM reset or TPM restart.
func (t *TPMContext) NVReadLock(authContext, nvIndex ResourceContext, authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVReadLock, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVReadLocked)
	return nil
}

// NVChangeAuth executes the TPM2_NV_ChangeAuth command to change the authorization value for the NV index associated with nvIndex,
// setting it to the new value defined by newAuth. The command requires the admin auth role for nvIndex, provided via nvIndexAuth.
//
// If the size of newAuth is greater than the name algorithm for the index, a *TPMParameterError error with an error code of ErrorSize
// will be returned.
func (t *TPMContext) NVChangeAuth(nvIndex ResourceContext, newAuth Auth, nvIndexAuth *Session, sessions ...*Session) error {
	var s []*sessionParam
	s, err := t.validateAndAppendSessionParam(s, ResourceWithAuth{Context: nvIndex, Auth: nvIndexAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing resource context with authorization for nvIndex: %v",
			err)
	}
	s, err = t.validateAndAppendSessionParam(s, sessions)
	if err != nil {
		return fmt.Errorf("error whilst processing non-auth sessions: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandNVChangeAuth, s,
		nvIndex, Separator,
		newAuth)
	if err != nil {
		return err
	}

	// If the session is not bound to nvIndex, the TPM will respond with a HMAC generated with a key
	// derived from newAuth. If the session is bound, the TPM will respond with a HMAC generated from the
	// original key
	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		ctx.sessionParams[0].session = authSession.copyWithNewAuthIfRequired(newAuth)
	}

	return t.processResponse(ctx)
}

// func (t *TPMContext) NVCertify(signContext, authContext, nvIndex ResourceContext, qualifyingData Data,
//	inScheme *SigScheme, size, offset uint16, signContextAuth, authContextAuth interface{},
//	sessions ...*Session) (AttestRaw, *Signature, error) {
// }
