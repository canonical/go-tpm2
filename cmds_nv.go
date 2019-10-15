// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 31 - Non-volatile Storage

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// NVDefineSpace executes the TPM2_NV_DefineSpace command to reserve space to hold the data associated with a
// NV index described by the publicInfo parameter. If an index is already defined at the location specified by
// the Index field of publicInfo, this function will return an error. The auth parameter specifies an
// authorization value for the NV index.
//
// An error will be returned if the Attrs field of publicInfo has either AttrWriteLocked, AttrReadLocked or
// AttrNVWritten set.
//
// If the type defined by publicInfo is NVTypeCounter, NVTypeBits, NVTypePinPass or NVTypePinFail, the Size field
// of publicInfo must be 8, else an error will be returned. If the type defined by publicInfo is NVTypeExtend,
// the Size field of publicInfo must match the size of the algorithm defined by the NameAlg field of publicInfo,
// else an error will be returned.
//
// The Attrs field of publicInfo must have one of either AttrNVPPWrite, AttrNVOwnerWrite, AttrNVAuthWrite or
// AttrNVPolicyWrite set, else an error will be returned. It must also have one of either AttrNVPPRead,
// AttrNVOwnerRead, AttrNVAuthRead or AttrNVPolicyRead set.
//
// If the type defined by publicInfo is NVTypeCounter, then the Attrs field must not have the AttrNVClearStClear
// attribute set, else an error will be returned.
//
// The authHandle parameter specifies the hierarchy used for authorization, and should be HandlePlatform or
// HandleOwner. If it is HandlePlatform, the Attrs field of publicInfo must have the AttrNVPlatformCreate flag
// set, else it must be clear. The command requires the user auth role for the specified hierarchy, provided via
// authHandleAuth. If the Attrs field of publicInfo has the AttrNVPolicyDelete attribute set, then HandlePlatform
// must be used for authorization.
//
// On successful completion, the NV index will be defined and a ResourceContext can be created for it using
// the TPMContext.WrapHandle function, specifying the value of the Index field of publicInfo as the handle.
func (t *TPMContext) NVDefineSpace(authHandle Handle, auth Auth, publicInfo *NVPublic, authHandleAuth interface{},
	sessions ...*Session) error {
	if publicInfo == nil {
		return makeInvalidParamError("publicInfo", "nil value")
	}

	return t.RunCommand(CommandNVDefineSpace, sessions,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, Separator, auth,
		nvPublicSized{publicInfo})
}

// NVUndefineSpace executes the TPM2_NV_UndefineSpace command to remove the NV index associated with nvIndex,
// and free the resources used by it. If nvIndex does not correspond to a NV index, then this function will return
// an error.
//
// The authHandle parameter specifies the hierarchy used for authorization. If the NV index has the
// AttrNVPlatformCreate attribute then this must be HandlePlatform, else it must be HandleOwner. The command
// requires the user auth role for the specified hierarchy, provided via authHandleAuth. If the NV index has the
// AttrNVPolicyDelete attribute set, then this function will return an error and NVUndefineSpaceSpecial must be
// used instead.
//
// On successful completion, nvIndex will be invalidated.
func (t *TPMContext) NVUndefineSpace(authHandle Handle, nvIndex ResourceContext,
	authHandleAuth interface{}) error {
	if err := t.RunCommand(CommandNVUndefineSpace, nil,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, nvIndex); err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)
	return nil
}

// NVUndefineSpace executes the TPM2_NV_UndefineSpaceSpecial command to remove the NV index associated with
// nvIndex, and free the resources used by it. If nvIndex does not correspond to a NV index, then this function
// will return an error. If the NV index associated with nvIndex does not have the AttrNVPlatformCreate and
// AttrNVPolicyDelete attributes, then an error will be returned.
//
// The platform parameter must be HandlePlatform. The command requires the user auth role for the platform
// hierarchy, provided via platformAuth. The command requires the admin role for nvIndex, provided via nvIndexAuth.
//
// On successful completion, nvIndex will be invalidated.
func (t *TPMContext) NVUndefineSpaceSpecial(nvIndex ResourceContext, platform Handle, nvIndexAuth *Session,
	platformAuth interface{}) error {
	var s []*sessionParam
	s, err := t.validateAndAppendSessionParam(s, ResourceWithAuth{Context: nvIndex, Auth: nvIndexAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing resource context with authorization for nvIndex: "+
			"%v", err)
	}
	s, err = t.validateAndAppendSessionParam(s, HandleWithAuth{Handle: platform, Auth: platformAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing handle with authorization for platform: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandNVUndefineSpaceSpecial, s, nvIndex, platform)
	if err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)

	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		// If the HMAC key for this command includes the auth value for authHandle (eg, if the
		// PolicyAuthValue assertion was executed), the TPM will respond with a HMAC generated with a key
		// based on an empty auth value.
		ctx.sessionParams[0].session = authSession.copyWithNewAuthIfRequired(nil)
	}

	return t.processResponse(ctx)
}

func (t *TPMContext) nvReadPublic(nvIndex Handle, sessions ...*Session) (*NVPublic, Name, error) {
	var nvPublic nvPublicSized
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, sessions, nvIndex, Separator, Separator, Separator, &nvPublic,
		&nvName); err != nil {
		return nil, nil, err
	}
	return nvPublic.Ptr, nvName, nil
}

// NVReadPublic executes the TPM2_NV_ReadPublic command to read the public area of the NV index associated with
// nvIndex.
func (t *TPMContext) NVReadPublic(nvIndex ResourceContext, sessions ...*Session) (*NVPublic, Name, error) {
	if err := t.checkResourceContextParam(nvIndex); err != nil {
		return nil, nil, fmt.Errorf("invalid resource context for nvIndex: %v", err)
	}

	return t.nvReadPublic(nvIndex.Handle(), sessions...)
}

// NVWrite executes the TPM2_NV_Write command to write data to the NV index associated with nvIndex, at the
// specified offset. If the index has the AttrNVWriteLocked attribute set, this will return an error. If the NV
// index has the AttrNVWriteAll attribute set, an error will be returned if offset is not 0 and the size of data
// doesn't correspond to the size of the index. If the type of the index is NVTypeCounter, NVTypeBits or
// NVTypeExtend, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite,
// AttrNVAuthWrite and AttrNVPolicyWrite attributes. The handle used for authorization is specified via
// authContext. If the NV index has the AttrNVPPWrite attribute, authorization can be satisfied with
// HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization can be satisfied with
// HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyWrite attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been
// written to.
func (t *TPMContext) NVWrite(authContext, nvIndex ResourceContext, data MaxNVBuffer, offset uint16,
	authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVWrite, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator, data,
		offset); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

// NVSetPinCounterParams is a helper function for NVWrite for updating the contents of the NV pin pass or NV pin
// fail index associated with nvIndex. If the index has the AttrNVWriteLocked attribute set, this will return an
// error. If the type of nvIndex is not NVTypePinPass of NVTypePinFail, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite,
// AttrNVAuthWrite and AttrNVPolicyWrite attributes. The handle used for authorization is specified via
// authContext. If the NV index has the AttrNVPPWrite attribute, authorization can be satisfied with
// HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization can be satisfied with
// HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyWrite attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been
// written to.
func (t *TPMContext) NVSetPinCounterParams(authContext, nvIndex ResourceContext, params *NVPinCounterParams,
	authContextAuth interface{}, sessions ...*Session) error {
	context, isNv := nvIndex.(*nvIndexContext)
	if !isNv {
		return errors.New("nvIndex does not correspond to a NV index")
	}
	if context.public.Attrs.Type() != NVTypePinPass && context.public.Attrs.Type() != NVTypePinFail {
		return errors.New("nvIndex does not correspond to a PIN pass or PIN fail index")
	}
	data, err := MarshalToBytes(params)
	if err != nil {
		return fmt.Errorf("cannot marshal PIN counter parameters: %v", err)
	}
	return t.NVWrite(authContext, nvIndex, data, 0, authContextAuth, sessions...)
}

// NVIncrement executes the TPM2_NV_Increment command to increment the counter associated with nvIndex. If the
// index has the AttrNVWriteLocked attribute set, this will return an error. If the type of the index is not
// NVTypeCounter, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite,
// AttrNVAuthWrite and AttrNVPolicyWrite attributes. The handle used for authorization is specified via
// authContext. If the NV index has the AttrNVPPWrite attribute, authorization can be satisfied with
// HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization can be satisfied with
// HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyWrite attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been
// written to.
func (t *TPMContext) NVIncrement(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVIncrement, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

// NVExtend executes the TPM2_NV_Extend command to extend data to the NV index associated with nvIndex, using
// the index's name algorithm. If the index has the AttrNVWriteLocked attribute set, this will return an error.
// If the type of the index is not NVTypeExtend, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite,
// AttrNVAuthWrite and AttrNVPolicyWrite attributes. The handle used for authorization is specified via
// authContext. If the NV index has the AttrNVPPWrite attribute, authorization can be satisfied with
// HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization can be satisfied with
// HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyWrite attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been
// written to.
func (t *TPMContext) NVExtend(authContext, nvIndex ResourceContext, data MaxNVBuffer, authContextAuth interface{},
	sessions ...*Session) error {
	if err := t.RunCommand(CommandNVExtend, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		data); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

// NVSetBits executes the TPM2_NV_SetBits command to OR the value of bits with the contents of the NV index
// associated with nvIndex. If the index has the AttrNVWriteLocked attribute set, this will return an error. If
// the type of the index is not NVTypeBits, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite,
// AttrNVAuthWrite and AttrNVPolicyWrite attributes. The handle used for authorization is specified via
// authContext. If the NV index has the AttrNVPPWrite attribute, authorization can be satisfied with
// HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization can be satisfied with
// HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyWrite attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the AttrNVWritten flag will be set if this is the first time that the index has been
// written to.
func (t *TPMContext) NVSetBits(authContext, nvIndex ResourceContext, bits uint64,
	authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVSetBits, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		bits); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

// NVWriteLock executes the TPM2_NV_WriteLock command to inhibit further writes to the NV index associated with
// nvIndex. If the index has neither the AttrNVWriteDefine or AttrNVWriteStClear attributes set, this will return
// an error.
//
// The command requires authorization, defined by the state of the AttrNVPPWrite, AttrNVOwnerWrite,
// AttrNVAuthWrite and AttrNVPolicyWrite attributes. The handle used for authorization is specified via
// authContext. If the NV index has the AttrNVPPWrite attribute, authorization can be satisfied with
// HandlePlatform. If the NV index has the AttrNVOwnerWrite attribute, authorization can be satisfied with
// HandleOwner. If the NV index has the AttrNVAuthWrite or AttrNVPolicyWrite attribute, authorization can be
// satisfied with nvIndex. The command requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthWrite attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyWrite attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the AttrNVWriteLocked attribute will be set. It will be cleared again (and writes
// will be reenabled) on the next TPM reset or TPM restart unless the index has the AttrNVWriteDefine attribute
// set and AttrNVWritten attribute is set.
func (t *TPMContext) NVWriteLock(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVWriteLock, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWriteLocked)
	return nil
}

// NVGlobalWriteLock executes the TPM2_NV_GlobalWriteLock command to inhibit further writes for all NV indexes
// that have the AttrNVGlobalLock attribute set.
//
// The authHandle parameter specifies a hierarchy, and should be either HandlePlatform or HandleOwner. The command
// requires the user auth role for authHandle, provided via authHandleAuth.
//
// On successful completion, the AttrNVWriteLocked attribute will be set for all NV indexes that have the
// AttrNVGlobalLock attribute set. If an index also has the AttrNVWriteDefine attribute set, this will permanently
// inhibit further writes unless AttrNVWritten is clear.
func (t *TPMContext) NVGlobalWriteLock(authHandle Handle, authHandleAuth interface{}) error {
	if err := t.RunCommand(CommandNVGlobalWriteLock, nil,
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

// NVRead executes the TPM2_NV_Read command to read the contents of the NV index associated with nvIndex. The
// amount of data to read, and the offset within the index are defined by the size and offset parameters. If the
// index has the AttrNVReadLocked attribute set, this will return an error.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead,
// AttrNVAuthRead and AttrNVPolicyRead attributes. The handle used for authorization is specified via authContext.
// If the NV index has the AttrNVPPRead attribute, authorization can be satisfied with HandlePlatform. If the NV
// index has the AttrNVOwnerRead attribute, authorization can be satisfied with HandleOwner. If the NV index has
// the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied with nvIndex. The command
// requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyRead attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the requested data will be returned.
func (t *TPMContext) NVRead(authContext, nvIndex ResourceContext, size, offset uint16, authContextAuth interface{},
	sessions ...*Session) (MaxNVBuffer, error) {
	var data MaxNVBuffer
	if err := t.RunCommand(CommandNVRead, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator, size, offset,
		Separator, Separator, &data); err != nil {
		return nil, err
	}

	return data, nil
}

// NVReadCounter is a helper function for NVRead for reading the contents of the NV counter index associated with
// nvIndex. If the index has the AttrNVReadLocked attribute set, this will return an error. If the type of nvIndex
// is not NVTypeCounter, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead,
// AttrNVAuthRead and AttrNVPolicyRead attributes. The handle used for authorization is specified via authContext.
// If the NV index has the AttrNVPPRead attribute, authorization can be satisfied with HandlePlatform. If the NV
// index has the AttrNVOwnerRead attribute, authorization can be satisfied with HandleOwner. If the NV index has
// the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied with nvIndex. The command
// requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyRead attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the current counter value will be returned.
func (t *TPMContext) NVReadCounter(authContext, nvIndex ResourceContext, authContextAuth interface{},
	sessions ...*Session) (uint64, error) {
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
	return binary.BigEndian.Uint64(data), nil
}

// NVReadPinCounterParams is a helper function for NVRead for reading the contents of the NV pin pass or NV pin
// fail index associated with nvIndex. If the index has the AttrNVReadLocked attribute set, this will return an
// error. If the type of nvIndex is not NVTypePinPass of NVTypePinFail, an error will be returned.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead,
// AttrNVAuthRead and AttrNVPolicyRead attributes. The handle used for authorization is specified via authContext.
// If the NV index has the AttrNVPPRead attribute, authorization can be satisfied with HandlePlatform. If the NV
// index has the AttrNVOwnerRead attribute, authorization can be satisfied with HandleOwner. If the NV index has
// the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied with nvIndex. The command
// requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyRead attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the current PIN count and limit will be returned.
func (t *TPMContext) NVReadPinCounterParams(authContext, nvIndex ResourceContext, authContextAuth interface{},
	sessions ...*Session) (*NVPinCounterParams, error) {
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
		return nil, wrapUnmarshallingError(CommandNVRead, "NV index data", err)
	}
	return &res, nil
}

// NVReadLock executes the TPM2_NV_ReadLock command to inhibit further reads of the NV index associated with
// nvIndex. If the index doesn't have the AttrNVReadStClear attribute set, this will return an error.
//
// The command requires authorization, defined by the state of the AttrNVPPRead, AttrNVOwnerRead,
// AttrNVAuthRead and AttrNVPolicyRead attributes. The handle used for authorization is specified via authContext.
// If the NV index has the AttrNVPPRead attribute, authorization can be satisfied with HandlePlatform. If the NV
// index has the AttrNVOwnerRead attribute, authorization can be satisfied with HandleOwner. If the NV index has
// the AttrNVAuthRead or AttrNVPolicyRead attribute, authorization can be satisfied with nvIndex. The command
// requires the user auth role for authContext, provided via authContextAuth.
//
// If nvIndex is being used for authorization and the AttrNVAuthRead attribute is defined, the authorization can
// be satisfied by supplying the authorization value for the index (either directly or using a HMAC session). If
// nvIndex is being used for authorization and the AttrNVPolicyRead attribute is defined, the authorization can
// be satisfied using a policy session with a digest that matches the authorization policy for the index.
//
// On successful completion, the AttrNVReadLocked attribute will be set. It will be cleared again (and reads
// will be reenabled) on the next TPM reset or TPM restart.
func (t *TPMContext) NVReadLock(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVReadLock, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVReadLocked)
	return nil
}

// NVChangeAuth executes the TPM2_NV_ChangeAuth command to change the authorization value for the NV index
// associated with nvIndex, setting it to the new value defined by newAuth. The command requires the admin auth
// role for nvIndex, provided via nvIndexAuth.
func (t *TPMContext) NVChangeAuth(nvIndex ResourceContext, newAuth Auth, nvIndexAuth *Session,
	sessions ...*Session) error {
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

	ctx, err := t.runCommandWithoutProcessingResponse(CommandNVChangeAuth, s, nvIndex, Separator, newAuth)
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
