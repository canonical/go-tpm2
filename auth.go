// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"

	"golang.org/x/xerrors"
)

type policyHMACType uint8
type sessionAttrs uint8

const (
	policyHMACTypeNoAuth policyHMACType = iota
	policyHMACTypeAuth
	policyHMACTypePassword

	policyHMACTypeMax = policyHMACTypePassword
)

const (
	attrContinueSession sessionAttrs = 1 << iota
	attrAuditExclusive
	attrAuditReset
	attrDecrypt = 1 << (iota + 2)
	attrEncrypt
	attrAudit
)

type sessionParam struct {
	associatedContext HandleContext
	session           *Session // For any session that isn't a password session
	authValue         []byte   // For a password session, this is the auth value
}

type authCommand struct {
	SessionHandle Handle
	Nonce         Nonce
	SessionAttrs  sessionAttrs
	HMAC          Auth
}

type authResponse struct {
	Nonce        Nonce
	SessionAttrs sessionAttrs
	HMAC         Auth
}

type commandAuthArea []authCommand

type commandAuthAreaRawSlice struct {
	Data []authCommand `tpm2:"raw"`
}

func (a *commandAuthArea) Marshal(buf io.Writer) error {
	tmpBuf := new(bytes.Buffer)
	if err := MarshalToWriter(tmpBuf, commandAuthAreaRawSlice{[]authCommand(*a)}); err != nil {
		panic(fmt.Sprintf("cannot marshal raw command auth area to temporary buffer: %v", err))
	}

	if err := binary.Write(buf, binary.BigEndian, uint32(tmpBuf.Len())); err != nil {
		return xerrors.Errorf("cannot write size of auth area to buffer: %w", err)
	}

	if _, err := tmpBuf.WriteTo(buf); err != nil {
		return xerrors.Errorf("cannot write marshalled auth area to buffer: %w", err)
	}
	return nil
}

func (a *commandAuthArea) Unmarshal(buf io.Reader) error {
	panic("no need to unmarshal a command's auth area")
}

func attrsFromSession(session *Session) sessionAttrs {
	var attrs sessionAttrs
	if session.Attrs&AttrContinueSession > 0 {
		attrs |= attrContinueSession
	}
	if session.Attrs&AttrAuditExclusive > 0 {
		attrs |= (attrAuditExclusive | attrAudit)
	}
	if session.Attrs&AttrAuditReset > 0 {
		attrs |= (attrAuditReset | attrAudit)
	}
	if session.Attrs&AttrCommandEncrypt > 0 {
		attrs |= attrDecrypt
	}
	if session.Attrs&AttrResponseEncrypt > 0 {
		attrs |= attrEncrypt
	}
	if session.Attrs&AttrAudit > 0 {
		attrs |= attrAudit
	}
	return attrs
}

func computeCallerNonces(params []*sessionParam) error {
	for _, param := range params {
		if param.session == nil {
			continue
		}

		context := param.session.Context.(*sessionContext)

		if err := cryptComputeNonce(context.nonceCaller); err != nil {
			return fmt.Errorf("cannot compute new caller nonce: %v", err)
		}
	}
	return nil
}

func computeBindName(name Name, auth Auth) Name {
	if len(auth) > len(name) {
		auth = auth[0:len(name)]
	}
	r := make(Name, len(name))
	copy(r, name)
	j := 0
	for i := len(name) - len(auth); i < len(name); i++ {
		r[i] ^= auth[j]
		j++
	}
	return r
}

func (s *Session) computeSessionHMACKey() []byte {
	var key []byte
	key = append(key, s.Context.(*sessionContext).sessionKey...)
	if s.includeAuthValue {
		key = append(key, s.AuthValue...)
	}
	return key
}

func (s *Session) updateIncludeAuthValueInHMACKey(associatedContext HandleContext) {
	sc := s.Context.(*sessionContext)
	switch sc.sessionType {
	case SessionTypeHMAC:
		switch {
		case associatedContext == nil:
			s.includeAuthValue = false
		case !sc.isBound:
			s.includeAuthValue = true
		default:
			bindName := computeBindName(associatedContext.Name(), s.AuthValue)
			s.includeAuthValue = !bytes.Equal(bindName, sc.boundEntity)
		}
	case SessionTypePolicy:
		s.includeAuthValue = sc.policyHMACType == policyHMACTypeAuth
	}
}

func (s *Session) copyWithNewAuthIfRequired(newAuth []byte) *Session {
	if !s.includeAuthValue {
		return s
	}
	return &Session{Context: s.Context, AuthValue: newAuth, Attrs: s.Attrs, includeAuthValue: true}
}

func buildCommandSessionAuth(tpm *TPMContext, session *Session, associatedContext HandleContext, commandCode CommandCode,
	commandHandles []Name, cpBytes []byte, decryptNonce, encryptNonce Nonce) *authCommand {
	sessionContext := session.Context.(*sessionContext)

	attrs := attrsFromSession(session)
	var hmac []byte

	if sessionContext.sessionType == SessionTypePolicy && sessionContext.policyHMACType == policyHMACTypePassword {
		hmac = session.AuthValue
	} else {
		session.updateIncludeAuthValueInHMACKey(associatedContext)
		key := session.computeSessionHMACKey()
		if len(key) > 0 {
			cpHash := cryptComputeCpHash(sessionContext.hashAlg, commandCode, commandHandles, cpBytes)
			hmac = cryptComputeSessionCommandHMAC(sessionContext, key, cpHash, decryptNonce, encryptNonce, attrs)
		}

	}

	return &authCommand{
		SessionHandle: session.Context.Handle(),
		Nonce:         sessionContext.nonceCaller,
		SessionAttrs:  attrs,
		HMAC:          hmac}
}

func buildCommandPasswordAuth(authValue Auth) *authCommand {
	return &authCommand{SessionHandle: HandlePW, SessionAttrs: attrContinueSession, HMAC: authValue}
}

func buildCommandAuth(tpm *TPMContext, param *sessionParam, commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	decryptNonce, encryptNonce Nonce) *authCommand {
	if param.session == nil {
		return buildCommandPasswordAuth(Auth(param.authValue))
	}
	return buildCommandSessionAuth(tpm, param.session, param.associatedContext, commandCode, commandHandles, cpBytes, decryptNonce,
		encryptNonce)
}

func processResponseSessionAuth(tpm *TPMContext, resp authResponse, session *Session, associatedContext HandleContext,
	commandCode CommandCode, responseCode ResponseCode, rpBytes []byte) error {
	sc := session.Context.(*sessionContext)
	sc.nonceTPM = resp.Nonce
	sc.isAudit = resp.SessionAttrs&attrAudit > 0
	sc.isExclusive = resp.SessionAttrs&attrAuditExclusive > 0

	if resp.SessionAttrs&attrContinueSession == 0 {
		tpm.evictHandleContext(sc)
	}

	if sc.sessionType == SessionTypePolicy && sc.policyHMACType == policyHMACTypePassword {
		if len(resp.HMAC) != 0 {
			return errors.New("non-zero length HMAC for policy session with PolicyPassword assertion")
		}
		return nil
	}

	key := session.computeSessionHMACKey()
	if len(key) == 0 && len(resp.HMAC) == 0 {
		return nil
	}

	rpHash := cryptComputeRpHash(sc.hashAlg, responseCode, commandCode, rpBytes)
	hmac := cryptComputeSessionResponseHMAC(sc, key, rpHash, resp.SessionAttrs)

	if !bytes.Equal(hmac, resp.HMAC) {
		return errors.New("incorrect HMAC")
	}

	return nil
}

func processResponseAuth(tpm *TPMContext, resp authResponse, param *sessionParam, commandCode CommandCode,
	responseCode ResponseCode, rpBytes []byte) error {
	if param.session == nil {
		return nil
	}

	return processResponseSessionAuth(tpm, resp, param.session, param.associatedContext, commandCode, responseCode, rpBytes)
}

func buildCommandAuthArea(tpm *TPMContext, sessionParams []*sessionParam, commandCode CommandCode, commandHandles []Name,
	cpBytes []byte) (commandAuthArea, error) {
	if len(sessionParams) > 3 {
		return nil, errors.New("too many session parameters provided")
	}

	if err := computeCallerNonces(sessionParams); err != nil {
		return nil, fmt.Errorf("cannot compute caller nonces: %v", err)
	}

	decryptNonce, err := encryptCommandParameter(sessionParams, cpBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt first command parameter: %v", err)
	}

	encryptNonce := computeEncryptNonce(sessionParams)

	var area commandAuthArea
	for i, param := range sessionParams {
		var dn, en Nonce
		if i == 0 {
			dn = decryptNonce
			en = encryptNonce
		}
		a := buildCommandAuth(tpm, param, commandCode, commandHandles, cpBytes, dn, en)
		area = append(area, *a)
	}

	return area, nil
}

func processResponseAuthArea(tpm *TPMContext, authResponses []authResponse, sessionParams []*sessionParam, commandCode CommandCode,
	responseCode ResponseCode, rpBytes []byte) error {
	for i, resp := range authResponses {
		if err := processResponseAuth(tpm, resp, sessionParams[i], commandCode, responseCode, rpBytes); err != nil {
			return fmt.Errorf("encountered an error for session at index %d: %v", i, err)
		}
	}

	if err := decryptResponseParameter(sessionParams, rpBytes); err != nil {
		return fmt.Errorf("cannot decrypt first response parameter: %v", err)
	}

	return nil
}

func (t *TPMContext) validateAndAppendSessionParam(params []*sessionParam, in interface{}) ([]*sessionParam, error) {
	makeSessionParamFromAuth := func(auth interface{}) *sessionParam {
		switch a := auth.(type) {
		case string:
			return &sessionParam{authValue: []byte(a)}
		case []byte:
			return &sessionParam{authValue: a}
		case nil:
			return &sessionParam{}
		case *Session:
			return &sessionParam{session: a}
		}
		return nil
	}

	var s *sessionParam

	switch i := in.(type) {
	case HandleContextWithAuth:
		s = makeSessionParamFromAuth(i.Auth)
		if s == nil {
			return nil, fmt.Errorf("invalid auth parameter type (%s)", reflect.TypeOf(i.Auth))
		}
		s.associatedContext = i.Context
	case HandleWithAuth:
		s = makeSessionParamFromAuth(i.Auth)
		if s == nil {
			return nil, fmt.Errorf("invalid auth parameter type (%s)", reflect.TypeOf(i.Auth))
		}
		// Wrap the handle in permanentContext here. Handles that only represent permanent resources are
		// the only use case for supporting passing Handles to RunCommand. Consider it a bug to pass a
		// Handle that represents anything other than a permanent resource (HandleContext should be
		// used instead).
		if i.Handle.Type() != HandleTypePermanent && i.Handle.Type() != HandleTypePCR {
			return nil, errors.New("invalid handle type")
		}
		rc, _ := t.WrapHandle(i.Handle)
		s.associatedContext = rc
	case []*Session:
		addedOne := false
		for _, s := range i {
			if s == nil {
				if !addedOne {
					continue
				}
				return nil, errors.New("nil session parameter")
			}
			addedOne = true
			var err error
			params, err = t.validateAndAppendSessionParam(params, s)
			if err != nil {
				return nil, err
			}
		}
		return params, nil
	case *Session:
		s = &sessionParam{session: i}
	default:
		return nil, fmt.Errorf("invalid session parameter type (%s)", reflect.TypeOf(in))
	}

	if s.session != nil {
		if err := t.checkHandleContextParam(s.session.Context); err != nil {
			return nil, fmt.Errorf("invalid resource context for session: %v", err)
		}
		sc, isSessionContext := s.session.Context.(*sessionContext)
		if !isSessionContext {
			return nil, errors.New("invalid resource context for session: not a session context")
		}
		if !sc.usable {
			return nil, errors.New("invalid resource context for session: not complete and loaded")
		}
	}

	return append(params, s), nil
}
