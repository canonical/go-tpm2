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
)

type policyHMACType uint8
type sessionAttrs uint8

const (
	policyHMACTypeNoAuth policyHMACType = iota
	policyHMACTypeAuth
	policyHMACTypePassword
)

const (
	attrContinueSession sessionAttrs = 1 << iota
	attrAuditExclusive
	attrAuditReset
	attrDecrypt = 1 << (iota + 2)
	attrEncrypt
	attrAudit
)

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

func (a *commandAuthArea) Marshal(buf io.Writer) error {
	tmpBuf := new(bytes.Buffer)
	if err := MarshalToWriter(tmpBuf, RawSlice([]authCommand(*a))); err != nil {
		return nil
	}

	if err := binary.Write(buf, binary.BigEndian, uint32(tmpBuf.Len())); err != nil {
		return fmt.Errorf("cannot write size of auth area to buffer: %v", err)
	}

	n, err := buf.Write(tmpBuf.Bytes())
	if err != nil {
		return fmt.Errorf("cannot write marshalled auth area to buffer: %v", err)
	}
	if n != tmpBuf.Len() {
		return errors.New("cannot write complete marshalled auth area to buffer")
	}
	return nil
}

func (a *commandAuthArea) Unmarshal(buf io.Reader) error {
	return errors.New("no need to unmarshal a command's auth area")
}

func attrsFromSession(session *Session) sessionAttrs {
	var attrs sessionAttrs
	if session.Attrs&AttrContinueSession > 0 {
		attrs |= attrContinueSession
	}
	if session.Attrs&AttrCommandEncrypt > 0 {
		attrs |= attrDecrypt
	}
	if session.Attrs&AttrResponseEncrypt > 0 {
		attrs |= attrEncrypt
	}
	return attrs
}

func sessionContextFromParam(param interface{}) *sessionContext {
	switch p := param.(type) {
	case HandleWithAuth:
		return sessionContextFromParam(p.Auth)
	case ResourceWithAuth:
		return sessionContextFromParam(p.Auth)
	case *Session:
		return p.Context.(*sessionContext)
	}
	return nil
}

func validateSessionParam(tpm *tpmContext, param interface{}) error {
	switch p := param.(type) {
	case HandleWithAuth:
		return validateSessionParam(tpm, p.Auth)
	case ResourceWithAuth:
		return validateSessionParam(tpm, p.Auth)
	case string:
		return nil
	case []byte:
		return nil
	case Auth:
		return nil
	case nil:
		return nil
	case *Session:
		if err := tpm.checkResourceContextParam(p.Context, "session"); err != nil {
			return err
		}
		_, isSessionContext := p.Context.(*sessionContext)
		if !isSessionContext {
			return errors.New("invalid resource context: not a session context")
		}
		return nil
	default:
		return fmt.Errorf("unexpected type (%s)", reflect.TypeOf(param))
	}
}

func validateSessionParams(tpm *tpmContext, params ...interface{}) error {
	if len(params) > 3 {
		return errors.New("too many session parameters provided")
	}

	for i, param := range params {
		if err := validateSessionParam(tpm, param); err != nil {
			return fmt.Errorf("invalid session parameter at index %d: %v", i, err)
		}
	}

	return nil
}

func computeCallerNonces(params ...interface{}) error {
	for _, param := range params {
		context := sessionContextFromParam(param)
		if context == nil {
			continue
		}

		if err := cryptComputeNonce(context.nonceCaller); err != nil {
			return fmt.Errorf("cannot compute new caller nonce: %v", err)
		}
	}
	return nil
}

func computeSessionHMACKey(sessionContext *sessionContext, authValue []byte,
	associatedContext ResourceContext) []byte {
	var key []byte
	key = append(key, sessionContext.sessionKey...)

	var includeAuthValue bool
	if sessionContext.sessionType == SessionTypeHMAC {
		includeAuthValue = !sessionContext.isBoundTo(associatedContext)
	} else {
		includeAuthValue = sessionContext.policyHMACType == policyHMACTypeAuth
	}

	if includeAuthValue {
		key = append(key, authValue...)
	}

	return key
}

func buildCommandSessionAuth(tpm *tpmContext, commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	session *Session, associatedContext ResourceContext, decryptNonce, encryptNonce Nonce) (*authCommand,
	error) {
	sessionContext := session.Context.(*sessionContext)

	attrs := attrsFromSession(session)
	var hmac []byte

	if sessionContext.sessionType == SessionTypePolicy &&
		sessionContext.policyHMACType == policyHMACTypePassword {
		hmac = session.AuthValue
	} else {
		key := computeSessionHMACKey(sessionContext, session.AuthValue, associatedContext)
		if len(key) > 0 {
			cpHash := cryptComputeCpHash(sessionContext.hashAlg, commandCode, commandHandles, cpBytes)
			hmac = cryptComputeSessionCommandHMAC(sessionContext, key, cpHash, decryptNonce,
				encryptNonce, attrs)
		}

	}

	return &authCommand{SessionHandle: session.Context.Handle(),
		Nonce:        sessionContext.nonceCaller,
		SessionAttrs: attrs,
		HMAC:         hmac}, nil
}

func buildCommandPasswordAuth(authValue Auth) *authCommand {
	return &authCommand{SessionHandle: HandlePW, SessionAttrs: attrContinueSession, HMAC: authValue}
}

func buildCommandAuth(tpm *tpmContext, commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	param interface{}, context ResourceContext, decryptNonce, encryptNonce Nonce) (*authCommand, error) {
	switch p := param.(type) {
	case HandleWithAuth:
		rc := &permanentContext{handle: p.Handle}
		return buildCommandAuth(tpm, commandCode, commandHandles, cpBytes, p.Auth, rc, decryptNonce,
			encryptNonce)
	case ResourceWithAuth:
		return buildCommandAuth(tpm, commandCode, commandHandles, cpBytes, p.Auth, p.Context, decryptNonce,
			encryptNonce)
	case string:
		return buildCommandPasswordAuth(Auth(p)), nil
	case []byte:
		return buildCommandPasswordAuth(Auth(p)), nil
	case Auth:
		return buildCommandPasswordAuth(p), nil
	case nil:
		return buildCommandPasswordAuth(nil), nil
	case *Session:
		return buildCommandSessionAuth(tpm, commandCode, commandHandles, cpBytes, p, context, decryptNonce,
			encryptNonce)
	}
	panic("Unrecognized session parameter type")
}

func processResponseSessionAuth(tpm *tpmContext, responseCode ResponseCode, commandCode CommandCode,
	rpBytes []byte, resp authResponse, session *Session, associatedContext ResourceContext) error {
	sessionContext := session.Context.(*sessionContext)
	sessionContext.nonceTPM = resp.Nonce

	if resp.SessionAttrs&attrContinueSession == 0 {
		tpm.evictResourceContext(sessionContext)
	}

	if sessionContext.sessionType == SessionTypePolicy &&
		sessionContext.policyHMACType == policyHMACTypePassword {
		if len(resp.HMAC) != 0 {
			return InvalidAuthResponseError{Command: commandCode,
				msg: "non-zero length HMAC for policy password auth"}
		}
		return nil
	}

	key := computeSessionHMACKey(sessionContext, session.AuthValue, associatedContext)
	if len(key) == 0 {
		return nil
	}

	rpHash := cryptComputeRpHash(sessionContext.hashAlg, responseCode, commandCode, rpBytes)
	hmac := cryptComputeSessionResponseHMAC(sessionContext, key, rpHash, resp.SessionAttrs)

	if !bytes.Equal(hmac, resp.HMAC) {
		return InvalidAuthResponseError{Command: commandCode, msg: "incorrect HMAC"}
	}

	return nil
}

func processResponseAuth(tpm *tpmContext, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte,
	resp authResponse, param interface{}, context ResourceContext) error {
	switch p := param.(type) {
	case HandleWithAuth:
		rc := &permanentContext{handle: p.Handle}
		return processResponseAuth(tpm, responseCode, commandCode, rpBytes, resp, p.Auth, rc)
	case ResourceWithAuth:
		return processResponseAuth(tpm, responseCode, commandCode, rpBytes, resp, p.Auth, p.Context)
	case *Session:
		return processResponseSessionAuth(tpm, responseCode, commandCode, rpBytes, resp, p, context)
	}
	return nil
}

func buildCommandAuthArea(tpm *tpmContext, commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	sessionParams ...interface{}) (commandAuthArea, error) {
	if err := validateSessionParams(tpm, sessionParams...); err != nil {
		return nil, fmt.Errorf("error whilst validating session parameters: %v", err)
	}

	if err := computeCallerNonces(sessionParams...); err != nil {
		return nil, fmt.Errorf("cannot compute caller nonces: %v", err)
	}

	decryptNonce, err := encryptCommandParameter(cpBytes, sessionParams...)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt first command parameter: %v", err)
	}

	encryptNonce := computeEncryptNonce(sessionParams...)

	var area commandAuthArea
	for i, param := range sessionParams {
		var dn, en Nonce
		if i == 0 {
			dn = decryptNonce
			en = encryptNonce
		}
		a, err := buildCommandAuth(tpm, commandCode, commandHandles, cpBytes, param, nil, dn, en)
		if err != nil {
			return nil, fmt.Errorf("cannot build auth area for command %s at index %d: %v",
				commandCode, i, err)
		}
		area = append(area, *a)
	}

	return area, nil
}

func processResponseAuthArea(tpm *tpmContext, responseCode ResponseCode, commandCode CommandCode,
	rpBytes []byte, authResponses []authResponse, sessionParams ...interface{}) error {
	for i, resp := range authResponses {
		if err := processResponseAuth(tpm, responseCode, commandCode, rpBytes, resp,
			sessionParams[i], nil); err != nil {
			return err
		}
	}

	if err := decryptResponseParameter(rpBytes, sessionParams...); err != nil {
		return fmt.Errorf("cannot decrypt first response parameter: %v", err)
	}

	return nil
}
