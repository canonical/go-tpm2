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

	"github.com/canonical/go-tpm2/mu"

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
	isAuth            bool            // Whether this parameter is used for authorization
	associatedContext ResourceContext // The resource associated with an authorization - can be nil
	session           *sessionContext // The session instance used for this session parameter - will be nil for a password authorization
	includeAuthValue  bool            // Whether the authorization value of associatedContext is included in the HMAC key
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

func (a *commandAuthArea) Marshal(w io.Writer) error {
	tmpBuf := new(bytes.Buffer)
	if _, err := mu.MarshalToWriter(tmpBuf, commandAuthAreaRawSlice{[]authCommand(*a)}); err != nil {
		panic(fmt.Sprintf("cannot marshal raw command auth area to temporary buffer: %v", err))
	}

	if err := binary.Write(w, binary.BigEndian, uint32(tmpBuf.Len())); err != nil {
		return xerrors.Errorf("cannot write size of auth area to buffer: %w", err)
	}

	if _, err := tmpBuf.WriteTo(w); err != nil {
		return xerrors.Errorf("cannot write marshalled auth area to buffer: %w", err)
	}
	return nil
}

func (a *commandAuthArea) Unmarshal(r mu.Reader) error {
	panic("no need to unmarshal a command's auth area")
}

func attrsFromSession(session *sessionContext) sessionAttrs {
	var attrs sessionAttrs
	if session.attrs&AttrContinueSession > 0 {
		attrs |= attrContinueSession
	}
	if session.attrs&AttrAuditExclusive > 0 {
		attrs |= (attrAuditExclusive | attrAudit)
	}
	if session.attrs&AttrAuditReset > 0 {
		attrs |= (attrAuditReset | attrAudit)
	}
	if session.attrs&AttrCommandEncrypt > 0 {
		attrs |= attrDecrypt
	}
	if session.attrs&AttrResponseEncrypt > 0 {
		attrs |= attrEncrypt
	}
	if session.attrs&AttrAudit > 0 {
		attrs |= attrAudit
	}
	return attrs
}

func computeCallerNonces(params []*sessionParam) error {
	for _, param := range params {
		if param.session == nil {
			continue
		}

		if err := cryptComputeNonce(param.session.scData().NonceCaller); err != nil {
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

func (s *sessionParam) computeSessionHMACKey() []byte {
	var authValue []byte
	if s.associatedContext != nil {
		authValue = s.associatedContext.(resourceContextPrivate).authValue()
	}
	var key []byte
	key = append(key, s.session.scData().SessionKey...)
	if s.includeAuthValue {
		key = append(key, authValue...)
	}
	return key
}

func buildCommandSessionAuth(tpm *TPMContext, param *sessionParam, commandCode CommandCode, commandHandles []Name, cpBytes []byte, decryptNonce, encryptNonce Nonce) *authCommand {
	scData := param.session.scData()

	attrs := attrsFromSession(param.session)
	var hmac []byte

	if scData.SessionType == SessionTypePolicy && scData.PolicyHMACType == policyHMACTypePassword {
		// Policy session that contains a TPM2_PolicyPassword assertion. The HMAC is just the authorization value
		// of the resource being authorized.
		if param.associatedContext != nil {
			hmac = param.associatedContext.(resourceContextPrivate).authValue()
		}
	} else {
		key := param.computeSessionHMACKey()
		if len(key) > 0 {
			cpHash := cryptComputeCpHash(scData.HashAlg, commandCode, commandHandles, cpBytes)
			hmac = cryptComputeSessionCommandHMAC(param.session, key, cpHash, decryptNonce, encryptNonce, attrs)
		}
	}

	return &authCommand{
		SessionHandle: param.session.Handle(),
		Nonce:         scData.NonceCaller,
		SessionAttrs:  attrs,
		HMAC:          hmac}
}

func buildCommandPasswordAuth(authValue Auth) *authCommand {
	return &authCommand{SessionHandle: HandlePW, SessionAttrs: attrContinueSession, HMAC: authValue}
}

func buildCommandAuth(tpm *TPMContext, param *sessionParam, commandCode CommandCode, commandHandles []Name, cpBytes []byte, decryptNonce, encryptNonce Nonce) *authCommand {
	if param.session == nil {
		// Cleartext password session
		var authValue []byte
		if param.associatedContext != nil {
			authValue = param.associatedContext.(resourceContextPrivate).authValue()
		}
		return buildCommandPasswordAuth(Auth(authValue))
	}
	// HMAC or policy session
	return buildCommandSessionAuth(tpm, param, commandCode, commandHandles, cpBytes, decryptNonce, encryptNonce)
}

func processResponseSessionAuth(tpm *TPMContext, resp authResponse, param *sessionParam, commandCode CommandCode, responseCode ResponseCode, rpBytes []byte) error {
	scData := param.session.scData()
	scData.NonceTPM = resp.Nonce
	scData.IsAudit = resp.SessionAttrs&attrAudit > 0
	scData.IsExclusive = resp.SessionAttrs&attrAuditExclusive > 0

	if resp.SessionAttrs&attrContinueSession == 0 {
		param.session.invalidate()
	}

	if scData.SessionType == SessionTypePolicy && scData.PolicyHMACType == policyHMACTypePassword {
		if len(resp.HMAC) != 0 {
			return errors.New("non-zero length HMAC for policy session with PolicyPassword assertion")
		}
		return nil
	}

	key := param.computeSessionHMACKey()
	if len(key) == 0 && len(resp.HMAC) == 0 {
		return nil
	}

	rpHash := cryptComputeRpHash(scData.HashAlg, responseCode, commandCode, rpBytes)
	hmac := cryptComputeSessionResponseHMAC(param.session, key, rpHash, resp.SessionAttrs)

	if !bytes.Equal(hmac, resp.HMAC) {
		return errors.New("incorrect HMAC")
	}

	return nil
}

func processResponseAuth(tpm *TPMContext, resp authResponse, param *sessionParam, commandCode CommandCode, responseCode ResponseCode, rpBytes []byte) error {
	if param.session == nil {
		return nil
	}

	return processResponseSessionAuth(tpm, resp, param, commandCode, responseCode, rpBytes)
}

func buildCommandAuthArea(tpm *TPMContext, sessionParams []*sessionParam, commandCode CommandCode, commandHandles []Name, cpBytes []byte) (commandAuthArea, error) {
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

func processResponseAuthArea(tpm *TPMContext, authResponses []authResponse, sessionParams []*sessionParam, commandCode CommandCode, responseCode ResponseCode, rpBytes []byte) error {
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

func (t *TPMContext) validateAndAppendSessionParam(params []*sessionParam, in *sessionParam, isAuth bool) ([]*sessionParam, error) {
	if in.session != nil {
		if err := t.checkHandleContextParam(in.session); err != nil {
			return nil, fmt.Errorf("invalid context for session: %v", err)
		}
		scData := in.session.scData()
		if scData == nil {
			return nil, errors.New("invalid context for session: incomplete session can only be used in TPMContext.FlushContext")
		}
		switch scData.SessionType {
		case SessionTypeHMAC:
			switch {
			case !isAuth:
			case !scData.IsBound:
				in.includeAuthValue = true
			default:
				associatedContext := in.associatedContext
				if associatedContext == nil {
					associatedContext = makeDummyContext(HandleNull)
				}
				bindName := computeBindName(associatedContext.Name(), associatedContext.(resourceContextPrivate).authValue())
				in.includeAuthValue = !bytes.Equal(bindName, scData.BoundEntity)
			}
		case SessionTypePolicy:
			in.includeAuthValue = scData.PolicyHMACType == policyHMACTypeAuth
		}
	}

	return append(params, in), nil
}

func (t *TPMContext) validateAndAppendAuthSessionParam(params []*sessionParam, in ResourceContextWithSession) ([]*sessionParam, error) {
	var sc *sessionContext
	if in.Session != nil {
		sc = in.Session.(*sessionContext)
	}
	s := &sessionParam{isAuth: true, associatedContext: in.Context, session: sc}
	return t.validateAndAppendSessionParam(params, s, true)
}

func (t *TPMContext) validateAndAppendExtraSessionParams(params []*sessionParam, in []SessionContext) ([]*sessionParam, error) {
	addedOne := false
	for _, s := range in {
		if s == nil {
			if !addedOne {
				continue
			}
			return nil, errors.New("nil session parameter")
		}
		addedOne = true
		var err error
		params, err = t.validateAndAppendSessionParam(params, &sessionParam{session: s.(*sessionContext)}, false)
		if err != nil {
			return nil, err
		}
	}

	return params, nil
}
