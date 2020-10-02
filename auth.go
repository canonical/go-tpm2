// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
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

type authCommand struct {
	SessionHandle Handle
	Nonce         Nonce
	SessionAttrs  sessionAttrs
	HMAC          Auth
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

type authResponse struct {
	Nonce        Nonce
	SessionAttrs sessionAttrs
	HMAC         Auth
}

type sessionParam struct {
	session           *sessionContext // The session instance used for this session parameter - will be nil for a password authorization
	associatedContext ResourceContext // The resource associated with an authorization - can be nil
	includeAuthValue  bool            // Whether the authorization value of associatedContext is included in the HMAC key

	decryptNonce Nonce
	encryptNonce Nonce
}

func (s *sessionParam) isAuth() bool {
	return s.associatedContext != nil
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

func (s *sessionParam) computeHMAC(pHash []byte, nonceNewer, nonceOlder, nonceDecrypt, nonceEncrypt Nonce, attrs sessionAttrs) ([]byte, bool) {
	key := s.computeSessionHMACKey()
	h := hmac.New(func() hash.Hash { return s.session.scData().HashAlg.NewHash() }, key)

	h.Write(pHash)
	h.Write(nonceNewer)
	h.Write(nonceOlder)
	h.Write(nonceDecrypt)
	h.Write(nonceEncrypt)
	h.Write([]byte{uint8(attrs)})

	return h.Sum(nil), len(key) > 0
}

func (s *sessionParam) computeCommandHMAC(commandCode CommandCode, commandHandles []Name, cpBytes []byte) []byte {
	scData := s.session.scData()
	cpHash := cryptComputeCpHash(scData.HashAlg, commandCode, commandHandles, cpBytes)
	h, _ := s.computeHMAC(cpHash, scData.NonceCaller, scData.NonceTPM, s.decryptNonce, s.encryptNonce, s.session.tpmAttrs())
	return h
}

func (s *sessionParam) buildCommandSessionAuth(commandCode CommandCode, commandHandles []Name, cpBytes []byte) *authCommand {
	scData := s.session.scData()

	var hmac []byte

	if scData.SessionType == SessionTypePolicy && scData.PolicyHMACType == policyHMACTypePassword {
		// Policy session that contains a TPM2_PolicyPassword assertion. The HMAC is just the authorization value
		// of the resource being authorized.
		if s.isAuth() {
			hmac = s.associatedContext.(resourceContextPrivate).authValue()
		}
	} else {
		hmac = s.computeCommandHMAC(commandCode, commandHandles, cpBytes)
	}

	return &authCommand{
		SessionHandle: s.session.Handle(),
		Nonce:         scData.NonceCaller,
		SessionAttrs:  s.session.tpmAttrs(),
		HMAC:          hmac}
}

func (s *sessionParam) buildCommandPasswordAuth() *authCommand {
	return &authCommand{SessionHandle: HandlePW, SessionAttrs: attrContinueSession, HMAC: s.associatedContext.(resourceContextPrivate).authValue()}
}

func (s *sessionParam) buildCommandAuth(commandCode CommandCode, commandHandles []Name, cpBytes []byte) *authCommand {
	if s.session == nil {
		// Cleartext password session
		return s.buildCommandPasswordAuth()
	}
	// HMAC or policy session
	return s.buildCommandSessionAuth(commandCode, commandHandles, cpBytes)
}

func (s *sessionParam) computeResponseHMAC(resp authResponse, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte) ([]byte, bool) {
	scData := s.session.scData()
	rpHash := cryptComputeRpHash(scData.HashAlg, responseCode, commandCode, rpBytes)
	return s.computeHMAC(rpHash, scData.NonceTPM, scData.NonceCaller, nil, nil, resp.SessionAttrs)
}

func (s *sessionParam) processResponseAuth(resp authResponse, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte) error {
	if s.session == nil {
		return nil
	}

	scData := s.session.scData()
	scData.NonceTPM = resp.Nonce
	scData.IsAudit = resp.SessionAttrs&attrAudit > 0
	scData.IsExclusive = resp.SessionAttrs&attrAuditExclusive > 0

	if resp.SessionAttrs&attrContinueSession == 0 {
		s.session.invalidate()
	}

	if scData.SessionType == SessionTypePolicy && scData.PolicyHMACType == policyHMACTypePassword {
		if len(resp.HMAC) != 0 {
			return errors.New("non-zero length HMAC for policy session with PolicyPassword assertion")
		}
		return nil
	}

	hmac, hmacRequired := s.computeResponseHMAC(resp, responseCode, commandCode, rpBytes)
	if (hmacRequired || len(resp.HMAC) > 0) && !bytes.Equal(hmac, resp.HMAC) {
		return errors.New("incorrect HMAC")
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

type sessionParams []*sessionParam

func (sessions sessionParams) findSessionWithAttr(attr SessionAttributes) (*sessionParam, int) {
	for i, session := range sessions {
		if session.session == nil {
			continue
		}
		if session.session.attrs&attr > 0 {
			return session, i
		}
	}

	return nil, 0
}

func (sessions sessionParams) validateAndAppend(s *sessionParam) (sessionParams, error) {
	if s.session != nil {
		scData := s.session.scData()
		if scData == nil {
			return nil, errors.New("invalid context for session: incomplete session can only be used in TPMContext.FlushContext")
		}
		switch scData.SessionType {
		case SessionTypeHMAC:
			switch {
			case !s.isAuth():
				// HMAC session not used for authorization
			case !scData.IsBound:
				// A non-bound HMAC session used for authorization. Include the auth value of the associated
				// ResourceContext in the HMAC key
				s.includeAuthValue = true
			default:
				// A bound HMAC session used for authorization. Include the auth value of the associated
				// ResourceContext only if it is not the bind entity.
				bindName := computeBindName(s.associatedContext.Name(), s.associatedContext.(resourceContextPrivate).authValue())
				s.includeAuthValue = !bytes.Equal(bindName, scData.BoundEntity)
			}
		case SessionTypePolicy:
			// A policy session that includes a TPM2_PolicyAuthValue assertion. Include the auth value of the associated
			// ResourceContext.
			s.includeAuthValue = scData.PolicyHMACType == policyHMACTypeAuth
		}
	}

	return append(sessions, s), nil
}

func (sessions sessionParams) validateAndAppendAuth(in ResourceContextWithSession) (sessionParams, error) {
	var sc *sessionContext
	if in.Session != nil {
		sc = in.Session.(*sessionContext)
	}
	associatedContext := in.Context
	if associatedContext == nil {
		associatedContext = makePermanentContext(HandleNull)
	}
	s := &sessionParam{associatedContext: associatedContext, session: sc}
	return sessions.validateAndAppend(s)
}

func (sessions sessionParams) validateAndAppendExtra(in []SessionContext) (sessionParams, error) {
	for _, s := range in {
		if s == nil {
			continue
		}
		var err error
		sessions, err = sessions.validateAndAppend(&sessionParam{session: s.(*sessionContext)})
		if err != nil {
			return nil, err
		}
	}

	return sessions, nil
}

func (sessions sessionParams) computeCallerNonces() error {
	for _, s := range sessions {
		if s.session == nil {
			continue
		}

		if err := cryptComputeNonce(s.session.scData().NonceCaller); err != nil {
			return fmt.Errorf("cannot compute new caller nonce: %v", err)
		}
	}
	return nil
}

func (sessions sessionParams) buildCommandAuthArea(commandCode CommandCode, commandHandles []Name, cpBytes []byte) (commandAuthArea, error) {
	if len(sessions) > 3 {
		return nil, errors.New("too many session parameters provided")
	}

	if err := sessions.computeCallerNonces(); err != nil {
		return nil, fmt.Errorf("cannot compute caller nonces: %v", err)
	}

	if err := sessions.encryptCommandParameter(cpBytes); err != nil {
		return nil, fmt.Errorf("cannot encrypt first command parameter: %v", err)
	}

	sessions.computeEncryptNonce()

	var area commandAuthArea
	for _, s := range sessions {
		a := s.buildCommandAuth(commandCode, commandHandles, cpBytes)
		area = append(area, *a)
	}

	return area, nil
}

func (sessions sessionParams) processResponseAuthArea(authResponses []authResponse, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte) error {
	for i, resp := range authResponses {
		if err := sessions[i].processResponseAuth(resp, responseCode, commandCode, rpBytes); err != nil {
			return fmt.Errorf("encountered an error for session at index %d: %v", i, err)
		}
	}

	if err := sessions.decryptResponseParameter(rpBytes); err != nil {
		return fmt.Errorf("cannot decrypt first response parameter: %v", err)
	}

	return nil
}
