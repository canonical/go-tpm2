// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
)

type policyHMACType uint8

const (
	policyHMACTypeNoAuth policyHMACType = iota
	policyHMACTypeAuth
	policyHMACTypePassword

	policyHMACTypeMax = policyHMACTypePassword
)

type sessionParam struct {
	session            sessionContextInternal  // The session instance used for this session parameter
	associatedResource resourceContextInternal // The resource associated with an authorization
	includeAuthValue   bool                    // Whether the authorization value of associatedResource is included in the HMAC key

	decryptNonce Nonce
	encryptNonce Nonce
}

func newExtraSessionParam(session SessionContext) (*sessionParam, error) {
	s := &sessionParam{session: session.(sessionContextInternal)}

	data := s.session.Data()
	if data == nil {
		return nil, errors.New("incomplete session can only be used in TPMContext.FlushContext")
	}
	if data.SessionType != SessionTypeHMAC {
		return nil, errors.New("invalid session type")
	}

	return s, nil
}

func newSessionParamForAuth(session SessionContext, resource ResourceContext) (*sessionParam, error) {
	s := &sessionParam{
		session:            session.(sessionContextInternal),
		associatedResource: resource.(resourceContextInternal)}

	data := s.session.Data()
	if data == nil {
		return nil, errors.New("invalid context for session: incomplete session can only be used in TPMContext.FlushContext")
	}

	switch {
	case s.session.Handle() == HandlePW:
		// Passphrase session
	case data.SessionType == SessionTypeHMAC && !data.IsBound:
		// A non-bound HMAC session. Include the auth value of the associated
		// context in the HMAC key
		s.includeAuthValue = true
	case data.SessionType == SessionTypeHMAC:
		// A bound HMAC session. Include the auth value of the associated
		// context only if it is not the bind entity.
		bindName := computeBindName(s.associatedResource.Name(), s.associatedResource.GetAuthValue())
		s.includeAuthValue = !bytes.Equal(bindName, data.BoundEntity)
	case data.SessionType == SessionTypePolicy:
		// A policy session. Include the auth value of the associated context
		// if the session includes a TPM2_PolicyAuthValue assertion.
		s.includeAuthValue = data.PolicyHMACType == policyHMACTypeAuth
	default:
		return nil, errors.New("invalid context for session: invalid session type")
	}

	return s, nil
}

func (s *sessionParam) IsAuth() bool {
	return s.associatedResource != nil
}

func (s *sessionParam) IsPassword() bool {
	data := s.session.Data()
	return s.session.Handle() == HandlePW || (data.SessionType == SessionTypePolicy && data.PolicyHMACType == policyHMACTypePassword)
}

func (s *sessionParam) ComputeSessionHMACKey() []byte {
	var key []byte
	key = append(key, s.session.Data().SessionKey...)
	if s.includeAuthValue {
		key = append(key, s.associatedResource.GetAuthValue()...)
	}
	return key
}

func (s *sessionParam) computeHMAC(pHash []byte, nonceNewer, nonceOlder, nonceDecrypt, nonceEncrypt Nonce, attrs SessionAttributes) ([]byte, bool) {
	key := s.ComputeSessionHMACKey()
	h := hmac.New(func() hash.Hash { return s.session.Data().HashAlg.NewHash() }, key)

	h.Write(pHash)
	h.Write(nonceNewer)
	h.Write(nonceOlder)
	h.Write(nonceDecrypt)
	h.Write(nonceEncrypt)
	h.Write([]byte{uint8(attrs)})

	return h.Sum(nil), len(key) > 0
}

func (s *sessionParam) ComputeCommandHMAC(commandCode CommandCode, commandHandles []Name, cpBytes []byte) []byte {
	data := s.session.Data()
	cpHash := cryptComputeCpHash(data.HashAlg, commandCode, commandHandles, cpBytes)
	h, _ := s.computeHMAC(cpHash, data.NonceCaller, data.NonceTPM, s.decryptNonce, s.encryptNonce, s.session.Attrs().canonicalize())
	return h
}

func (s *sessionParam) ComputeResponseHMAC(resp AuthResponse, commandCode CommandCode, rpBytes []byte) ([]byte, bool) {
	data := s.session.Data()
	rpHash := cryptComputeRpHash(data.HashAlg, ResponseSuccess, commandCode, rpBytes)
	return s.computeHMAC(rpHash, data.NonceTPM, data.NonceCaller, nil, nil, resp.SessionAttributes)
}

func (s *sessionParam) BuildCommandAuth(commandCode CommandCode, commandHandles []Name, cpBytes []byte) *AuthCommand {
	data := s.session.Data()

	var hmac []byte
	if s.IsPassword() {
		hmac = s.associatedResource.GetAuthValue()
	} else {
		hmac = s.ComputeCommandHMAC(commandCode, commandHandles, cpBytes)
	}

	return &AuthCommand{
		SessionHandle:     s.session.Handle(),
		Nonce:             data.NonceCaller,
		SessionAttributes: s.session.Attrs().canonicalize(),
		HMAC:              hmac}
}

func (s *sessionParam) ProcessResponseAuth(resp AuthResponse, commandCode CommandCode, rpBytes []byte) error {
	if s.IsPassword() {
		if len(resp.HMAC) != 0 {
			return errors.New("unexpected HMAC")
		}
		return nil
	}

	data := s.session.Data()
	data.NonceTPM = resp.Nonce
	data.IsAudit = resp.SessionAttributes&AttrAudit > 0
	data.IsExclusive = resp.SessionAttributes&AttrAuditExclusive > 0

	hmac, hmacRequired := s.ComputeResponseHMAC(resp, commandCode, rpBytes)
	if (hmacRequired || len(resp.HMAC) > 0) && !bytes.Equal(hmac, resp.HMAC) {
		return fmt.Errorf("incorrect HMAC (expected: %x, got: %x)", hmac, resp.HMAC)
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

type sessionParams struct {
	commandCode CommandCode

	sessions            []*sessionParam
	encryptSessionIndex int
	decryptSessionIndex int
}

func newSessionParams(commandCode CommandCode) *sessionParams {
	return &sessionParams{
		commandCode:         commandCode,
		encryptSessionIndex: -1,
		decryptSessionIndex: -1}
}

func (p *sessionParams) append(s *sessionParam) error {
	if len(p.sessions) >= 3 {
		return errors.New("too many session parameters")
	}

	if p.encryptSessionIndex == -1 && s.session.Attrs()&AttrResponseEncrypt > 0 {
		p.encryptSessionIndex = len(p.sessions)
	}
	if p.decryptSessionIndex == -1 && s.session.Attrs()&AttrCommandEncrypt > 0 {
		p.decryptSessionIndex = len(p.sessions)
	}

	p.sessions = append(p.sessions, s)
	return nil
}

func (p *sessionParams) AppendSessionForResource(session SessionContext, resource ResourceContext) error {
	s, err := newSessionParamForAuth(session, resource)
	if err != nil {
		return err
	}

	return p.append(s)
}

func (p *sessionParams) AppendExtraSessions(sessions ...SessionContext) error {
	for i, session := range sessions {
		if session == nil {
			continue
		}

		s, err := newExtraSessionParam(session)
		if err != nil {
			return fmt.Errorf("cannot handle session context at index %d: %v", i, err)
		}

		if err := p.append(s); err != nil {
			return err
		}
	}

	return nil
}

func (p *sessionParams) ComputeCallerNonces() error {
	for _, s := range p.sessions {
		if err := cryptComputeNonce(s.session.Data().NonceCaller); err != nil {
			return fmt.Errorf("cannot compute new caller nonce: %v", err)
		}
	}
	return nil
}

func (p *sessionParams) BuildCommandAuthArea(commandHandles []Name, cpBytes []byte) ([]AuthCommand, error) {
	if err := p.ComputeCallerNonces(); err != nil {
		return nil, fmt.Errorf("cannot compute caller nonces: %v", err)
	}

	if err := p.EncryptCommandParameter(cpBytes); err != nil {
		return nil, fmt.Errorf("cannot encrypt first command parameter: %v", err)
	}

	p.ComputeEncryptNonce()

	var area []AuthCommand
	for _, s := range p.sessions {
		a := s.BuildCommandAuth(p.commandCode, commandHandles, cpBytes)
		area = append(area, *a)
	}

	return area, nil
}

func (p *sessionParams) InvalidateSessionContexts(authResponses []AuthResponse) {
	for i, resp := range authResponses {
		session := p.sessions[i].session
		if resp.SessionAttributes&AttrContinueSession != 0 {
			continue
		}
		session.Invalidate()
	}
}

func (p *sessionParams) ProcessResponseAuthArea(authResponses []AuthResponse, rpBytes []byte) error {
	defer p.InvalidateSessionContexts(authResponses)

	if len(authResponses) != len(p.sessions) {
		return fmt.Errorf("unexpected number of response auths (got %d, expected %d)",
			len(authResponses), len(p.sessions))
	}

	for i, resp := range authResponses {
		if err := p.sessions[i].ProcessResponseAuth(resp, p.commandCode, rpBytes); err != nil {
			return fmt.Errorf("encountered an error for session at index %d: %v", i, err)
		}
	}

	if err := p.DecryptResponseParameter(rpBytes); err != nil {
		return fmt.Errorf("cannot decrypt first response parameter: %v", err)
	}

	return nil
}
