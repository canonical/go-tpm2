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

func trimAuthValue(value []byte) []byte {
	return bytes.TrimRight(value, "\x00")
}

type policyHMACType uint8

const (
	policyHMACTypeNoAuth policyHMACType = iota
	policyHMACTypeAuth
	policyHMACTypePassword

	policyHMACTypeMax = policyHMACTypePassword
)

type sessionParam struct {
	Session            SessionContext  // The session instance used for this session parameter
	AssociatedResource ResourceContext // The resource associated with an authorization
	IncludeAuthValue   bool            // Whether the authorization value of associatedResource is included in the HMAC key

	NonceCaller  Nonce
	DecryptNonce Nonce
	EncryptNonce Nonce
}

func newExtraSessionParam(session SessionContext) (*sessionParam, error) {
	if !session.Available() {
		return nil, errors.New("saved or flushed session")
	}
	if session.Handle().Type() != HandleTypeHMACSession {
		return nil, errors.New("invalid session type")
	}

	return &sessionParam{Session: session}, nil
}

func newSessionParamForAuth(session SessionContext, resource ResourceContext) (*sessionParam, error) {
	if !session.Available() {
		return nil, errors.New("invalid context for session: saved or flushed session")
	}

	s := &sessionParam{
		Session:            session,
		AssociatedResource: resource}

	switch {
	case s.Session.Handle() == HandlePW:
		// Passphrase session
	case s.Session.Handle().Type() == HandleTypePolicySession:
		// A policy session. Include the auth value of the associated context
		// if the session includes a TPM2_PolicyAuthValue assertion.
		s.IncludeAuthValue = s.Session.NeedsAuthValue()
	case s.Session.IsBound():
		// A bound HMAC session. Include the auth value of the associated
		// context only if it is not the bind entity.
		bindName := computeBindName(s.AssociatedResource.Name(), trimAuthValue(s.AssociatedResource.AuthValue()))
		s.IncludeAuthValue = !bytes.Equal(bindName, s.Session.BoundEntity())
	default:
		// A non-bound HMAC session. Include the auth value of the associated
		// context in the HMAC key
		s.IncludeAuthValue = true
	}

	return s, nil
}

func (s *sessionParam) IsAuth() bool {
	return s.AssociatedResource != nil
}

func (s *sessionParam) IsPassword() bool {
	return s.Session.Handle() == HandlePW || (s.Session.Handle().Type() == HandleTypePolicySession && s.Session.NeedsPassword())
}

func (s *sessionParam) ComputeSessionHMACKey() []byte {
	var key []byte
	key = append(key, s.Session.SessionKey()...)
	if s.IncludeAuthValue {
		key = append(key, trimAuthValue(s.AssociatedResource.AuthValue())...)
	}
	return key
}

func (s *sessionParam) computeHMAC(pHash []byte, nonceNewer, nonceOlder, nonceDecrypt, nonceEncrypt Nonce, attrs SessionAttributes) ([]byte, bool) {
	key := s.ComputeSessionHMACKey()
	h := hmac.New(func() hash.Hash { return s.Session.HashAlg().NewHash() }, key)

	h.Write(pHash)
	h.Write(nonceNewer)
	h.Write(nonceOlder)
	h.Write(nonceDecrypt)
	h.Write(nonceEncrypt)
	h.Write([]byte{uint8(attrs)})

	return h.Sum(nil), len(key) > 0
}

func (s *sessionParam) ComputeCommandHMAC(commandCode CommandCode, commandHandles []Name, cpBytes []byte) []byte {
	cpHash := cryptComputeCpHash(s.Session.HashAlg(), commandCode, commandHandles, cpBytes)
	h, _ := s.computeHMAC(cpHash, s.NonceCaller, s.Session.NonceTPM(), s.DecryptNonce, s.EncryptNonce, s.Session.Attrs())
	return h
}

func (s *sessionParam) ComputeResponseHMAC(resp AuthResponse, commandCode CommandCode, rpBytes []byte) ([]byte, bool) {
	rpHash := cryptComputeRpHash(s.Session.HashAlg(), ResponseSuccess, commandCode, rpBytes)
	return s.computeHMAC(rpHash, s.Session.NonceTPM(), s.NonceCaller, nil, nil, resp.SessionAttributes)
}

func (s *sessionParam) BuildCommandAuth(commandCode CommandCode, commandHandles []Name, cpBytes []byte) *AuthCommand {
	var hmac []byte
	if s.IsPassword() {
		hmac = s.AssociatedResource.AuthValue()
	} else {
		hmac = s.ComputeCommandHMAC(commandCode, commandHandles, cpBytes)
	}

	return &AuthCommand{
		SessionHandle:     s.Session.Handle(),
		Nonce:             s.NonceCaller,
		SessionAttributes: s.Session.Attrs(),
		HMAC:              hmac}
}

func (s *sessionParam) ProcessResponseAuth(resp AuthResponse, commandCode CommandCode, rpBytes []byte) error {
	s.Session.Update(resp.Nonce, resp.SessionAttributes&AttrAudit > 0, resp.SessionAttributes&AttrAuditExclusive > 0)

	if s.IsPassword() {
		if len(resp.HMAC) != 0 {
			return errors.New("unexpected HMAC")
		}
		return nil
	}

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
	CommandCode CommandCode

	Sessions            []*sessionParam
	EncryptSessionIndex int
	DecryptSessionIndex int
}

func newSessionParams() *sessionParams {
	return &sessionParams{
		EncryptSessionIndex: -1,
		DecryptSessionIndex: -1}
}

func (p *sessionParams) append(s *sessionParam) error {
	if len(p.Sessions) >= 3 {
		return errors.New("too many session parameters")
	}

	if p.EncryptSessionIndex == -1 && s.Session.Attrs()&AttrResponseEncrypt > 0 {
		p.EncryptSessionIndex = len(p.Sessions)
	}
	if p.DecryptSessionIndex == -1 && s.Session.Attrs()&AttrCommandEncrypt > 0 {
		p.DecryptSessionIndex = len(p.Sessions)
	}

	p.Sessions = append(p.Sessions, s)
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
	for _, s := range p.Sessions {
		if s.Session.HashAlg() == HashAlgorithmNull {
			continue
		}
		s.NonceCaller = make(Nonce, s.Session.HashAlg().Size())
		if err := cryptComputeNonce(s.NonceCaller); err != nil {
			return fmt.Errorf("cannot compute new caller nonce: %v", err)
		}
	}
	return nil
}

func (p *sessionParams) BuildCommandAuthArea(commandCode CommandCode, commandHandles []Name, cpBytes []byte) ([]AuthCommand, error) {
	p.CommandCode = commandCode

	if err := p.ComputeCallerNonces(); err != nil {
		return nil, fmt.Errorf("cannot compute caller nonces: %v", err)
	}

	if err := p.EncryptCommandParameter(cpBytes); err != nil {
		return nil, fmt.Errorf("cannot encrypt first command parameter: %v", err)
	}

	p.ComputeEncryptNonce()

	var area []AuthCommand
	for _, s := range p.Sessions {
		a := s.BuildCommandAuth(p.CommandCode, commandHandles, cpBytes)
		area = append(area, *a)
	}

	return area, nil
}

func (p *sessionParams) InvalidateSessionContexts(authResponses []AuthResponse) {
	for i, resp := range authResponses {
		session := p.Sessions[i].Session
		if resp.SessionAttributes&AttrContinueSession != 0 {
			continue
		}
		session.Dispose()
	}
}

func (p *sessionParams) ProcessResponseAuthArea(authResponses []AuthResponse, rpBytes []byte) error {
	defer p.InvalidateSessionContexts(authResponses)

	if len(authResponses) != len(p.Sessions) {
		return fmt.Errorf("unexpected number of response auths (got %d, expected %d)",
			len(authResponses), len(p.Sessions))
	}

	for i, resp := range authResponses {
		if err := p.Sessions[i].ProcessResponseAuth(resp, p.CommandCode, rpBytes); err != nil {
			return &InvalidAuthResponseError{i + 1, err.Error()}
		}
	}

	if err := p.DecryptResponseParameter(rpBytes); err != nil {
		return fmt.Errorf("cannot decrypt first response parameter: %v", err)
	}

	return nil
}
