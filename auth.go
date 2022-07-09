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
	session           sessionContextInternal  // The session instance used for this session parameter
	associatedContext resourceContextInternal // The resource associated with an authorization
	includeAuthValue  bool                    // Whether the authorization value of associatedContext is included in the HMAC key

	decryptNonce Nonce
	encryptNonce Nonce
}

func (s *sessionParam) IsAuth() bool {
	return s.associatedContext != nil
}

func (s *sessionParam) IsPassword() bool {
	data := s.session.Data()
	return s.IsAuth() && (s.session.Handle() == HandlePW || (data.SessionType == SessionTypePolicy && data.PolicyHMACType == policyHMACTypePassword))
}

func (s *sessionParam) ComputeSessionHMACKey() []byte {
	var key []byte
	key = append(key, s.session.Data().SessionKey...)
	if s.includeAuthValue {
		key = append(key, s.associatedContext.GetAuthValue()...)
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

func (s *sessionParam) computeCommandHMAC(commandCode CommandCode, commandHandles []Name, cpBytes []byte) []byte {
	data := s.session.Data()
	cpHash := cryptComputeCpHash(data.HashAlg, commandCode, commandHandles, cpBytes)
	h, _ := s.computeHMAC(cpHash, data.NonceCaller, data.NonceTPM, s.decryptNonce, s.encryptNonce, s.session.Attrs().canonicalize())
	return h
}

func (s *sessionParam) computeResponseHMAC(resp AuthResponse, commandCode CommandCode, rpBytes []byte) ([]byte, bool) {
	data := s.session.Data()
	rpHash := cryptComputeRpHash(data.HashAlg, ResponseSuccess, commandCode, rpBytes)
	return s.computeHMAC(rpHash, data.NonceTPM, data.NonceCaller, nil, nil, resp.SessionAttributes)
}

func (s *sessionParam) buildCommandAuth(commandCode CommandCode, commandHandles []Name, cpBytes []byte) *AuthCommand {
	data := s.session.Data()

	var hmac []byte
	if s.IsPassword() {
		hmac = s.associatedContext.GetAuthValue()
	} else {
		hmac = s.computeCommandHMAC(commandCode, commandHandles, cpBytes)
	}

	return &AuthCommand{
		SessionHandle:     s.session.Handle(),
		Nonce:             data.NonceCaller,
		SessionAttributes: s.session.Attrs().canonicalize(),
		HMAC:              hmac}
}

func (s *sessionParam) processResponseAuth(resp AuthResponse, commandCode CommandCode, rpBytes []byte) error {
	if s.IsPassword() {
		if len(resp.HMAC) != 0 {
			return errors.New("non-zero length HMAC for policy session with PolicyPassword assertion")
		}
		return nil
	}

	data := s.session.Data()
	data.NonceTPM = resp.Nonce
	data.IsAudit = resp.SessionAttributes&AttrAudit > 0
	data.IsExclusive = resp.SessionAttributes&AttrAuditExclusive > 0

	hmac, hmacRequired := s.computeResponseHMAC(resp, commandCode, rpBytes)
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

type sessionParams struct {
	commandCode CommandCode
	sessions    []*sessionParam
}

func (p *sessionParams) findSessionWithAttr(attr SessionAttributes) (*sessionParam, int) {
	for i, session := range p.sessions {
		if session.session.Attrs().canonicalize()&attr > 0 {
			return session, i
		}
	}

	return nil, 0
}

func (p *sessionParams) append(s *sessionParam) error {
	if len(p.sessions) >= 3 {
		return errors.New("too many session parameters")
	}

	p.sessions = append(p.sessions, s)
	return nil
}

func (p *sessionParams) appendSessionForResource(session SessionContext, resource ResourceContext) error {
	s := &sessionParam{
		session:           session.(sessionContextInternal),
		associatedContext: resource.(resourceContextInternal)}

	data := s.session.Data()
	if data == nil {
		return errors.New("invalid context for session: incomplete session can only be used in TPMContext.FlushContext")
	}

	switch {
	case s.session.Handle() == HandlePW:
	case data.SessionType == SessionTypeHMAC:
		if !data.IsBound {
			// A non-bound HMAC session. Include the auth value of the associated
			// context in the HMAC key
			s.includeAuthValue = true
		} else {
			// A bound HMAC session. Include the auth value of the associated
			// context only if it is not the bind entity.
			bindName := computeBindName(s.associatedContext.Name(), s.associatedContext.GetAuthValue())
			s.includeAuthValue = !bytes.Equal(bindName, data.BoundEntity)
		}
	case data.SessionType == SessionTypePolicy:
		// Include the auth value of the associated context if the session
		// includes a TPM2_PolicyAuthValue assertion.
		s.includeAuthValue = data.PolicyHMACType == policyHMACTypeAuth
	}

	return p.append(s)
}

func (p *sessionParams) appendExtraSessions(sessions ...SessionContext) error {
	for _, session := range sessions {
		if session == nil {
			continue
		}
		if err := p.append(&sessionParam{session: session.(sessionContextInternal)}); err != nil {
			return err
		}
	}

	return nil
}

func (p *sessionParams) computeCallerNonces() error {
	for _, s := range p.sessions {
		if err := cryptComputeNonce(s.session.Data().NonceCaller); err != nil {
			return fmt.Errorf("cannot compute new caller nonce: %v", err)
		}
	}
	return nil
}

func (p *sessionParams) buildCommandAuthArea(commandCode CommandCode, commandHandles []Name, cpBytes []byte) ([]AuthCommand, error) {
	if err := p.computeCallerNonces(); err != nil {
		return nil, fmt.Errorf("cannot compute caller nonces: %v", err)
	}

	if err := p.encryptCommandParameter(cpBytes); err != nil {
		return nil, fmt.Errorf("cannot encrypt first command parameter: %v", err)
	}

	p.computeEncryptNonce()
	p.commandCode = commandCode

	var area []AuthCommand
	for _, s := range p.sessions {
		a := s.buildCommandAuth(commandCode, commandHandles, cpBytes)
		area = append(area, *a)
	}

	return area, nil
}

func (p *sessionParams) invalidateSessionContexts(authResponses []AuthResponse) {
	for i, resp := range authResponses {
		session := p.sessions[i].session
		if resp.SessionAttributes&AttrContinueSession != 0 {
			continue
		}
		session.Invalidate()
	}
}

func (p *sessionParams) processResponseAuthArea(authResponses []AuthResponse, rpBytes []byte) error {
	defer p.invalidateSessionContexts(authResponses)

	for i, resp := range authResponses {
		if err := p.sessions[i].processResponseAuth(resp, p.commandCode, rpBytes); err != nil {
			return fmt.Errorf("encountered an error for session at index %d: %v", i, err)
		}
	}

	if err := p.decryptResponseParameter(rpBytes); err != nil {
		return fmt.Errorf("cannot decrypt first response parameter: %v", err)
	}

	return nil
}
