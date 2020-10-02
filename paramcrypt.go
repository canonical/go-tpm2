// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"

	"github.com/canonical/go-tpm2/internal"
	"github.com/canonical/go-tpm2/mu"
)

func isParamEncryptable(param interface{}) bool {
	return mu.DetermineTPMKind(param) == mu.TPMKindSized
}

func (s *sessionParam) computeSessionValue() []byte {
	var key []byte
	key = append(key, s.session.scData().SessionKey...)
	if s.associatedContext != nil {
		key = append(key, s.associatedContext.(resourceContextPrivate).authValue()...)
	}
	return key
}

func (sessions sessionParams) findDecryptSession() (*sessionParam, int) {
	return sessions.findSessionWithAttr(AttrCommandEncrypt)
}

func (sessions sessionParams) findEncryptSession() (*sessionParam, int) {
	return sessions.findSessionWithAttr(AttrResponseEncrypt)
}

func (sessions sessionParams) hasDecryptSession() bool {
	s, _ := sessions.findDecryptSession()
	return s != nil
}

func (sessions sessionParams) computeEncryptNonce() {
	session, i := sessions.findEncryptSession()
	if session == nil || i == 0 || !sessions[0].isAuth() {
		return
	}
	decSession, di := sessions.findDecryptSession()
	if decSession != nil && di == i {
		return
	}

	sessions[0].encryptNonce = session.session.scData().NonceTPM
}

func (sessions sessionParams) encryptCommandParameter(cpBytes []byte) error {
	session, index := sessions.findDecryptSession()
	if session == nil {
		return nil
	}

	scData := session.session.scData()
	if !scData.HashAlg.Supported() {
		return fmt.Errorf("invalid digest algorithm: %v", scData.HashAlg)
	}

	sessionValue := session.computeSessionValue()

	size := binary.BigEndian.Uint16(cpBytes)
	data := cpBytes[2 : size+2]

	symmetric := scData.Symmetric

	switch symmetric.Algorithm {
	case SymAlgorithmAES:
		k := internal.KDFa(scData.HashAlg.GetHash(), sessionValue, []byte("CFB"), scData.NonceCaller, scData.NonceTPM,
			int(symmetric.KeyBits.Sym())+(aes.BlockSize*8))
		offset := (symmetric.KeyBits.Sym() + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := internal.EncryptSymmetricAES(symKey, internal.SymmetricMode(symmetric.Mode.Sym()), data, iv); err != nil {
			return fmt.Errorf("AES encryption failed: %v", err)
		}
	case SymAlgorithmXOR:
		internal.XORObfuscation(scData.HashAlg.GetHash(), sessionValue, scData.NonceCaller, scData.NonceTPM, data)
	default:
		return fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	if index > 0 && sessions[0].isAuth() {
		sessions[0].decryptNonce = scData.NonceTPM
	}

	return nil
}

func (sessions sessionParams) decryptResponseParameter(rpBytes []byte) error {
	session, _ := sessions.findEncryptSession()
	if session == nil {
		return nil
	}

	scData := session.session.scData()
	if !scData.HashAlg.Supported() {
		return fmt.Errorf("invalid digest algorithm: %v", scData.HashAlg)
	}

	sessionValue := session.computeSessionValue()

	size := binary.BigEndian.Uint16(rpBytes)
	data := rpBytes[2 : size+2]

	symmetric := scData.Symmetric

	switch symmetric.Algorithm {
	case SymAlgorithmAES:
		k := internal.KDFa(scData.HashAlg.GetHash(), sessionValue, []byte("CFB"), scData.NonceTPM, scData.NonceCaller,
			int(symmetric.KeyBits.Sym())+(aes.BlockSize*8))
		offset := (symmetric.KeyBits.Sym() + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := internal.DecryptSymmetricAES(symKey, internal.SymmetricMode(symmetric.Mode.Sym()), data, iv); err != nil {
			return fmt.Errorf("AES encryption failed: %v", err)
		}
	case SymAlgorithmXOR:
		internal.XORObfuscation(scData.HashAlg.GetHash(), sessionValue, scData.NonceTPM, scData.NonceCaller, data)
	default:
		return fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	return nil
}
