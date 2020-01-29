// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"reflect"
)

func findSessionWithAttr(attr SessionAttributes, sessions []*sessionParam) (*sessionParam, int) {
	for i, session := range sessions {
		if session.session == nil {
			continue
		}
		if session.session.Attrs&attr > 0 {
			return session, i
		}
	}

	return nil, 0
}

func findDecryptSession(sessions []*sessionParam) (*sessionParam, int) {
	return findSessionWithAttr(AttrCommandEncrypt, sessions)
}

func findEncryptSession(sessions []*sessionParam) (*sessionParam, int) {
	return findSessionWithAttr(AttrResponseEncrypt, sessions)
}

func hasDecryptSession(sessions []*sessionParam) bool {
	s, _ := findDecryptSession(sessions)
	return s != nil
}

func isSizedStructParam(v reflect.Value) bool {
	if v.Kind() != reflect.Struct {
		return false
	}
	if v.Type().NumField() != 1 {
		return false
	}
	f := v.Type().Field(0)
	if !parseFieldOptions(f.Tag.Get("tpm2")).sized {
		return false
	}
	if f.Type.Kind() == reflect.Struct {
		return true
	}
	if f.Type.Kind() == reflect.Ptr && f.Type.Elem().Kind() == reflect.Struct {
		return true
	}
	if f.Type.Kind() == reflect.Interface && v.Field(0).Elem().Kind() == reflect.Ptr &&
		v.Field(0).Elem().Elem().Kind() == reflect.Struct {
		return true
	}
	return false
}

func isSizedBuffer(t reflect.Type) bool {
	return isByteSlice(t) && t != rawBytesType
}

func isParamEncryptable(param interface{}) bool {
	v := reflect.ValueOf(param)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	return isSizedStructParam(v) || isSizedBuffer(v.Type())
}

func (s *sessionParam) computeSessionValue() []byte {
	var key []byte
	key = append(key, s.session.Context.(*sessionContext).scData().SessionKey...)
	if s.associatedContext != nil {
		key = append(key, s.associatedContext.(resourceContextPrivate).authValue()...)
	}
	return key
}

func computeEncryptNonce(sessions []*sessionParam) Nonce {
	session, i := findEncryptSession(sessions)
	if session == nil || i == 0 || !sessions[0].isAuth {
		return nil
	}
	decSession, di := findDecryptSession(sessions)
	if decSession != nil && di == i {
		return nil
	}

	return session.session.Context.(*sessionContext).scData().NonceTPM
}

func encryptCommandParameter(sessions []*sessionParam, cpBytes []byte) (Nonce, error) {
	session, index := findDecryptSession(sessions)
	if session == nil {
		return nil, nil
	}

	scData := session.session.Context.(*sessionContext).scData()
	sessionValue := session.computeSessionValue()

	size := binary.BigEndian.Uint16(cpBytes)
	data := cpBytes[2 : size+2]

	symmetric := scData.Symmetric

	switch symmetric.Algorithm {
	case SymAlgorithmAES:
		if symmetric.Mode.Sym() != SymModeCFB {
			return nil, fmt.Errorf("invalid symmetric mode %v", symmetric.Mode.Sym())
		}
		if !scData.HashAlg.Supported() {
			return nil, fmt.Errorf("invalid digest algorithm: %v", scData.HashAlg)
		}
		k := cryptKDFa(scData.HashAlg, sessionValue, []byte("CFB"), scData.NonceCaller, scData.NonceTPM,
			int(symmetric.KeyBits.Sym())+(aes.BlockSize*8), nil, false)
		offset := (symmetric.KeyBits.Sym() + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := cryptEncryptSymmetricAES(symKey, symmetric.Mode.Sym(), data, iv); err != nil {
			return nil, fmt.Errorf("AES encryption failed: %v", err)
		}
	case SymAlgorithmXOR:
		if err := cryptXORObfuscation(scData.HashAlg, sessionValue, scData.NonceCaller, scData.NonceTPM, data); err != nil {
			return nil, fmt.Errorf("XOR parameter obfuscation failed: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	if index == 0 || !sessions[0].isAuth {
		return nil, nil
	}

	return scData.NonceTPM, nil
}

func decryptResponseParameter(sessions []*sessionParam, rpBytes []byte) error {
	session, _ := findEncryptSession(sessions)
	if session == nil {
		return nil
	}

	scData := session.session.Context.(*sessionContext).scData()
	sessionValue := session.computeSessionValue()

	size := binary.BigEndian.Uint16(rpBytes)
	data := rpBytes[2 : size+2]

	symmetric := scData.Symmetric

	switch symmetric.Algorithm {
	case SymAlgorithmAES:
		if symmetric.Mode.Sym() != SymModeCFB {
			return fmt.Errorf("invalid symmetric mode %v", symmetric.Mode.Sym())
		}
		if !scData.HashAlg.Supported() {
			return fmt.Errorf("invalid digest algorithm: %v", scData.HashAlg)
		}
		k := cryptKDFa(scData.HashAlg, sessionValue, []byte("CFB"), scData.NonceTPM, scData.NonceCaller,
			int(symmetric.KeyBits.Sym())+(aes.BlockSize*8), nil, false)
		offset := (symmetric.KeyBits.Sym() + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := cryptDecryptSymmetricAES(symKey, symmetric.Mode.Sym(), data, iv); err != nil {
			return fmt.Errorf("AES encryption failed: %v", err)
		}
	case SymAlgorithmXOR:
		if err := cryptXORObfuscation(scData.HashAlg, sessionValue, scData.NonceTPM, scData.NonceCaller, data); err != nil {
			return fmt.Errorf("XOR parameter obfuscation failed: %v", err)
		}
	default:
		return fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	return nil
}
