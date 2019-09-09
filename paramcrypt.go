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

func findSessionWithAttr(attr SessionAttributes, sessions []*sessionParam) (*Session, bool, int) {
	for i, session := range sessions {
		if session.session == nil {
			continue
		}
		if session.session.Attrs&attr > 0 {
			isAuth := session.associatedContext != nil
			return session.session, isAuth, i
		}
	}

	return nil, false, 0
}

func findDecryptSession(sessions []*sessionParam) (*Session, bool, int) {
	return findSessionWithAttr(AttrCommandEncrypt, sessions)
}

func findEncryptSession(sessions []*sessionParam) (*Session, bool, int) {
	return findSessionWithAttr(AttrResponseEncrypt, sessions)
}

func hasDecryptSession(sessions []*sessionParam) bool {
	s, _, _ := findDecryptSession(sessions)
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

func isParamEncryptable(param interface{}) bool {
	v := reflect.ValueOf(param)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	return isSizedStructParam(v) || isSizedBuffer(v.Type())
}

func computeSessionValue(context *sessionContext, authValue []byte, isAuth bool) []byte {
	var key []byte
	key = append(key, context.sessionKey...)
	if isAuth {
		key = append(key, authValue...)
	}
	return key
}

func computeEncryptNonce(sessions []*sessionParam) Nonce {
	session, _, i := findEncryptSession(sessions)
	if session == nil || i == 0 {
		return nil
	}

	return session.Context.(*sessionContext).nonceTPM
}

func encryptCommandParameter(sessions []*sessionParam, cpBytes []byte) (Nonce, error) {
	session, isAuth, index := findDecryptSession(sessions)
	if session == nil {
		return nil, nil
	}

	context := session.Context.(*sessionContext)
	sessionValue := computeSessionValue(context, session.AuthValue, isAuth)

	size := binary.BigEndian.Uint16(cpBytes)
	data := cpBytes[2 : size+2]

	symmetric := context.symmetric

	switch symmetric.Algorithm {
	case AlgorithmAES:
		if symmetric.Mode.Sym != AlgorithmCFB {
			return nil, fmt.Errorf("invalid symmetric mode %v", symmetric.Mode.Sym)
		}
		if !cryptIsKnownDigest(context.hashAlg) {
			return nil, fmt.Errorf("invalid digest algorithm: %v", context.hashAlg)
		}
		k := cryptKDFa(context.hashAlg, sessionValue, []byte("CFB"), context.nonceCaller,
			context.nonceTPM, uint(symmetric.KeyBits.Sym())+(aes.BlockSize*8), nil, false)
		offset := (symmetric.KeyBits.Sym() + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := cryptEncryptSymmetricAES(symKey, symmetric.Mode.Sym, data, iv); err != nil {
			return nil, fmt.Errorf("AES encryption failed: %v", err)
		}
	case AlgorithmXOR:
		if err := cryptXORObfuscation(context.hashAlg, sessionValue, context.nonceCaller,
			context.nonceTPM, data); err != nil {
			return nil, fmt.Errorf("XOR parameter obfuscation failed: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	if index == 0 {
		return nil, nil
	}

	return context.nonceTPM, nil
}

func decryptResponseParameter(sessions []*sessionParam, rpBytes []byte) error {
	session, isAuth, _ := findEncryptSession(sessions)
	if session == nil {
		return nil
	}

	context := session.Context.(*sessionContext)
	sessionValue := computeSessionValue(context, session.AuthValue, isAuth)

	size := binary.BigEndian.Uint16(rpBytes)
	data := rpBytes[2 : size+2]

	symmetric := context.symmetric

	switch symmetric.Algorithm {
	case AlgorithmAES:
		if symmetric.Mode.Sym != AlgorithmCFB {
			return fmt.Errorf("invalid symmetric mode %v", symmetric.Mode.Sym)
		}
		if !cryptIsKnownDigest(context.hashAlg) {
			return fmt.Errorf("invalid digest algorithm: %v", context.hashAlg)
		}
		k := cryptKDFa(context.hashAlg, sessionValue, []byte("CFB"), context.nonceTPM,
			context.nonceCaller, uint(symmetric.KeyBits.Sym())+(aes.BlockSize*8), nil, false)
		offset := (symmetric.KeyBits.Sym() + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := cryptDecryptSymmetricAES(symKey, symmetric.Mode.Sym, data, iv); err != nil {
			return fmt.Errorf("AES encryption failed: %v", err)
		}
	case AlgorithmXOR:
		if err := cryptXORObfuscation(context.hashAlg, sessionValue, context.nonceTPM,
			context.nonceCaller, data); err != nil {
			return fmt.Errorf("XOR parameter obfuscation failed: %v", err)
		}
	default:
		return fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	return nil
}
