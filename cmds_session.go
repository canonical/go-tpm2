// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
)

func (t *tpmContext) StartAuthSession(tpmKey, bind ResourceContext, sessionType SessionType, symmetric *SymDef,
	authHash AlgorithmId, authValue []byte) (ResourceContext, error) {
	if tpmKey != nil {
		if err := t.checkResourceContextParam(tpmKey, "tpmKey"); err != nil {
			return nil, err
		}
	}
	if bind != nil {
		if err := t.checkResourceContextParam(bind, "bind"); err != nil {
			return nil, err
		}
	}
	if symmetric != nil {
		return nil,
			makeInvalidParamError("symmetric", "no support for parameter / response encryption yet")
	}
	digestSize, known := cryptGetDigestSize(authHash)
	if !known {
		return nil, makeInvalidParamError("authHash",
			fmt.Sprintf("unsupported digest algorithm %v", authHash))
	}

	var salt []byte
	var encryptedSalt EncryptedSecret

	if tpmKey != nil {
		object, isObject := tpmKey.(*objectContext)
		if !isObject {
			return nil, makeInvalidParamError("tpmKey", "not an object")
		}

		var err error
		encryptedSalt, salt, err = cryptComputeEncryptedSalt(&object.public)
		if err != nil {
			return nil, fmt.Errorf("cannot compute encrypted salt: %v", err)
		}
	} else {
		tpmKey = &permanentContext{handle: HandleNull}
	}

	if bind == nil {
		bind = &permanentContext{handle: HandleNull}
	}

	nonceCaller := make([]byte, digestSize)
	if err := cryptComputeNonce(nonceCaller); err != nil {
		return nil, fmt.Errorf("cannot compute initial nonceCaller: %v", err)
	}

	var sessionHandle Handle
	var nonceTPM Nonce

	if err := t.RunCommand(CommandStartAuthSession, tpmKey, bind, Separator, Nonce(nonceCaller),
		encryptedSalt, sessionType, &SymDef{Algorithm: AlgorithmNull}, authHash, Separator,
		&sessionHandle, Separator, &nonceTPM); err != nil {
		return nil, err
	}

	sessionContext := &sessionContext{handle: sessionHandle,
		hashAlg:        authHash,
		sessionType:    sessionType,
		policyHMACType: policyHMACTypeNoAuth,
		boundResource:  bind.Name(),
		nonceCaller:    Nonce(nonceCaller),
		nonceTPM:       nonceTPM}

	if tpmKey.Handle() != HandleNull || bind.Handle() != HandleNull {
		key := make([]byte, len(authValue)+len(salt))
		copy(key, authValue)
		copy(key[len(authValue):], salt)

		sessionContext.sessionKey =
			cryptKDFa(authHash, key, []byte("ATH"), []byte(nonceTPM), nonceCaller, digestSize*8)
	}

	t.addResourceContext(sessionContext)
	return sessionContext, nil
}

func (t *tpmContext) PolicyRestart(sessionHandle ResourceContext) error {
	if err := t.checkResourceContextParam(sessionHandle, "sessionHandle"); err != nil {
		return err
	}
	return t.RunCommand(CommandPolicyRestart, sessionHandle)
}
