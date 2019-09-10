// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 11 - Session Commands

import (
	"errors"
	"fmt"
)

func (t *TPMContext) StartAuthSession(tpmKey, bind ResourceContext, sessionType SessionType, symmetric *SymDef,
	authHash AlgorithmId, authValue []byte, sessions ...*Session) (ResourceContext, error) {
	if symmetric == nil {
		symmetric = &SymDef{Algorithm: AlgorithmNull}
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
			return nil, errors.New("invalid resource context for tpmKey: not an object")
		}

		var err error
		encryptedSalt, salt, err = cryptComputeEncryptedSalt(&object.public)
		if err != nil {
			return nil, fmt.Errorf("cannot compute encrypted salt: %v", err)
		}
	} else {
		tpmKey = permanentContext(HandleNull)
	}

	if bind == nil {
		bind = permanentContext(HandleNull)
	}

	var isBound bool = false
	var boundEntity Name
	if bind.Handle() != HandleNull && sessionType == SessionTypeHMAC {
		boundEntity = computeBindName(bind.Name(), authValue)
		isBound = true
	}

	nonceCaller := make([]byte, digestSize)
	if err := cryptComputeNonce(nonceCaller); err != nil {
		return nil, fmt.Errorf("cannot compute initial nonceCaller: %v", err)
	}

	var sessionHandle Handle
	var nonceTPM Nonce

	if err := t.RunCommand(CommandStartAuthSession, sessions, tpmKey, bind, Separator, Nonce(nonceCaller),
		encryptedSalt, sessionType, symmetric, authHash, Separator, &sessionHandle, Separator,
		&nonceTPM); err != nil {
		return nil, err
	}

	sessionContext := &sessionContext{handle: sessionHandle,
		hashAlg:        authHash,
		sessionType:    sessionType,
		policyHMACType: policyHMACTypeNoAuth,
		isBound:        isBound,
		boundEntity:    boundEntity,
		nonceCaller:    Nonce(nonceCaller),
		nonceTPM:       nonceTPM,
		symmetric:      symmetric}

	if tpmKey.Handle() != HandleNull || bind.Handle() != HandleNull {
		key := make([]byte, len(authValue)+len(salt))
		copy(key, authValue)
		copy(key[len(authValue):], salt)

		sessionContext.sessionKey =
			cryptKDFa(authHash, key, []byte("ATH"), []byte(nonceTPM), nonceCaller, digestSize*8,
				nil, false)
	}

	t.addResourceContext(sessionContext)
	return sessionContext, nil
}

func (t *TPMContext) PolicyRestart(sessionHandle ResourceContext) error {
	return t.RunCommand(CommandPolicyRestart, nil, sessionHandle)
}
