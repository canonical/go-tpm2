// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/canonical/go-tpm2/mu"
)

const (
	PolicyHMACTypeAuth     = policyHMACTypeAuth
	PolicyHMACTypePassword = policyHMACTypePassword
)

type ResourceContextInternal = resourceContextInternal
type ObjectContext = objectContext
type NvIndexContext = nvIndexContext
type PolicyHMACType = policyHMACType
type SessionContextData = sessionContextData
type SessionContextImpl = sessionContext // We already have a SessionContext interface
type SessionContextInternal = sessionContextInternal
type SessionParam = sessionParam
type SessionParams = sessionParams

var ComputeBindName = computeBindName
var NewExtraSessionParam = newExtraSessionParam
var NewSessionParamForAuth = newSessionParamForAuth
var NewSessionParams = newSessionParams

func Canonicalize(vals ...interface{}) error {
	b := new(bytes.Buffer)
	if _, err := mu.MarshalToWriter(b, vals...); err != nil {
		return err
	}
	_, err := mu.UnmarshalFromReader(b, vals...)
	return err
}

func MockRandReader(r io.Reader) (restore func()) {
	orig := rand.Reader
	rand.Reader = r
	return func() {
		rand.Reader = orig
	}
}

func NewMockSessionParam(session SessionContext, associatedResource ResourceContext, includeAuthValue bool, decryptNonce, encryptNonce Nonce) *SessionParam {
	var r resourceContextInternal
	if associatedResource != nil {
		r = associatedResource.(resourceContextInternal)
	}
	var s sessionContextInternal
	if session != nil {
		s = session.(sessionContextInternal)
	}

	return &sessionParam{
		session:            s,
		associatedResource: r,
		includeAuthValue:   includeAuthValue,
		decryptNonce:       decryptNonce,
		encryptNonce:       encryptNonce}
}

func NewMockSessionParams(commandCode CommandCode, sessions []*SessionParam, encryptSessionIndex, decryptSessionIndex int) *SessionParams {
	return &sessionParams{
		commandCode:         commandCode,
		sessions:            sessions,
		encryptSessionIndex: encryptSessionIndex,
		decryptSessionIndex: decryptSessionIndex}
}
