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

type CmdContext = cmdContext
type NvIndexContextImpl = nvIndexContext
type PolicyHMACType = policyHMACType
type RspContext = rspContext
type SessionContextData = sessionContextData
type SessionContextImpl = sessionContext // We already have a SessionContext interface
type SessionParam = sessionParam
type SessionParams = sessionParams

var ComputeBindName = computeBindName
var NewExtraSessionParam = newExtraSessionParam
var NewSessionParamForAuth = newSessionParamForAuth
var NewSessionParams = newSessionParams
var NullResource = nullResource
var PwSession = pwSession

func (c *CommandContext) Cmd() *CmdContext {
	return &c.cmd
}

func (c *NvIndexContextImpl) Public() *NVPublic {
	return c.Data.NV.Data
}

func (c *ResponseContext) Dispatcher() commandDispatcher {
	return c.dispatcher
}

func (c *ResponseContext) Rsp() *RspContext {
	return c.rsp
}

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

func NewMockCommandContext(dispatcher commandDispatcher, cmd *CmdContext) *CommandContext {
	c := &CommandContext{dispatcher: dispatcher}
	if cmd != nil {
		c.cmd = *cmd
	}
	return c
}

func NewMockResponseContext(dispatcher commandDispatcher, rsp *RspContext) *ResponseContext {
	return &ResponseContext{
		dispatcher: dispatcher,
		rsp:        rsp}
}
