// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"

	"github.com/canonical/go-tpm2/mu"
)

type ResourceContextPrivate = resourceContextPrivate
type ObjectContext = objectContext
type NvIndexContext = nvIndexContext
type SessionContextImpl = sessionContext // We already have a SessionContext interface

func (r *SessionContextImpl) Attrs() SessionAttributes {
	return r.attrs
}

var ComputeBindName = computeBindName

type SessionContextData = sessionContextData

func Canonicalize(vals ...interface{}) error {
	b := new(bytes.Buffer)
	if _, err := mu.MarshalToWriter(b, vals...); err != nil {
		return err
	}
	_, err := mu.UnmarshalFromReader(b, vals...)
	return err
}
