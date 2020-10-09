// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

type ResourceContextPrivate = resourceContextPrivate
type ObjectContext = objectContext
type NvIndexContext = nvIndexContext
type TestSessionContext = sessionContext

func (r *TestSessionContext) Attrs() SessionAttributes {
	return r.attrs
}

var TestComputeBindName = computeBindName

type SessionContextData = sessionContextData
