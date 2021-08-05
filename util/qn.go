// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"encoding/binary"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// ComputeQualifiedName can compute the qualified name of an object with
// the specified name that is protected by a parent with the specified
// qualified name.
func ComputeQualifiedName(name, parentQn tpm2.Name) tpm2.Name {
	h := name.Algorithm().NewHash()
	h.Write(parentQn)
	h.Write(name)

	b, _ := mu.MarshalToBytes(name.Algorithm(), mu.RawBytes(h.Sum(nil)))
	return tpm2.Name(b)
}

// ComputeQualifiedNameFull can compute the qualified name of an object with
// the specified name that is protected in the specified hierarchy by the chain
// of parent objects with the specified names. The ancestor names are ordered
// from the primary key towards the immediate parent.
func ComputeQualifiedNameFull(name tpm2.Name, hierarchy tpm2.Handle, ancestors ...tpm2.Name) tpm2.Name {
	lastQn := make(tpm2.Name, 4)
	binary.BigEndian.PutUint32(lastQn, uint32(hierarchy))

	for len(ancestors) > 0 {
		current := ancestors[0]
		ancestors = ancestors[1:]
		lastQn = ComputeQualifiedName(current, lastQn)
	}

	return ComputeQualifiedName(name, lastQn)
}
