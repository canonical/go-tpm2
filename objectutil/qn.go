// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

func computeOneQualifiedName(object Named, parentQn tpm2.Name) (tpm2.Name, error) {
	if object.Name().Algorithm() == tpm2.HashAlgorithmNull {
		return nil, errors.New("invalid name")
	}
	if !object.Name().Algorithm().Available() {
		return nil, errors.New("name algorithm is not available")
	}
	if !parentQn.IsValid() {
		return nil, errors.New("invalid parent qualified name")
	}
	if parentQn.Algorithm() != tpm2.HashAlgorithmNull && parentQn.Algorithm() != object.Name().Algorithm() {
		return nil, errors.New("name algorithm mismatch")
	}

	h := object.Name().Algorithm().NewHash()
	h.Write(parentQn)
	h.Write(object.Name())

	return mu.MustMarshalToBytes(object.Name().Algorithm(), mu.RawBytes(h.Sum(nil))), nil
}

// ComputeQualifiedName computes the qualified name of an object from the specified qualified name
// of a root object and a list of ancestor objects. The ancestor objects are ordered starting with
// the immediate child of the object associated with the root qualified name.
func ComputeQualifiedName(object Named, rootQn tpm2.Name, ancestors ...Named) (tpm2.Name, error) {
	lastQn := rootQn

	for i, ancestor := range ancestors {
		var err error
		lastQn, err = computeOneQualifiedName(ancestor, lastQn)
		if err != nil {
			return nil, fmt.Errorf("cannot compute intermediate QN for ancestor at index %d: %w", i, err)
		}
	}

	return computeOneQualifiedName(object, lastQn)
}

// ComputeQualifiedNameInHierarchy computes the qualified name of an object protected in the
// specified hierarchy from a list of ancestor objects. The ancestor objects are ordered
// starting from the primary object.
func ComputeQualifiedNameInHierarchy(object Named, hierarchy tpm2.Handle, ancestors ...Named) (tpm2.Name, error) {
	switch hierarchy {
	case tpm2.HandleOwner, tpm2.HandleNull, tpm2.HandleEndorsement, tpm2.HandlePlatform:
		// Good!
	default:
		return nil, errors.New("invalid hierarchy")
	}
	return ComputeQualifiedName(object, mu.MustMarshalToBytes(hierarchy), ancestors...)
}
