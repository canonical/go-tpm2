// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func TestNVPublicName(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	pub := NVPublic{
		Index:   Handle(0x0181ffff),
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthWrite | AttrNVAuthRead),
		Size:    64}
	rc, err := tpm.NVDefineSpace(owner, nil, &pub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, rc, owner)

	name := pub.Name()

	// rc.Name() is what the TPM returned from NVReadPublic
	if !bytes.Equal(rc.Name(), name) {
		t.Errorf("NVPublic.Name() returned an unexpected name")
	}
}
