// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/util"
)

// srkHandle defines the handle for the SRK
const srkHandle = 0x81000001

// seal protects the supplied secret in the storage hierarchy of the TPM using
// a simple authorization policy that is gated on the current values of the PCRs
// included in the specified selection. The sealed object and metadata are
// serialized and returned in a form that can be passed to the unseal function.
func seal(secret []byte, pcrSelection tpm2.PCRSelectionList) ([]byte, error) {
	device, err := linux.DefaultTPM2Device()
	if err != nil {
		return nil, err
	}
	tpm, err := tpm2.OpenTPMDevice(device)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// Use the shared SRK as the storage object, and assume that it already exists.
	srk, err := tpm.NewResourceContext(srkHandle)
	if err != nil {
		return nil, err
	}

	// Build the sealed object template
	template := objectutil.NewSealedObjectTemplate(
		objectutil.WithUserAuthMode(objectutil.RequirePolicy))

	// Compute a simple PCR policy using the TPM's current values
	_, values, err := tpm.PCRRead(pcrSelection)
	if err != nil {
		return nil, err
	}

	digest, err := policyutil.ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrSelection, values)
	if err != nil {
		return nil, err
	}

	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyPCR(digest, pcrSelection)

	template.AuthPolicy = trial.GetDigest()

	sensitive := &tpm2.SensitiveCreate{Data: secret}

	// Create the sealed object
	priv, pub, _, _, _, err := tpm.Create(srk, sensitive, template, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	// Encode and return the sealed object
	return mu.MarshalToBytes(priv, pub, pcrSelection)
}

// unseal attempts to recover a secret from the supplied blob previously created by the seal
// function.
func unseal(data []byte) ([]byte, error) {
	// Decode the sealed object
	var priv tpm2.Private
	var pub *tpm2.Public
	var pcrSelection tpm2.PCRSelectionList
	if _, err := mu.UnmarshalFromBytes(data, &priv, &pub, &pcrSelection); err != nil {
		return nil, err
	}

	device, err := linux.DefaultTPM2Device()
	if err != nil {
		return nil, err
	}
	tpm, err := tpm2.OpenTPMDevice(device)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	srk, err := tpm.NewResourceContext(srkHandle)
	if err != nil {
		return nil, err
	}

	// Load the sealed object into the TPM
	object, err := tpm.Load(srk, priv, pub, nil)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(object)

	// Run a policy session with the PCR assertion
	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(session)

	if err := tpm.PolicyPCR(session, nil, pcrSelection); err != nil {
		return nil, err
	}

	return tpm.Unseal(object, session)
}

func Example_sealingASecret() {
	// Seal a secret to the storage hierarchy of the TPM using an authorization policy
	// that is gated on the current value of PCR7.
	//
	// Don't assume that this is a secure way to protect a key - it's just an example!

	secret := []byte("secret data")
	pcrSelection := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}

	sealedData, err := seal(secret, pcrSelection)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot seal:", err)
		return
	}

	// sealedData contains a serialized blob containing our secret that has been protected by the
	// TPM. It could be written somewhere to be read back later on.

	recoveredSecret, err := unseal(sealedData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot unseal:", err)
		return
	}

	fmt.Println("recovered secret:", recoveredSecret)
}
