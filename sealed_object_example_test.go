// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/util"
)

const (
	// forceCreateSRK controls whether seal unconditionally creates a SRK
	// at srkHandle
	forceCreateSRK = true

	// srkHandle defines the handle for the SRK
	srkHandle = 0x81000001
)

// seal seals the supplied secret to a sealed object in the storage hierarchy
// of the TPM, using a simple authorization policy that is gated on the current
// values of the PCRs included in the specified selection. The sealed object and
// metadata are serialized to the supplied io.Writer.
func seal(secret []byte, pcrSelection tpm2.PCRSelectionList, w io.Writer) error {
	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		return err
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// Ensure we have a storage root key (SRK)
	srk, err := tpm.CreateResourceContextFromTPM(srkHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, srkHandle):
		// No existing object - nothing to do
	case err != nil:
		// Unexpected error
		return err
	case forceCreateSRK:
		// Evict the existing object
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), srk, srk.Handle(), nil); err != nil {
			return err
		}
	}

	if srk == nil || srk.Handle() == tpm2.HandleUnassigned {
		template := objectutil.NewRSAStorageKeyTemplate()
		template.Unique.RSA = make(tpm2.PublicKeyRSA, 256)

		object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, template, nil, nil, nil)
		if err != nil {
			return err
		}

		srk, err = tpm.EvictControl(tpm.OwnerHandleContext(), object, srkHandle, nil)
		if err != nil {
			tpm.FlushContext(object)
			return err
		}

		tpm.FlushContext(object)
	}

	// Build the sealed object template
	template := objectutil.NewSealedObjectTemplate()

	// Disallow passphrase authorization for the user role
	template.Attrs &^= tpm2.AttrUserWithAuth

	// Compute a simple PCR policy using the TPM's current values
	_, values, err := tpm.PCRRead(pcrSelection)
	if err != nil {
		return err
	}

	digest, err := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrSelection, values)
	if err != nil {
		return err
	}

	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyPCR(digest, pcrSelection)

	template.AuthPolicy = trial.GetDigest()

	sensitive := &tpm2.SensitiveCreate{Data: secret}

	// Create the sealed object
	priv, pub, _, _, _, err := tpm.Create(srk, sensitive, template, nil, nil, nil)
	if err != nil {
		return err
	}

	// Encode the sealed object
	_, err = mu.MarshalToWriter(w, priv, pub, pcrSelection)
	return err
}

// unseal attempts to recover a secret previously sealed by the seal function
func unseal(r io.Reader) ([]byte, error) {
	// Decode the sealed object
	var priv tpm2.Private
	var pub *tpm2.Public
	var pcrSelection tpm2.PCRSelectionList
	if _, err := mu.UnmarshalFromReader(r, &priv, &pub, &pcrSelection); err != nil {
		return nil, err
	}

	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		return nil, err
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	srk, err := tpm.CreateResourceContextFromTPM(srkHandle)
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
	// that is gated on the value of PCR7.
	secret := []byte("secret data")

	// Use a memory buffer for storing the encoded sealed object, but this could
	// be a file or some other persistent storage.
	buf := new(bytes.Buffer)

	if err := seal(secret, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}, buf); err != nil {
		fmt.Fprintln(os.Stderr, "cannot seal:", err)
		return
	}

	recoveredSecret, err := unseal(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot unseal:", err)
		return
	}

	fmt.Println("recovered secret:", recoveredSecret)
}
