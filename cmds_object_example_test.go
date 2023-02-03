// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/objectutil"
)

func ExampleTPMContext_Create_createPassphraseProtectedSealedObject() {
	// Use TPMContext.Create to seal some arbitrary data in a passphrase protected object.

	passphrase := []byte("passphrase")
	secret := []byte("secret data")

	device, err := linux.DefaultTPM2Device()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm, err := tpm2.OpenTPMDevice(device)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer tpm.Close()

	// We need a storage parent, eg, the shared SRK. Assume it already exists.
	srk, err := tpm.CreateResourceContextFromTPM(0x81000001)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	template := objectutil.NewSealedObjectTemplate()

	sensitive := &tpm2.SensitiveCreate{
		UserAuth: passphrase,
		Data:     secret}

	priv, pub, _, _, _, err := tpm.Create(srk, sensitive, template, nil, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// priv and pub contain the private and public parts of the sealed object,
	// and these can be serialized to persistent storage somewhere, or loaded in
	// to the TPM with the TPMContext.Load function. The mu/ subpackage can be used
	// to serialize them in the TPM wire format.
	_ = priv
	_ = pub
}
