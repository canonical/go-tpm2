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
	// Use TPMContext.Create to seal some arbitrary data in a
	// passphrase protected object.

	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// We need a parent object, eg, the shared SRK. Assume it already exists.
	srk, err := tpm.CreateResourceContextFromTPM(0x81000001)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	template := objectutil.NewSealedObjectTemplate()

	sensitive := &tpm2.SensitiveCreate{
		UserAuth: []byte("passphrase"),
		Data:     []byte("secret data")}

	priv, pub, _, _, _, err := tpm.Create(srk, sensitive, template, nil, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// priv and pub contain the private and public parts of the sealed object,
	// and these can be serialized to persistent storage somewhere. The mu
	// subpackage can be used to serialize them in the TPM wire format.
	_ = priv
	_ = pub
}
