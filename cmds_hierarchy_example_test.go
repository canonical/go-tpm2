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

func ExampleTPMContext_CreatePrimary_createPrimaryStorageKeyInStorageHierarchy() {
	// Use TPMContext.CreatePrimary to create a primary storage key in the storage hierarchy.
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

	template := objectutil.NewRSAStorageKeyTemplate()

	object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, template, nil, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// object is the handle to the new transient primary object
	// ...
	// ... do something with object
	// ...

	tpm.FlushContext(object)
}
