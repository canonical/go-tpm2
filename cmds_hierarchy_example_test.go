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
	// Use TPMContext.CreatePrimary to create a primary storage key in the
	// storage hierarchy.
	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	template := objectutil.NewRSAStorageKeyTemplate()

	object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, template, nil, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer tpm.FlushContext(object)

	// object is the handle to the new transient primary object
}
