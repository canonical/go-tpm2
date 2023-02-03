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

func ExampleTPMContext_EvictControl_persistTransientObject() {
	// Create a primary object and then use TPMContext.EvictControl to store it in NV memory
	// at handle 0x81000001.
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

	transient, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, template, nil, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer tpm.FlushContext(transient)

	persistent, err := tpm.EvictControl(tpm.OwnerHandleContext(), transient, 0x81000001, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// persistent is the handle to the new persistent object
	_ = persistent
}

func ExampleTPMContext_EvictControl_evictPersistentObject() {
	// Use TPMContext.EvictControl to remove the object at handle 0x81000001 from NV memory.
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

	persistent, err := tpm.CreateResourceContextFromTPM(0x81000001)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), persistent, persistent.Handle(), nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// The resource associated with persistent is now unavailable.
}
