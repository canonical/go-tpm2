// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mssim"
)

func ExampleOpenTPMDevice_linux() {
	// Open the default Linux TPM2 character device.

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

	// Use TPMContext
	// ...
}

func ExampleOpenTPMDevice_simulator() {
	// Open the TPM simulator on the default port (2321).

	tpm, err := tpm2.OpenTPMDevice(mssim.DefaultDevice)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer tpm.Close()

	// Use TPMContext
	// ...
}

func ExampleTPMContext_cleartextPassphraseAuth() {
	// Change the authorization value for the storage hierarchy using
	// a cleartext passphrase for authorization.

	oldPassphrase := []byte("passphrase")
	newPassphrase := []byte("esarhpssap")

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

	tpm.OwnerHandleContext().SetAuthValue(oldPassphrase)

	// Change the new authorization value. Note that we don't pass
	// in a session argument - TPMContext creates a password session
	// automatically. Both the old and new passphrases are sent to the
	// TPM in cleartext.
	if err := tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), newPassphrase, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func ExampleTPMContext_hMACSessionAuth() {
	// Change the authorization value for the storage hierarchy using
	// a HMAC session for authorization.

	oldPassphrase := []byte("passphrase")
	newPassphrase := []byte("esarhpssap")

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

	// Create an unbounded, unsalted HMAC session.
	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer tpm.FlushContext(session)

	tpm.OwnerHandleContext().SetAuthValue(oldPassphrase)

	// Change the authorization value. Note that we pass in the HMAC session
	// context. The current passphrase is not sent to the TPM - it is used to
	// derive the key used to create a command HMAC, which is then verified on
	// the TPM. The new passphrase is sent to the TPM in cleartext.
	if err := tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), newPassphrase, session); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func ExampleTPMContext_policySessionAuth() {
	// Change the authorization value of an existing NV index at handle 0x0180000 using a
	// policy session for authorization. The policy for the index asserts that the caller
	// must know the existing authorization value.

	handle := tpm2.Handle(0x01800000)
	oldPassphrase := []byte("passphrase")
	newPassphrase := []byte("esarhpssap")

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

	index, err := tpm.NewResourceContext(handle)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer tpm.FlushContext(session)

	if err := tpm.PolicyCommandCode(session, tpm2.CommandNVChangeAuth); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if err := tpm.PolicyAuthValue(session); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	index.SetAuthValue(oldPassphrase)

	if err := tpm.NVChangeAuth(index, newPassphrase, session); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
