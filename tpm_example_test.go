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

func ExampleNewTPMContext_linux() {
	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// Use TPMContext
	// ...
}

func ExampleNewTPMContext_simulator() {
	tcti, err := mssim.OpenConnection("", 2321)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// Use TPMContext
	// ...
}

func ExampleTPMContext_cleartextPassphraseAuth() {
	// Change the authorization value for the storage hierarchy using
	// a cleartext passphrase for authorization. The existing authorization
	// value is sent to the TPM in cleartext.
	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// Assume the current authorization value is "passphrase".
	tpm.OwnerHandleContext().SetAuthValue([]byte("passphrase"))

	// Set the new authorization value to "foo". Note that we don't pass
	// in a session argument - TPMContext creates a password session
	// automatically.
	if err := tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), []byte("foo"), nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func ExampleTPMContext_hMACSessionAuth() {
	// Change the authorization value for the storage hierarchy using
	// a HMAC session for authorization. The current passphrase is used
	// to derive the key for the command HMAC which is verified on the TPM.
	// The current passphrase is not sent to the TPM in cleartext.
	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	// Create an unbounded, unsalted HMAC session.
	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer tpm.FlushContext(session)

	// Assume the current authorization value is "passphrase".
	tpm.OwnerHandleContext().SetAuthValue([]byte("passphrase"))

	// Set the new authorization value to "foo". Note that the new passphrase
	// is sent to the TPM in cleartext.
	if err := tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), []byte("foo"), session); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func ExampleTPMContext_policySessionAuth() {
	// Change the authorization value of an existing NV index using a
	// policy session for authorization.
	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	index, err := tpm.CreateResourceContextFromTPM(0x01800000)
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

	// Assume the current authorization value is "passphrase".
	index.SetAuthValue([]byte("passphrase"))

	if err := tpm.NVChangeAuth(index, []byte("foo"), session); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
