// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func TestSetCommandCodeAuditStatus(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy|testutil.TPMFeatureSetCommandCodeAuditStatus)
	defer closeTPM(t, tpm)

	var allCommands CommandCodeList
	if commands, err := tpm.GetCapabilityCommands(CommandFirst, CapabilityMaxProperties); err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	} else {
		for _, c := range commands {
			allCommands = append(allCommands, c.CommandCode())
		}
	}

	initialCommands, err := tpm.GetCapabilityAuditCommands(CommandFirst, CapabilityMaxProperties)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	auditInfo, _, err := tpm.GetCommandAuditDigest(tpm.EndorsementHandleContext(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("GetCommandAuditDigest failed: %v", err)
	}

	initialAlgorithm := HashAlgorithmId(auditInfo.Attested.CommandAudit.DigestAlg)

	var alg HashAlgorithmId
	switch initialAlgorithm {
	case HashAlgorithmSHA256:
		alg = HashAlgorithmSHA1
	default:
		alg = HashAlgorithmSHA256
	}

	var commands CommandCodeList
	i := 0
Next:
	for _, c := range allCommands {
		if i >= 10 {
			break
		}
		for _, a := range initialCommands {
			if a == c {
				continue Next
			}
		}
		commands = append(commands, c)
		i++
	}

	defer func() {
		owner := tpm.OwnerHandleContext()
		if err := tpm.SetCommandCodeAuditStatus(owner, initialAlgorithm, nil, nil, nil); err != nil {
			t.Errorf("Cannot restore command audit algorithm: %v", err)
		}
		if err := tpm.SetCommandCodeAuditStatus(owner, HashAlgorithmNull, nil, allCommands, nil); err != nil {
			t.Errorf("Cannot clear command audit commands: %v", err)
		}
		if err := tpm.SetCommandCodeAuditStatus(owner, HashAlgorithmNull, initialCommands, nil, nil); err != nil {
			t.Errorf("Cannot restore command audit commands: %v", err)
		}
	}()

	run := func(t *testing.T, authAuthSession SessionContext) {
		checkAuditDigest := func(alg HashAlgorithmId) {
			auditInfo, _, err = tpm.GetCommandAuditDigest(tpm.EndorsementHandleContext(), nil, nil, nil, nil, nil)
			if err != nil {
				t.Fatalf("GetCommandAuditDigest failed: %v", err)
			}

			if HashAlgorithmId(auditInfo.Attested.CommandAudit.DigestAlg) != alg {
				t.Errorf("Failed to set command audit digest")
			}
		}

		owner := tpm.OwnerHandleContext()
		if err := tpm.SetCommandCodeAuditStatus(owner, alg, nil, nil, authAuthSession); err != nil {
			t.Errorf("SetCommandCodeAuditStatus failed: %v", err)
		}

		checkAuditDigest(alg)

		checkAuditCommands := func(expectedCommands CommandCodeList) {
			expected := make(map[CommandCode]struct{})
			var empty struct{}
			for _, c := range expectedCommands {
				expected[c] = empty
			}

			commands, err := tpm.GetCapabilityAuditCommands(CommandFirst, CapabilityMaxProperties)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}

			for _, c := range commands {
				if _, ok := expected[c]; !ok {
					t.Errorf("Unexpected command code %v returned from GetCapabilityAuditCommands", c)
				} else {
					delete(expected, c)
				}
			}

			if len(expected) > 0 {
				t.Errorf("Missing command codes")
			}
		}

		if err := tpm.SetCommandCodeAuditStatus(owner, HashAlgorithmNull, commands, nil, authAuthSession); err != nil {
			t.Errorf("SetCommandCodeAuditStatus failed: %v", err)
		}

		expectedCommands := make(CommandCodeList, 0, len(initialCommands)+len(commands))
		expectedCommands = append(expectedCommands, initialCommands...)
		expectedCommands = append(expectedCommands, commands...)
		checkAuditCommands(expectedCommands)

		if err := tpm.SetCommandCodeAuditStatus(owner, alg, nil, commands, authAuthSession); err != nil {
			t.Errorf("SetCommandCodeAuditStatus failed: %v", err)
		}

		checkAuditCommands(initialCommands)

		if err := tpm.SetCommandCodeAuditStatus(owner, initialAlgorithm, nil, nil, authAuthSession); err != nil {
			t.Errorf("SetCommandCodeAuditStatus failed: %v", err)
		}

		checkAuditDigest(initialAlgorithm)
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})

	t.Run("WithPasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())
		run(t, nil)
	})

	t.Run("WithSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())

		sessionContext, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		run(t, sessionContext.WithAttrs(AttrContinueSession))
	})
}
