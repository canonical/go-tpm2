// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func TestSetCommandCodeAuditStatus(t *testing.T) {
	tpm := openTPMForTesting(t)
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

	attest, _, err := tpm.GetCommandAuditDigest(HandleEndorsement, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("GetCommandAuditDigest failed: %v", err)
	}

	auditInfo, err := attest.Decode()
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	initialAlgorithm := HashAlgorithmId(auditInfo.Attested.CommandAudit().DigestAlg)

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
		if err := tpm.SetCommandCodeAuditStatus(HandleOwner, initialAlgorithm, nil, nil, nil); err != nil {
			t.Errorf("Cannot restore command audit algorithm: %v", err)
		}
		if err := tpm.SetCommandCodeAuditStatus(HandleOwner, HashAlgorithmNull, nil, allCommands, nil); err != nil {
			t.Errorf("Cannot clear command audit commands: %v", err)
		}
		if err := tpm.SetCommandCodeAuditStatus(HandleOwner, HashAlgorithmNull, initialCommands, nil, nil); err != nil {
			t.Errorf("Cannot restore command audit commands: %v", err)
		}
	}()

	run := func(t *testing.T, auth interface{}) {
		checkAuditDigest := func(alg HashAlgorithmId) {
			attest, _, err = tpm.GetCommandAuditDigest(HandleEndorsement, nil, nil, nil, nil, nil)
			if err != nil {
				t.Fatalf("GetCommandAuditDigest failed: %v", err)
			}

			auditInfo, err = attest.Decode()
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if HashAlgorithmId(auditInfo.Attested.CommandAudit().DigestAlg) != alg {
				t.Errorf("Failed to set command audit digest")
			}
		}

		if err := tpm.SetCommandCodeAuditStatus(HandleOwner, alg, nil, nil, auth); err != nil {
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

		if err := tpm.SetCommandCodeAuditStatus(HandleOwner, HashAlgorithmNull, commands, nil, auth); err != nil {
			t.Errorf("SetCommandCodeAuditStatus failed: %v", err)
		}

		expectedCommands := make(CommandCodeList, 0, len(initialCommands)+len(commands))
		expectedCommands = append(expectedCommands, initialCommands...)
		expectedCommands = append(expectedCommands, commands...)
		checkAuditCommands(expectedCommands)

		if err := tpm.SetCommandCodeAuditStatus(HandleOwner, alg, nil, commands, auth); err != nil {
			t.Errorf("SetCommandCodeAuditStatus failed: %v", err)
		}

		checkAuditCommands(initialCommands)

		if err := tpm.SetCommandCodeAuditStatus(HandleOwner, initialAlgorithm, nil, nil, auth); err != nil {
			t.Errorf("SetCommandCodeAuditStatus failed: %v", err)
		}

		checkAuditDigest(initialAlgorithm)
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})

	t.Run("WithPasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)
		run(t, testAuth)
	})

	t.Run("WithSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		run(t, &Session{Context: sessionContext, Attrs: AttrContinueSession})
	})
}
