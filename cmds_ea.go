// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) PolicyPCR(policySession ResourceContext, pcrDigest Digest, pcrs PCRSelectionList) error {
	if err := t.checkResourceContextParam(policySession, "policySession"); err != nil {
		return err
	}

	return t.RunCommand(CommandPolicyPCR, policySession, Separator, pcrDigest, pcrs)
}

func (t *tpmContext) PolicyGetDigest(policySession ResourceContext) (Digest, error) {
	if err := t.checkResourceContextParam(policySession, "policySession"); err != nil {
		return nil, err
	}

	var policyDigest Digest

	if err := t.RunCommand(CommandPolicyGetDigest, policySession, Separator, Separator, Separator,
		&policyDigest); err != nil {
		return nil, err
	}

	return policyDigest, nil
}
