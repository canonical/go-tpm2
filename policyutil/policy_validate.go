// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
)

type policyValidateRunner struct {
	policySession   *computePolicySession
	policyTickets   nullTickets
	policyResources mockPolicyResources

	currentPath policyBranchPath
}

func newPolicyValidateRunner(alg tpm2.HashAlgorithmId) *policyValidateRunner {
	return &policyValidateRunner{
		policySession: newComputePolicySession(alg, nil, false),
	}
}

func (r *policyValidateRunner) session() policySession {
	return r.policySession
}

func (r *policyValidateRunner) tickets() policyTickets {
	return &r.policyTickets
}

func (r *policyValidateRunner) resources() policyResources {
	return &r.policyResources
}

func (r *policyValidateRunner) authResourceName() tpm2.Name {
	return nil
}

func (r *policyValidateRunner) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewResourceContext(0x80000000, public.Name())
	return newResourceContext(resource, nil), nil
}

func (r *policyValidateRunner) authorize(auth ResourceContext, askForPolicy bool, usage *PolicySessionUsage, prefer tpm2.SessionType) (session SessionContext, err error) {
	return new(mockSessionContext), nil
}

func (r *policyValidateRunner) runBranch(branches policyBranches) (selected int, err error) {
	currentDigest, err := r.session().PolicyGetDigest()
	if err != nil {
		return 0, err
	}

	for i, branch := range branches {
		name := string(branch.Name)
		if len(name) == 0 {
			name = fmt.Sprintf("{%d}", i)
		}

		computedDigest, err := func() (tpm2.Digest, error) {
			origPolicySession := r.policySession
			origPath := r.currentPath
			r.policySession = newComputePolicySession(r.session().HashAlg(), currentDigest, false)
			r.currentPath = r.currentPath.Concat(name)
			defer func() {
				r.policySession = origPolicySession
				r.currentPath = origPath
			}()

			if err := r.run(branch.Policy); err != nil {
				return nil, err
			}

			return r.session().PolicyGetDigest()
		}()
		if err != nil {
			return 0, err
		}

		for _, digest := range branch.PolicyDigests {
			if digest.HashAlg != r.session().HashAlg() {
				continue
			}

			if !bytes.Equal(digest.Digest, computedDigest) {
				return 0, fmt.Errorf("stored and computed branch digest mismatch for branch %d (computed: %x, stored: %x)", i, computedDigest, digest.Digest)
			}
			break
		}
	}

	r.currentPath = r.currentPath.Concat("**")
	return -1, nil
}

func (r *policyValidateRunner) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*authorizedPolicy) (approvedPolicy tpm2.Digest, checkTicket *tpm2.TkVerified, err error) {
	return nil, nil, nil
}

func (r *policyValidateRunner) notifyPolicyPCRDigest() error {
	return nil
}

func (r *policyValidateRunner) run(elements policyElements) error {
	for len(elements) > 0 {
		element := elements[0].runner()
		elements = elements[1:]
		if err := element.run(r); err != nil {
			return makePolicyError(err, r.currentPath, element.name())
		}
	}

	return nil
}

// Validate performs some checking of every element in the policy, and
// verifies that every branch is consistent with their stored digests. On
// success, it returns the digest correpsonding to this policy for the
// specified digest algorithm.
func (p *Policy) Validate(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("unavailable algorithm")
	}

	expectedDigest, err := p.Digest(alg)
	if err != nil {
		return nil, err
	}

	runner := newPolicyValidateRunner(alg)
	if err := runner.run(p.policy.Policy); err != nil {
		return nil, err
	}

	computedDigest, err := runner.session().PolicyGetDigest()
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(computedDigest, expectedDigest) {
		return nil, fmt.Errorf("stored and computed policy digest mismatch (computed: %x, stored: %x)", computedDigest, expectedDigest)
	}

	for _, auth := range p.policy.PolicyAuthorizations {
		if auth.AuthKey.Name().Algorithm() != alg {
			continue
		}

		ok, err := auth.Verify(computedDigest)
		if err != nil {
			return nil, &PolicyAuthorizationError{AuthName: auth.AuthKey.Name(), PolicyRef: auth.PolicyRef, err: fmt.Errorf("cannot verify signature: %w", err)}
		}
		if !ok {
			return nil, &PolicyAuthorizationError{AuthName: auth.AuthKey.Name(), PolicyRef: auth.PolicyRef, err: errors.New("invalid signature")}
		}
	}

	return expectedDigest, nil
}
