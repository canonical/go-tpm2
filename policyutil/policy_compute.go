package policyutil

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

type policyComputeRunner struct {
	policySession   *computePolicySession
	policyTickets   nullTickets
	policyResources mockPolicyResources

	currentPath policyBranchPath
}

func newPolicyComputeRunner(alg tpm2.HashAlgorithmId) *policyComputeRunner {
	return &policyComputeRunner{
		policySession: newComputePolicySession(alg, nil, true),
	}
}

func (r *policyComputeRunner) session() policySession {
	return r.policySession
}

func (r *policyComputeRunner) tickets() policyTickets {
	return &r.policyTickets
}

func (r *policyComputeRunner) resources() policyResources {
	return &r.policyResources
}

func (r *policyComputeRunner) authResourceName() tpm2.Name {
	return nil
}

func (r *policyComputeRunner) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewResourceContext(0x80000000, public.Name())
	return newResourceContext(resource, nil), nil
}

func (r *policyComputeRunner) authorize(auth ResourceContext, askForPolicy bool, commandParams *authorizationCommandParams, prefer tpm2.SessionType) (session SessionContext, err error) {
	return new(mockSessionContext), nil
}

func (r *policyComputeRunner) runBranch(branches policyBranches) (selected int, err error) {
	currentDigest, err := r.session().PolicyGetDigest()
	if err != nil {
		return 0, err
	}

	for _, branch := range branches {
		computedDigest, err := func() (tpm2.Digest, error) {
			origPolicySession := r.policySession
			origPath := r.currentPath
			r.policySession = newComputePolicySession(r.session().HashAlg(), currentDigest, true)
			r.currentPath = r.currentPath.Concat(branch.name())
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

		added := false
		for j, digest := range branch.PolicyDigests {
			if digest.HashAlg != r.session().HashAlg() {
				continue
			}

			branch.PolicyDigests[j] = taggedHash{HashAlg: r.session().HashAlg(), Digest: computedDigest}
			added = true
			break
		}
		if !added {
			branch.PolicyDigests = append(branch.PolicyDigests, taggedHash{HashAlg: r.session().HashAlg(), Digest: computedDigest})
		}
	}

	r.currentPath = r.currentPath.Concat("**")
	return -1, nil
}

func (r *policyComputeRunner) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*authorizedPolicy) (approvedPolicy tpm2.Digest, checkTicket *tpm2.TkVerified, err error) {
	return nil, nil, nil
}

func (r *policyComputeRunner) notifyPolicyPCRDigest() error {
	return fmt.Errorf("cannot compute digest for policies with TPM2_PolicyPCR assertions which contain pre-computed digests")
}

func (r *policyComputeRunner) run(elements policyElements) error {
	for len(elements) > 0 {
		element := elements[0].runner()
		elements = elements[1:]
		if err := element.run(r); err != nil {
			return makePolicyError(err, r.currentPath, element.name())
		}
	}

	return nil
}

// AddDigest computes and adds an additional digest to this policy for the specified
// algorithm. The policy should be persisted after calling this if it is going to be
// used for a resource wth the specified algorithm. On success, it returns the computed
// digest.
//
// This will fail for policies that contain TPM2_PolicyCpHash or TPM2_PolicyNameHash
// assertions, These can only be computed for a single digest algorithm, because they
// are bound to a specific resource via its name.
//
// It will also fail for policies that contain TPM2_PolicyPCR assertions that were
// added by [PolicyBuilderBranch.PolicyPCRDigest]. In order to compute policies
// containing TPM2_PolicyPCR assertions for more than one digest, use the
// [PolicyBuilderBranch.PolicyPCRValues] API, which stores the raw PCR values from
// which a new digest can be computed (but may occupy more space for an assertion that
// contains more than a single PCR value, depending on the selection of algorithms).
func (p *Policy) AddDigest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("unavailable algorithm")
	}

	var policy *policy
	if err := mu.CopyValue(&policy, p.policy); err != nil {
		return nil, fmt.Errorf("cannot make temporary copy of policy: %w", err)
	}

	runner := newPolicyComputeRunner(alg)
	if err := runner.run(policy.Policy); err != nil {
		return nil, err
	}

	computedDigest, err := runner.session().PolicyGetDigest()
	if err != nil {
		return nil, err
	}

	addedDigest := false
	for i, d := range policy.PolicyDigests {
		if d.HashAlg == alg {
			policy.PolicyDigests[i] = taggedHash{HashAlg: alg, Digest: computedDigest}
			addedDigest = true
			break
		}
	}
	if !addedDigest {
		policy.PolicyDigests = append(policy.PolicyDigests, taggedHash{HashAlg: alg, Digest: computedDigest})
	}

	p.policy = *policy

	return computedDigest, nil
}
