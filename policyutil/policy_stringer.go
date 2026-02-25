// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
)

type policyStringifierRunner struct {
	w io.Writer

	policySession   policySession
	policyTickets   nullTickets
	policyResources *mockPolicyResources

	depth int

	currentPath policyBranchPath
}

func newPolicyStringifierRunner(alg tpm2.HashAlgorithmId, authorizedPolicies AuthorizedPolicies, w io.Writer) *policyStringifierRunner {
	return &policyStringifierRunner{
		w:               w,
		policySession:   newStringifierPolicySession(alg, w, 0),
		policyResources: newMockPolicyResources(authorizedPolicies),
	}
}

func (r *policyStringifierRunner) session() policySession {
	return r.policySession
}

func (r *policyStringifierRunner) tickets() policyTickets {
	return &r.policyTickets
}

func (r *policyStringifierRunner) resources() policyResources {
	return r.policyResources
}

func (r *policyStringifierRunner) authResourceName() tpm2.Name {
	return nil
}

func (r *policyStringifierRunner) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewResourceContext(0x80000000, public.Name())
	return newResourceContext(resource, nil), nil
}

func (r *policyStringifierRunner) authorize(auth ResourceContext, askForPolicy bool, commandParams *authorizationCommandParams, prefer tpm2.SessionType) (session SessionContext, err error) {
	return new(mockSessionContext), nil
}

func (r *policyStringifierRunner) runBranch(branches policyBranches) (selected int, err error) {
	var treeDepth int
	switch {
	case len(branches) <= 8:
		treeDepth = 1
	case len(branches) <= 64:
		treeDepth = 2
	case len(branches) <= 512:
		treeDepth = 3
	default:
		treeDepth = 4
	}

	var digests tpm2.DigestList
	for _, branch := range branches {
		var digest tpm2.Digest
		for _, d := range branch.PolicyDigests {
			if d.HashAlg != r.session().HashAlg() {
				continue
			}
			digest = d.Digest
			break
		}
		if len(digest) == 0 {
			return 0, ErrMissingDigest
		}
		digests = append(digests, digest)
	}

	tree, err := newPolicyOrTree(r.session().HashAlg(), digests)
	if err != nil {
		return 0, fmt.Errorf("cannot compute PolicyOR tree: %w", err)
	}

	fmt.Fprintf(r.w, "\n%*s BranchNode {", r.depth*3, "")

	maybeOpenSection := func(i int) {
		extraDepth := (treeDepth - 1) * 2
		if treeDepth > 3 && i%512 == 0 {
			fmt.Fprintf(r.w, "\n%*s {", (r.depth+extraDepth-5)*3, "")
			fmt.Fprintf(r.w, "\n%*s {", (r.depth+extraDepth-4)*3, "")
		}
		if treeDepth > 2 && i%64 == 0 {
			fmt.Fprintf(r.w, "\n%*s {", (r.depth+extraDepth-3)*3, "")
			fmt.Fprintf(r.w, "\n%*s {", (r.depth+extraDepth-2)*3, "")
		}
		if treeDepth > 1 && i%8 == 0 {
			fmt.Fprintf(r.w, "\n%*s {", (r.depth+extraDepth-1)*3, "")
			fmt.Fprintf(r.w, "\n%*s {", (r.depth+extraDepth)*3, "")
		}
	}
	maybeCloseSection := func(i int, finish bool) error {
		if i == 0 {
			return errors.New("invalid index")
		}

		extraDepth := (treeDepth - 1) * 2
		digests := tree.selectBranch(i - 1)
		if treeDepth > 1 && (i%8 == 0 || finish) {
			fmt.Fprintf(r.w, "\n%*s }", (r.depth+extraDepth)*3, "")
			if len(digests) > 1 {
				session := newStringifierPolicySession(r.session().HashAlg(), r.w, r.depth+extraDepth)
				if err := session.PolicyOR(digests[0]); err != nil {
					return err
				}
			}
			fmt.Fprintf(r.w, "\n%*s }", (r.depth+extraDepth-1)*3, "")
		}
		if treeDepth > 2 && (i%64 == 0 || finish) {
			fmt.Fprintf(r.w, "\n%*s }", (r.depth+extraDepth-2)*3, "")
			if len(digests) > 2 {
				session := newStringifierPolicySession(r.session().HashAlg(), r.w, r.depth+extraDepth-2)
				if err := session.PolicyOR(digests[0]); err != nil {
					return err
				}
			}
			fmt.Fprintf(r.w, "\n%*s }", (r.depth+extraDepth-3)*3, "")
		}
		if treeDepth > 4 && (i%512 == 0 || finish) {
			fmt.Fprintf(r.w, "\n%*s }", (r.depth+extraDepth-4)*3, "")
			if len(digests) > 3 {
				session := newStringifierPolicySession(r.session().HashAlg(), r.w, r.depth+extraDepth-4)
				if err := session.PolicyOR(digests[0]); err != nil {
					return err
				}
			}
			fmt.Fprintf(r.w, "\n%*s }", (r.depth+extraDepth-5)*3, "")
		}
		return nil
	}

	maybeOpenSection(0)

	for i, branch := range branches {
		if i > 0 {
			if err := maybeCloseSection(i, false); err != nil {
				return 0, fmt.Errorf("internal error: %w", err)
			}
			maybeOpenSection(i)
		}

		err := func() error {
			origSession := r.policySession
			origPath := r.currentPath
			origDepth := r.depth

			r.depth++
			r.depth += ((treeDepth - 1) * 2)
			r.policySession = newStringifierPolicySession(r.policySession.HashAlg(), r.w, r.depth)
			r.currentPath = r.currentPath.Concat(branch.name())
			defer func() {
				r.depth = origDepth
				r.policySession = origSession
				r.currentPath = origPath
			}()

			fmt.Fprintf(r.w, "\n%*sBranch %d", r.depth*3, "", i)
			if len(branch.Name) > 0 {
				fmt.Fprintf(r.w, " (%s)", branch.Name)
			}
			fmt.Fprintf(r.w, " {")

			fmt.Fprintf(r.w, "\n%*s # digest %v:%#x", r.depth*3, "", r.policySession.HashAlg(), digests[i])

			if err := r.run(branch.Policy); err != nil {
				return err
			}

			fmt.Fprintf(r.w, "\n%*s}", r.depth*3, "")
			return nil
		}()
		if err != nil {
			return 0, err
		}
	}
	if err := maybeCloseSection(len(branches), true); err != nil {
		return 0, fmt.Errorf("internal error: %w", err)
	}
	fmt.Fprintf(r.w, "\n%*s }", r.depth*3, "")

	return -1, nil
}

func (r *policyStringifierRunner) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*authorizedPolicy) (approvedPolicy tpm2.Digest, checkTicket *tpm2.TkVerified, err error) {
	fmt.Fprintf(r.w, "\n%*s AuthorizedPolicies {", r.depth*3, "")
	for _, policy := range policies {
		err := func() error {
			origSession := r.policySession
			origPath := r.currentPath

			r.depth++
			r.policySession = newStringifierPolicySession(r.policySession.HashAlg(), r.w, r.depth)
			r.currentPath = r.currentPath.Concat(string(policy.Name))
			defer func() {
				r.depth--
				r.policySession = origSession
				r.currentPath = origPath
			}()

			var digest tpm2.Digest
			for _, d := range policy.PolicyDigests {
				if d.HashAlg != r.policySession.HashAlg() {
					continue
				}
				digest = d.Digest
				break
			}
			if len(digest) == 0 {
				return ErrMissingDigest
			}
			fmt.Fprintf(r.w, "\n%*sAuthorizedPolicy %x {", r.depth*3, "", digest)
			fmt.Fprintf(r.w, "\n%*s # digest %v:%#x", r.depth*3, "", r.policySession.HashAlg(), digest)

			if err := r.run(policy.Policy); err != nil {
				return err
			}

			fmt.Fprintf(r.w, "\n%*s}", r.depth*3, "")
			return nil
		}()
		if err != nil {
			return nil, nil, err
		}

	}
	fmt.Fprintf(r.w, "\n%*s }", r.depth*3, "")
	return nil, nil, nil
}

func (r *policyStringifierRunner) notifyPolicyPCRDigest() error {
	return nil
}

func (r *policyStringifierRunner) run(elements policyElements) error {
	for len(elements) > 0 {
		element := elements[0].runner()
		elements = elements[1:]
		if err := element.run(r); err != nil {
			return makePolicyError(err, r.currentPath, element.name())
		}
	}

	return nil
}

func (p *Policy) string(alg tpm2.HashAlgorithmId, authorizedPolicies AuthorizedPolicies) (string, error) {
	var digest tpm2.Digest
	if alg == tpm2.HashAlgorithmNull {
		if len(p.policy.PolicyDigests) > 0 {
			alg = p.policy.PolicyDigests[0].HashAlg
			digest = p.policy.PolicyDigests[0].Digest
		}
	} else {
		for _, d := range p.policy.PolicyDigests {
			if d.HashAlg != alg {
				continue
			}
			digest = d.Digest
			break
		}
	}
	if len(digest) == 0 {
		return "", ErrMissingDigest
	}

	w := new(bytes.Buffer)
	fmt.Fprintf(w, "\nPolicy {")
	fmt.Fprintf(w, "\n # digest %v:%#x", alg, digest)
	for i, auth := range p.policy.PolicyAuthorizations {
		fmt.Fprintf(w, "\n # auth %d authName:%#x, policyRef:%#x, sigAlg:%v", i, auth.AuthKey.Name(), auth.PolicyRef, auth.Signature.SigAlg)
		if auth.Signature.SigAlg.IsValid() {
			fmt.Fprintf(w, ", hashAlg:%v", auth.Signature.HashAlg())
		}
	}

	runner := newPolicyStringifierRunner(alg, authorizedPolicies, w)
	if err := runner.run(p.policy.Policy); err != nil {
		return "", err
	}

	fmt.Fprintf(w, "\n}")
	return w.String(), nil
}

func (p *Policy) String() string {
	if len(p.policy.PolicyDigests) == 0 {
		return "%!(ERROR=no computed digests)"
	}
	return p.Stringer(p.policy.PolicyDigests[0].HashAlg, nil).String()
}

type policyStringer struct {
	alg                tpm2.HashAlgorithmId
	authorizedPolicies AuthorizedPolicies
	policy             *Policy
}

// String implements fmt.Stringer. It will print a string representation of the policy
// with the first computed digest algorithm.
func (s *policyStringer) String() string {
	str, err := s.policy.string(s.alg, s.authorizedPolicies)
	if err != nil {
		return fmt.Sprintf("%%!(ERROR=%v)", err)
	}
	return str
}

// Stringer returns a fmt.Stringer that will print a string representation of the policy
// for the specified digest algorithm. The policy must already include this algorithm. If
// the algorithm is [tpm2.HashAlgorithmNull], then the first computed algorithm will be used.
// If authorizedPolicies is supplied, the string representation will include the relevant
// authorized policies as well.
func (p *Policy) Stringer(alg tpm2.HashAlgorithmId, authorizedPolicies AuthorizedPolicies) fmt.Stringer {
	return &policyStringer{
		alg:                alg,
		authorizedPolicies: authorizedPolicies,
		policy:             p,
	}
}
