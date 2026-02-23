// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import "github.com/canonical/go-tpm2"

type policyBranchesWalkResult struct {
	branches []string
}

type policyBranchesTreeWalkerBranchContext struct {
	nodeCtx       *policyBranchesTreeWalkerBranchNodeContext
	policySession *nullPolicySession
	path          policyBranchPath
}

func (c *policyBranchesTreeWalkerBranchContext) session() policySession {
	return c.policySession
}

func (c *policyBranchesTreeWalkerBranchContext) beginBranchNode() (treeWalkerBranchNodeContext, error) {
	return newPolicyBranchesTreeWalkerBranchNodeContext(c.nodeCtx.alg, c.path, c.nodeCtx.result), nil
}

func (c *policyBranchesTreeWalkerBranchContext) completeFullPath() error {
	c.nodeCtx.result.branches = append(c.nodeCtx.result.branches, string(c.path))
	return nil
}

type policyBranchesTreeWalkerBranchNodeContext struct {
	alg    tpm2.HashAlgorithmId
	path   policyBranchPath // the path of the branch that this node is in
	result *policyBranchesWalkResult
}

func newPolicyBranchesTreeWalkerBranchNodeContext(alg tpm2.HashAlgorithmId, path policyBranchPath, result *policyBranchesWalkResult) *policyBranchesTreeWalkerBranchNodeContext {
	return &policyBranchesTreeWalkerBranchNodeContext{
		alg:    alg,
		path:   path,
		result: result,
	}
}

func (c *policyBranchesTreeWalkerBranchNodeContext) beginBranch(name string) (treeWalkerBranchContext, error) {
	return &policyBranchesTreeWalkerBranchContext{
		nodeCtx:       c,
		policySession: newNullPolicySession(c.alg),
		path:          c.path.Concat(name),
	}, nil
}

// Branches returns the path of every branch in this policy.
//
// If the authorizedPolicies argument is supplied, associated authorized policies will be
// merged into the result, otherwise missing authorized policies will be represented
// by a path component of the form "<authorize:key:%#x,ref:%#x>". The supplied algorithm
// is only really required for policies that make use of authorized policies, and is used
// to select the algorithm for encoding the path component for an authorized policy, which
// is the policy digest. Setting this to [tpm2.HashAlgorithmNull] selects the first digest
// algorithm that this policy is computed for.
func (p *Policy) Branches(alg tpm2.HashAlgorithmId, authorizedPolicies PolicyAuthorizedPolicies) ([]string, error) {
	if alg == tpm2.HashAlgorithmNull {
		if len(p.policy.PolicyDigests) == 0 {
			return nil, ErrMissingDigest
		}
		alg = p.policy.PolicyDigests[0].HashAlg
	}

	var result policyBranchesWalkResult

	walker := newTreeWalker(newMockPolicyResources(authorizedPolicies), newPolicyBranchesTreeWalkerBranchNodeContext(alg, "", &result))
	if err := walker.run(p.policy.Policy); err != nil {
		return nil, err
	}

	return result.branches, nil
}
