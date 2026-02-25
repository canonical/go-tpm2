// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/canonical/go-tpm2"
)

// PolicyNVDetails contains the properties of a TPM2_PolicyNV assertion.
type PolicyNVDetails struct {
	Auth      tpm2.Handle
	Index     tpm2.Handle
	Name      tpm2.Name
	OperandB  tpm2.Operand
	Offset    uint16
	Operation tpm2.ArithmeticOp
}

// PolicyAuthorizationDetails contains the properties of a TPM2_PolicySecret,
// TPM2_PolicySigned or TPM2_PolicyAuthorize assertion.
type PolicyAuthorizationDetails struct {
	AuthName  tpm2.Name
	PolicyRef tpm2.Nonce
}

// PolicyCounterTimerDetails contains the properties of a TPM2_PolicyCounterTimer
// assertion.
type PolicyCounterTimerDetails struct {
	OperandB  tpm2.Operand
	Offset    uint16
	Operation tpm2.ArithmeticOp
}

// PolicyPCRDetails contains the properties of a TPM2_PolicyPCR assertion.
type PolicyPCRDetails struct {
	PCRDigest tpm2.Digest
	PCRs      tpm2.PCRSelectionList
}

// PolicyBranchDetails contains the properties of a single policy branch.
type PolicyBranchDetails struct {
	NV                []PolicyNVDetails            // TPM2_PolicyNV assertions
	Secret            []PolicyAuthorizationDetails // TPM2_PolicySecret assertions
	Signed            []PolicyAuthorizationDetails // TPM2_PolicySigned assertions
	Authorize         []PolicyAuthorizationDetails // TPM2_PolicyAuthorize assertions
	AuthValueNeeded   bool                         // The branch contains a TPM2_PolicyAuthValue or TPM2_PolicyPassword assertion
	policyCommandCode tpm2.CommandCodeList
	CounterTimer      []PolicyCounterTimerDetails // TPM2_PolicyCounterTimer assertions
	policyCpHash      tpm2.DigestList
	policyNameHash    tpm2.DigestList
	PCR               []PolicyPCRDetails // TPM2_PolicyPCR assertions
	policyNvWritten   []bool
}

// IsValid indicates whether the corresponding policy branch is valid.
func (r *PolicyBranchDetails) IsValid() bool {
	if len(r.policyCommandCode) > 1 {
		for _, code := range r.policyCommandCode[1:] {
			if code != r.policyCommandCode[0] {
				return false
			}
		}
	}

	cpHashNum := 0
	if len(r.policyCpHash) > 0 {
		if len(r.policyCpHash) > 1 {
			for _, cpHash := range r.policyCpHash[1:] {
				if !bytes.Equal(cpHash, r.policyCpHash[0]) {
					return false
				}
			}
		}
		cpHashNum += 1
	}
	if len(r.policyNameHash) > 0 {
		if len(r.policyNameHash) > 1 {
			return false
		}
		cpHashNum += 1
	}
	if cpHashNum > 1 {
		return false
	}
	if len(r.policyNvWritten) > 1 {
		for _, nvWritten := range r.policyNvWritten[1:] {
			if nvWritten != r.policyNvWritten[0] {
				return false
			}
		}
	}

	return true
}

// The command code associated with a branch if set, either set by the TPM2_PolicyCommandCode
// or TPM2_PolicyDuplicationSelect assertion.
func (r *PolicyBranchDetails) CommandCode() (code tpm2.CommandCode, set bool) {
	if len(r.policyCommandCode) == 0 {
		return 0, false
	}
	return r.policyCommandCode[0], true
}

// The cpHash associated with a branch if set, either set by the TPM2_PolicyCpHash,
// TPM2_PolicySecret, or TPM2_PolicySigned assertions.
func (r *PolicyBranchDetails) CpHash() (cpHashA tpm2.Digest, set bool) {
	if len(r.policyCpHash) == 0 {
		return nil, false
	}
	return r.policyCpHash[0], true
}

// The nameHash associated with a branch if set, either set by the TPM2_PolicyNameHash
// or TPM2_PolicyDuplicationSelect assertion.
func (r *PolicyBranchDetails) NameHash() (nameHash tpm2.Digest, set bool) {
	if len(r.policyNameHash) == 0 {
		return nil, false
	}
	return r.policyNameHash[0], true
}

// The nvWrittenSet value associated with a branch if set.
func (r *PolicyBranchDetails) NvWritten() (nvWrittenSet bool, set bool) {
	if len(r.policyNvWritten) == 0 {
		return false, false
	}
	return r.policyNvWritten[0], true
}

type policyDetailsTreeWalkerBranchContext struct {
	nodeCtx       *policyDetailsTreeWalkerBranchNodeContext
	policySession *recorderPolicySession
	path          policyBranchPath
	details       PolicyBranchDetails
}

func (c *policyDetailsTreeWalkerBranchContext) session() policySession {
	return c.policySession
}

func (c *policyDetailsTreeWalkerBranchContext) beginBranchNode() (treeWalkerBranchNodeContext, error) {
	remaining := c.nodeCtx.remaining
	consumeGreedy := c.nodeCtx.consumeGreedy

	var next string
	if consumeGreedy {
		next = "*"
	} else {
		next, remaining = c.nodeCtx.remaining.PopNextComponent()
		if next == "**" {
			consumeGreedy = true
			next = "*"
		}
	}

	return newPolicyDetailsTreeWalkerBranchNodeContext(c.nodeCtx.alg, c.path, remaining, next, consumeGreedy, &c.details, c.nodeCtx.result), nil
}

func (c *policyDetailsTreeWalkerBranchContext) completeFullPath() error {
	c.nodeCtx.result[string(c.path)] = c.details
	return nil
}

type policyDetailsTreeWalkerBranchNodeContext struct {
	alg           tpm2.HashAlgorithmId
	path          policyBranchPath // the path of this branch that this node is in
	remaining     policyBranchPath // remaining components of the specified path
	next          string           // next component of the specified path
	consumeGreedy bool
	details       PolicyBranchDetails // details inherited from the parent branch
	result        map[string]PolicyBranchDetails
}

func newPolicyDetailsTreeWalkerBranchNodeContext(alg tpm2.HashAlgorithmId, path, remaining policyBranchPath, next string, consumeGreedy bool, details *PolicyBranchDetails, result map[string]PolicyBranchDetails) *policyDetailsTreeWalkerBranchNodeContext {
	return &policyDetailsTreeWalkerBranchNodeContext{
		alg:           alg,
		path:          path,
		remaining:     remaining,
		next:          next,
		consumeGreedy: consumeGreedy,
		details:       *details,
		result:        result,
	}
}

func (c *policyDetailsTreeWalkerBranchNodeContext) beginBranch(name string) (treeWalkerBranchContext, error) {
	switch len(c.next) {
	case 0:
		// handle this branch - there is no next component specified
	default:
		match, err := filepath.Match(c.next, name)
		switch {
		case err != nil:
			return nil, fmt.Errorf("cannot match: %w", err)
		case !match:
			// skip - the next component was specified but it's not a match for this branch.
			return nil, errTreeWalkerSkipBranch
		}
	}

	branchCtx := &policyDetailsTreeWalkerBranchContext{
		nodeCtx: c,
		path:    c.path.Concat(name),
		details: c.details,
	}
	branchCtx.policySession = newRecorderPolicySession(c.alg, &branchCtx.details)

	return branchCtx, nil
}

// Details returns details of all branches with the supplied path prefix, for
// the specified algorithm. If the specified algorithm is [tpm2.HashAlgorithmNull],
// then the first algorithm the policy is computed for is used.
//
// If the authorizedPolicies argument is supplied, details of branches from associated
// authorized policies will be inserted into the result.
func (p *Policy) Details(alg tpm2.HashAlgorithmId, path string, authorizedPolicies PolicyAuthorizedPolicies) (map[string]PolicyBranchDetails, error) {
	if alg == tpm2.HashAlgorithmNull {
		if len(p.policy.PolicyDigests) == 0 {
			return nil, ErrMissingDigest
		}
		alg = p.policy.PolicyDigests[0].HashAlg
	}

	result := make(map[string]PolicyBranchDetails)

	walker := newTreeWalker(
		newMockPolicyResources(authorizedPolicies),
		newPolicyDetailsTreeWalkerBranchNodeContext(alg, "", policyBranchPath(path), "*", false, new(PolicyBranchDetails), result),
	)
	if err := walker.run(p.policy.Policy); err != nil {
		return nil, err
	}

	return result, nil
}
