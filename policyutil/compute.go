// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"
	"fmt"
	"sort"

	"github.com/canonical/go-tpm2"
)

// mockPolicyParams is an implementation of policyParams that provides mock parameters
// to compute a policy.
type mockPolicyParams struct {
	signers  map[paramKey]*tpm2.Public  // maps a signed authorization to a dummy public key
	external map[*tpm2.Public]tpm2.Name // maps a dummy public key to a real name
}

func newMockPolicyParams(external map[*tpm2.Public]tpm2.Name) *mockPolicyParams {
	return &mockPolicyParams{
		signers:  make(map[paramKey]*tpm2.Public),
		external: external,
	}
}

func (p *mockPolicyParams) secretParams(authName tpm2.Name, policyRef tpm2.Nonce) *PolicySecretParams {
	return nil
}

func (p *mockPolicyParams) signedAuthorization(authName tpm2.Name, policyRef tpm2.Nonce) *PolicySignedAuthorization {
	key, exists := p.signers[policyParamKey(authName, policyRef)]
	if !exists {
		key = new(tpm2.Public)
		p.signers[policyParamKey(authName, policyRef)] = key
		p.external[key] = authName
	}
	return &PolicySignedAuthorization{
		Authorization: &PolicyAuthorization{
			AuthKey:   key,
			PolicyRef: policyRef,
		},
	}
}

func (p *mockPolicyParams) ticket(authName tpm2.Name, policyRef tpm2.Nonce) *PolicyTicket {
	return nil
}

type computePolicyFlowHandler struct {
	runner *policyRunner
}

func newComputePolicyFlowHandler(runner *policyRunner) *computePolicyFlowHandler {
	return &computePolicyFlowHandler{runner: runner}
}

func (h *computePolicyFlowHandler) handleBranches(branches policyBranches) error {
	context := &policyORContext{
		dispatcher:  h.runner,
		session:     h.runner.policySession,
		flowHandler: h.runner.policyFlowHandler,
		branches:    branches,
	}

	return context.collectBranchDigests(func() error {
		return context.completeBranchNode()
	})
}

func (h *computePolicyFlowHandler) pushComputeContext(digest *taggedHash) (restore func()) {
	oldContext := h.runner.policyRunnerContext
	h.runner.policyRunnerContext = newPolicyRunnerContext(
		newComputePolicySession(digest),
		oldContext.policyParams,
		oldContext.policyResources,
		oldContext.policyFlowHandler,
	)

	return func() {
		h.runner.policyRunnerContext = oldContext
	}
}

type PolicyComputeBranchNode struct {
	parentBranch      *PolicyComputeBranch
	saveBranchDigests bool
	childBranches     []*PolicyComputeBranch

	committed bool
}

func (n *PolicyComputeBranchNode) policy() *PolicyComputer {
	return n.parentBranch.policy
}

func (n *PolicyComputeBranchNode) parentPolicyBranch() *policyBranch {
	return n.parentBranch.policyBranch
}

func (n *PolicyComputeBranchNode) commitBranchNode() error {
	if n.committed {
		return errors.New("internal error: branch node already committed")
	}
	n.committed = true

	var branchesToLock []*PolicyComputeBranch
	nodes := []*PolicyComputeBranchNode{n}
	for len(nodes) > 0 {
		node := nodes[0]
		nodes = nodes[1:]

		for _, branch := range node.childBranches {
			if branch.locked {
				continue
			}
			branchesToLock = append(branchesToLock, branch)
			if branch.currentBranchNode != nil {
				nodes = append(nodes, branch.currentBranchNode)
			}
		}
	}

	for i := len(branchesToLock) - 1; i >= 0; i-- {
		if err := branchesToLock[i].lockBranch(); err != nil {
			return err
		}
	}

	var branches []policyBranch
	for _, branch := range n.childBranches {
		branches = append(branches, *branch.policyBranch)
	}
	return n.parentBranch.commitBranches(branches, n.saveBranchDigests)
}

// AddBranch adds a new branch to this branch node. The branch can be created with
// an optional name which can be used to select it during execution.
//
// The returned branch will be locked from further modifications when the branches associated
// with this node are committed to the parent branch (see [PolicyComputeBranch.AddBranchNode]).
func (n *PolicyComputeBranchNode) AddBranch(name PolicyBranchName) *PolicyComputeBranch {
	if n.committed {
		n.policy().fail("AddBranch", errors.New("cannot add branch to committed node"))
	}
	if len(n.childBranches) >= policyOrMaxDigests {
		n.policy().fail("AddBranch", fmt.Errorf("cannot add more than %d branches", policyOrMaxDigests))
	}
	if !name.isValid() {
		n.policy().fail("AddBranch", errors.New("invalid branch name"))
	}
	b := newPolicyComputeBranch(n.policy(), name, n.parentPolicyBranch().PolicyDigests)
	n.childBranches = append(n.childBranches, b)
	return b
}

func newComputePolicyRunnerContext(runner *policyRunner, digest *taggedHash) *policyRunnerContext {
	external := make(map[*tpm2.Public]tpm2.Name)
	return newPolicyRunnerContext(
		newComputePolicySession(digest),
		newMockPolicyParams(external),
		newMockResourceLoader(external),
		newComputePolicyFlowHandler(runner),
	)
}

// PolicyComputeBranch corresponds to a branch in a policy that is being computed.
type PolicyComputeBranch struct {
	policy       *PolicyComputer
	runners      []*policyRunner
	policyBranch *policyBranch

	currentBranchNode *PolicyComputeBranchNode
	locked            bool
}

func newPolicyComputeBranch(policy *PolicyComputer, name PolicyBranchName, digests taggedHashList) *PolicyComputeBranch {
	b := &PolicyComputeBranch{
		policy:       policy,
		policyBranch: &policyBranch{Name: name},
	}
	for _, digest := range digests {
		newDigest := taggedHash{HashAlg: digest.HashAlg, Digest: make(tpm2.Digest, digest.HashAlg.Size())}
		copy(newDigest.Digest, digest.Digest)
		b.policyBranch.PolicyDigests = append(b.policyBranch.PolicyDigests, newDigest)
	}
	for i := range b.policyBranch.PolicyDigests {
		runner := new(policyRunner)
		runner.policyRunnerContext = newComputePolicyRunnerContext(
			runner,
			&b.policyBranch.PolicyDigests[i],
		)
		b.runners = append(b.runners, runner)
	}
	return b
}

func (b *PolicyComputeBranch) commitBranches(branches []policyBranch, saveBranchDigests bool) error {
	b.currentBranchNode = nil
	if err := b.prepareToModifyBranch(); err != nil {
		return err
	}

	switch {
	case len(branches) == 0:
		// elide the branch node
	default:
		element := &policyElement{
			Type: tpm2.CommandPolicyOR,
			Details: &policyElementDetails{
				OR: &policyOR{Branches: branches}}}

		if err := b.runElementsForEachAlgorithm(element); err != nil {
			return err
		}

		if !saveBranchDigests {
			for i := range element.Details.OR.Branches {
				element.Details.OR.Branches[i].PolicyDigests = nil
			}
		}
		b.policyBranch.Policy = append(b.policyBranch.Policy, element)
	}

	return nil
}

func (b *PolicyComputeBranch) commitCurrentBranchNode() error {
	if b.currentBranchNode == nil {
		return nil
	}
	return b.currentBranchNode.commitBranchNode()
}

func (b *PolicyComputeBranch) prepareToModifyBranch() error {
	if b.policy.failed() {
		return b.policy.err
	}
	if b.locked {
		return errors.New("cannot modify locked branch")
	}
	return b.commitCurrentBranchNode()
}

func (b *PolicyComputeBranch) runElementsForEachAlgorithm(elements ...*policyElement) error {
	for _, runner := range b.runners {
		if err := runner.run(elements); err != nil {
			return fmt.Errorf("cannot update context for algorithm %v: %w", runner.session().HashAlg(), err)
		}
	}

	return nil
}

func (b *PolicyComputeBranch) lockBranch() error {
	if err := b.prepareToModifyBranch(); err != nil {
		return err
	}
	b.locked = true
	return nil
}

// PolicyNV adds a TPM2_PolicyNV assertion to this branch in order to bind the policy to the
// contents of the specified index. The caller specifies a value to be used for the comparison
// via the operandB argument, an offset from the start of the NV index data from which to start
// the comparison via the offset argument, and a comparison operator via the operation argument.
func (b *PolicyComputeBranch) PolicyNV(nvIndex *tpm2.NVPublic, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyNV", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNV,
		Details: &policyElementDetails{
			NV: &policyNV{
				NvIndex:   nvIndex,
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyNV", err)
	}

	return nil
}

// PolicySecret adds a TPM2_PolicySecret assertion to this branch so that the policy requires
// knowledge of the authorization value of the object associated with authObject.
func (b *PolicyComputeBranch) PolicySecret(authObject Named, policyRef tpm2.Nonce) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicySecret", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicySecret,
		Details: &policyElementDetails{
			Secret: &policySecret{
				AuthObjectName: authObject.Name(),
				PolicyRef:      policyRef}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicySecret", err)
	}

	return nil
}

// PolicySigned adds a TPM2_PolicySigned assertion to this branch so that the policy requires
// an assertion signed by the owner of the supplied key.
func (b *PolicyComputeBranch) PolicySigned(authKey Named, policyRef tpm2.Nonce) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicySigned", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicySigned,
		Details: &policyElementDetails{
			Signed: &policySigned{
				AuthKeyName: authKey.Name(),
				PolicyRef:   policyRef}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicySigned", err)
	}

	return nil
}

// PolicyAuthValue adds a TPM2_PolicyAuthValue assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyComputeBranch) PolicyAuthValue() error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyAuthValue", err)
	}

	element := &policyElement{
		Type:    tpm2.CommandPolicyAuthValue,
		Details: &policyElementDetails{AuthValue: new(policyAuthValue)}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyAuthValue", err)
	}

	return nil
}

// PolicyCommandCode adds a TPM2_PolicyCommandCode assertion to this branch to bind the policy
// to the specified command.
func (b *PolicyComputeBranch) PolicyCommandCode(code tpm2.CommandCode) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyCommandCode", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCommandCode,
		Details: &policyElementDetails{
			CommandCode: &policyCommandCode{CommandCode: code}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyCommandCode", err)
	}

	return nil
}

// PolicyCounterTimer adds a TPM2_PolicyCounterTimer assertion to this branch to bind the policy
// to the contents of the [tpm2.TimeInfo] structure.
func (b *PolicyComputeBranch) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyCounterTimer", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCounterTimer,
		Details: &policyElementDetails{
			CounterTimer: &policyCounterTimer{
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyCounterTimer", err)
	}

	return nil
}

// PolicyCpHash adds a TPM2_PolicyCpHash assertion to this branch in order to bind the policy to
// the supplied command parameters.
func (b *PolicyComputeBranch) PolicyCpHash(cpHashA CpHash) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyCpHash", err)
	}

	var digests taggedHashList
	for _, d := range b.policyBranch.PolicyDigests {
		digest, err := cpHashA.Digest(d.HashAlg)
		if err != nil {
			return b.policy.fail("PolicyCpHash", fmt.Errorf("cannot compute cpHash for algorithm %v: %w", d.HashAlg, err))
		}
		digests = append(digests, taggedHash{HashAlg: d.HashAlg, Digest: digest})
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCpHash,
		Details: &policyElementDetails{
			CpHash: &policyCpHash{Digests: digests}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyCpHash", err)
	}

	return nil
}

// PolicyNameHash adds a TPM2_PolicyNameHash assertion to this branch in order to bind the policy to
// the supplied command handles.
func (b *PolicyComputeBranch) PolicyNameHash(nameHash NameHash) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyNameHash", err)
	}

	var digests taggedHashList
	for _, d := range b.policyBranch.PolicyDigests {
		digest, err := nameHash.Digest(d.HashAlg)
		if err != nil {
			return b.policy.fail("PolicyNameHash", fmt.Errorf("cannot compute nameHash for algorithm %v: %w", d.HashAlg, err))
		}
		digests = append(digests, taggedHash{HashAlg: d.HashAlg, Digest: digest})
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNameHash,
		Details: &policyElementDetails{
			NameHash: &policyNameHash{Digests: digests}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyNameHash", err)
	}

	return nil
}

// PolicyPCR adds a TPM2_PolicyPCR assertion to this branch in order to bind the policy to the
// supplied PCR values.
func (b *PolicyComputeBranch) PolicyPCR(values tpm2.PCRValues) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyPCR", err)
	}

	var pcrs pcrValueList
	for alg := range values {
		if !alg.IsValid() {
			return b.policy.fail("PolicyPCR", fmt.Errorf("invalid digest algorithm %v", alg))
		}
		for pcr := range values[alg] {
			digest := values[alg][pcr]
			if len(digest) != alg.Size() {
				return b.policy.fail("PolicyPCR", fmt.Errorf("invalid digest size for PCR %v, algorithm %v", pcr, alg))
			}
			pcrs = append(pcrs, pcrValue{
				PCR:    tpm2.Handle(pcr),
				Digest: taggedHash{HashAlg: alg, Digest: digest}})
		}
	}
	sort.Slice(pcrs, func(i, j int) bool {
		return pcrs[i].PCR < pcrs[j].PCR || pcrs[i].Digest.HashAlg < pcrs[j].Digest.HashAlg
	})

	element := &policyElement{
		Type: tpm2.CommandPolicyPCR,
		Details: &policyElementDetails{
			PCR: &policyPCR{PCRs: pcrs}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyPCR", err)
	}

	return nil
}

// PolicyDuplicationSelect adds a TPM2_PolicyDuplicationSelect assertion to this branch in order
// to permit duplication of object to newParent with the [tpm2.TPMContext.Duplicate] function. Note
// that object must be supplied even if includeObject is false because the assertion sets the name
// hash of the session context to restrict the usage of the session to the specified pair of objects.
func (b *PolicyComputeBranch) PolicyDuplicationSelect(object, newParent Named, includeObject bool) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyDuplicationSelect", err)
	}

	var objectName tpm2.Name
	if object != nil {
		objectName = object.Name()
	}
	var newParentName tpm2.Name
	if newParent != nil {
		newParentName = newParent.Name()
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyDuplicationSelect,
		Details: &policyElementDetails{
			DuplicationSelect: &policyDuplicationSelect{
				Object:        objectName,
				NewParent:     newParentName,
				IncludeObject: includeObject}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyDuplicationSelect", err)
	}

	return nil
}

// PolicyPassword adds a TPM2_PolicyPassword assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyComputeBranch) PolicyPassword() error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyPassword", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyPassword,
		Details: &policyElementDetails{
			Password: new(policyPassword)}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyPassword", err)
	}

	return nil
}

// PolicyNvWritten adds a TPM2_PolicyNvWritten assertion to this branch in order to bind the
// policy to the status of the [tpm2.AttrNVWritten] attribute for the NV index on which the
// session is used.
func (b *PolicyComputeBranch) PolicyNvWritten(writtenSet bool) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyNvWritten", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNvWritten,
		Details: &policyElementDetails{
			NvWritten: &policyNvWritten{WrittenSet: writtenSet}}}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	if err := b.runElementsForEachAlgorithm(element); err != nil {
		return b.policy.fail("PolicyNvWritten", err)
	}

	return nil
}

// AddBranchNode adds a branch node to this branch from which sub-branches can be added.
// This makes it possible to create policies that can be satisified with different sets of
// conditions. One of the sub-branches will be selected during execution, and will be
// executed before the remaining assertions in this branch.
//
// The branches added to the returned branch node will be committed to this branch and
// the branch node will be locked from further modifications by subsequent additions to this
// branch, or any ancestor branches, or by calling [PolicyComputer.Policy].
//
// The saveBranchDigests argument indicates whether the policy digests associated with
// each branch should be retained. Omitting them saves space, but they will have to be be
// recomputed during execution.
func (b *PolicyComputeBranch) AddBranchNode(saveBranchDigests bool) *PolicyComputeBranchNode {
	if err := b.prepareToModifyBranch(); err != nil {
		b.policy.fail("AddBranchNode", err)
	}

	n := &PolicyComputeBranchNode{
		parentBranch:      b,
		saveBranchDigests: saveBranchDigests,
	}
	b.currentBranchNode = n
	return n
}

// PolicyComputer provides a way to compute an authorization policy.
type PolicyComputer struct {
	root *PolicyComputeBranch
	err  error
}

func computePolicy(digests taggedHashList) *PolicyComputer {
	c := new(PolicyComputer)
	c.root = newPolicyComputeBranch(c, "", digests)
	return c
}

// ComputePolicy begins the process of computing an authorization policy for the specified
// algorithms.
func ComputePolicy(algs ...tpm2.HashAlgorithmId) *PolicyComputer {
	for _, alg := range algs {
		if !alg.Available() {
			panic(fmt.Sprintf("digest algorithm %v is not available", alg))
		}
	}

	var digests taggedHashList
	for _, alg := range algs {
		digests = append(digests, taggedHash{HashAlg: alg, Digest: make(tpm2.Digest, alg.Size())})
	}

	return computePolicy(digests)
}

func (c *PolicyComputer) fail(name string, err error) error {
	if !c.failed() {
		c.err = fmt.Errorf("encountered an error when calling %s: %w", name, err)
	}

	return err
}

func (c *PolicyComputer) failed() bool { return c.err != nil }

// RootBranch returns the root branch associated with the policy that is being computed.
func (c *PolicyComputer) RootBranch() *PolicyComputeBranch {
	return c.root
}

// Policy returns the computed authorization policy digests and policy metadata. The
// returned metadata can be used to execute the computed policy.
//
// No more modifications can be made once this has been called.
func (c *PolicyComputer) Policy() (tpm2.TaggedHashList, *Policy, error) {
	if c.failed() {
		return nil, nil, fmt.Errorf("could not compute policy: %w", c.err)
	}

	if !c.root.locked {
		if err := c.root.lockBranch(); err != nil {
			return nil, nil, fmt.Errorf("cannot lock root branch: %w", err)
		}
	}

	var digests tpm2.TaggedHashList
	for _, digest := range c.root.policyBranch.PolicyDigests {
		digests = append(digests, tpm2.MakeTaggedHash(digest.HashAlg, digest.Digest))
	}

	return digests, &Policy{policy: policy{Policy: c.root.policyBranch.Policy}}, nil
}
