// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// PolicyBuilderBranchNode is a point in a [PolicyBuilderBranch] to which sub-branches
// can be added.
type PolicyBuilderBranchNode struct {
	parentBranch  *PolicyBuilderBranch
	childBranches []*PolicyBuilderBranch

	committed bool
}

func (n *PolicyBuilderBranchNode) policy() *PolicyBuilder {
	return n.parentBranch.policy
}

func (n *PolicyBuilderBranchNode) commitBranchNode() error {
	if n.committed {
		return errors.New("internal error: branch node already committed")
	}
	n.committed = true

	var branchesToLock []*PolicyBuilderBranch
	nodes := []*PolicyBuilderBranchNode{n}
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

	var branches []*policyBranch
	for _, branch := range n.childBranches {
		branches = append(branches, branch.policyBranch)
	}
	return n.parentBranch.commitBranches(branches)
}

// AddBranch adds a new branch to this branch node. The branch can be created with
// an optional name which can be used to select it during execution.
//
// The returned branch will be locked from further modifications when the branches associated
// with this node are committed to the parent branch (see [PolicyBuilderBranch.AddBranchNode]).
func (n *PolicyBuilderBranchNode) AddBranch(name string) *PolicyBuilderBranch {
	if n.committed {
		n.policy().fail("AddBranch", errors.New("cannot add branch to committed node"))
	}
	if len(n.childBranches) >= policyOrMaxDigests {
		n.policy().fail("AddBranch", fmt.Errorf("cannot add more than %d branches", policyOrMaxDigests))
	}

	pbn := policyBranchName(name)
	if !pbn.isValid() {
		n.policy().fail("AddBranch", errors.New("invalid branch name"))
	}
	b := newPolicyBuilderBranch(n.policy(), pbn)
	n.childBranches = append(n.childBranches, b)
	return b
}

// PolicyBuilderBranch corresponds to a branch in a policy that is being computed.
type PolicyBuilderBranch struct {
	policy       *PolicyBuilder
	policyBranch *policyBranch

	currentBranchNode *PolicyBuilderBranchNode
	locked            bool
}

func newPolicyBuilderBranch(policy *PolicyBuilder, name policyBranchName) *PolicyBuilderBranch {
	return &PolicyBuilderBranch{
		policy:       policy,
		policyBranch: &policyBranch{Name: policyBranchName(name)},
	}
}

func (b *PolicyBuilderBranch) commitBranches(branches []*policyBranch) error {
	b.currentBranchNode = nil
	if err := b.prepareToModifyBranch(); err != nil {
		return err
	}

	switch len(branches) {
	case 0:
		// elide the branch node
	// case 1:
	// Whilst it makes sense to elide the branch node in this case
	// and then copy the sub-branch into this branch, the caller may
	// expect to be able to still address the single sub-branch by
	// name when executing the policy.
	default:
		element := &policyElement{
			Type: tpm2.CommandPolicyOR,
			Details: makePolicyElementDetails(
				policyORElement{Branches: branches},
			),
		}
		b.policyBranch.Policy = append(b.policyBranch.Policy, element)
	}

	return nil
}

func (b *PolicyBuilderBranch) commitCurrentBranchNode() error {
	if b.currentBranchNode == nil {
		return nil
	}
	return b.currentBranchNode.commitBranchNode()
}

func (b *PolicyBuilderBranch) prepareToModifyBranch() error {
	if b.policy.failed() {
		return b.policy.err
	}
	if b.locked {
		return errors.New("cannot modify locked branch")
	}
	return b.commitCurrentBranchNode()
}

func (b *PolicyBuilderBranch) lockBranch() error {
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
//
// When using this assertion, it is generally good practise for the NV index to have an
// authorization policy that permits the use of TPM2_PolicyNV and TPM2_NV_Read without any
// conditions (ie, a policy with branches for those commands without any additional assertions).
// Where this assertion appears in a policy with multiple branches or a policy that is authorized,
// the contents of the NV index will be tested in the process of automatic branch selection if
// the index has a policy that permits the use of TPM2_NV_Read without any other conditions.
func (b *PolicyBuilderBranch) PolicyNV(nvIndex *tpm2.NVPublic, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyNV", err)
	}

	if !nvIndex.Name().IsValid() {
		return b.policy.fail("PolicyNV", errors.New("invalid nvIndex"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNV,
		Details: makePolicyElementDetails(
			policyNVElement{
				NvIndex:   nvIndex,
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation,
			},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicySecret adds a TPM2_PolicySecret assertion to this branch so that the policy requires
// knowledge of the authorization value of the object associated with authObject.
func (b *PolicyBuilderBranch) PolicySecret(authObject Named, policyRef tpm2.Nonce) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicySecret", err)
	}

	authObjectName := authObject.Name()
	if !authObjectName.IsValid() {
		return b.policy.fail("PolicySecret", errors.New("invalid authObject name"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicySecret,
		Details: makePolicyElementDetails(
			policySecretElement{
				AuthObjectName: authObjectName,
				PolicyRef:      policyRef,
			},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicySigned adds a TPM2_PolicySigned assertion to this branch so that the policy requires
// an assertion signed by the owner of the supplied key.
func (b *PolicyBuilderBranch) PolicySigned(authKey *tpm2.Public, policyRef tpm2.Nonce) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicySigned", err)
	}

	authKeyName := authKey.Name()
	if !authKeyName.IsValid() {
		return b.policy.fail("PolicySigned", errors.New("invalid authKey"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicySigned,
		Details: makePolicyElementDetails(
			policySignedElement{
				AuthKey:   authKey,
				PolicyRef: policyRef,
			},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyAuthorize adds a TPM2_PolicyAuthorize assertion to this branch so that the policy
// can be changed by allowing the authorizing entity to sign new policies. The name algorithm
// of the public key should match the name algorithm of the resource that this policy is being
// created for. Whilst this isn't required by the TPM, the [Policy.Authorize] API enforces this
// by only signing policy digests for the key's name algorithm.
//
// When [Policy.Execute] runs this assertion, it will select an execute an appropriate
// authorized policy.
func (b *PolicyBuilderBranch) PolicyAuthorize(policyRef tpm2.Nonce, keySign *tpm2.Public) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyAuthorize", err)
	}

	keySignName := keySign.Name()
	if !keySignName.IsValid() {
		return b.policy.fail("PolicyAuthorize", errors.New("invalid keySign"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyAuthorize,
		Details: makePolicyElementDetails(
			policyAuthorizeElement{
				PolicyRef: policyRef,
				KeySign:   keySign,
			},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyAuthValue adds a TPM2_PolicyAuthValue assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyBuilderBranch) PolicyAuthValue() error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyAuthValue", err)
	}

	element := &policyElement{
		Type:    tpm2.CommandPolicyAuthValue,
		Details: makePolicyElementDetails(policyAuthValueElement{}),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyCommandCode adds a TPM2_PolicyCommandCode assertion to this branch to bind the policy
// to the specified command.
func (b *PolicyBuilderBranch) PolicyCommandCode(code tpm2.CommandCode) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyCommandCode", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCommandCode,
		Details: makePolicyElementDetails(
			policyCommandCodeElement{CommandCode: code},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyCounterTimer adds a TPM2_PolicyCounterTimer assertion to this branch to bind the policy
// to the contents of the [tpm2.TimeInfo] structure.
func (b *PolicyBuilderBranch) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyCounterTimer", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCounterTimer,
		Details: makePolicyElementDetails(
			policyCounterTimerElement{
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation,
			},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyCpHash adds a TPM2_PolicyCpHash assertion to this branch in order to bind the policy to
// the supplied command parameters.
//
// As this binds the authorization to an object and and a policy has to have the same algorithm as
// this, policies with this assertion can only be computed for a single digest algorithm.
func (b *PolicyBuilderBranch) PolicyCpHash(code tpm2.CommandCode, handles []Named, params ...interface{}) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyCpHash", err)
	}

	var handleNames []tpm2.Name
	for i, handle := range handles {
		name := handle.Name()
		if !name.IsValid() {
			return b.policy.fail("PolicyCpHash", fmt.Errorf("invalid name at handle %d", i))
		}
		handleNames = append(handleNames, name)
	}

	cpBytes, err := mu.MarshalToBytes(params...)
	if err != nil {
		return b.policy.fail("PolicyCpHash", fmt.Errorf("cannot marshal parameters: %w", err))
	}

	id := uint32(len(b.policy.cpHashParams))
	idBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idBytes, id)
	b.policy.cpHashParams[id] = cpHashParams{
		CommandCode: code,
		Handles:     handleNames,
		CpBytes:     cpBytes}

	element := &policyElement{
		Type: tpm2.CommandPolicyCpHash,
		Details: makePolicyElementDetails(
			policyCpHashElement{Digest: idBytes},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyNameHash adds a TPM2_PolicyNameHash assertion to this branch in order to bind the policy to
// the supplied command handles.
//
// As this binds the authorization to an object and and a policy has to have the same algorithm as
// this, policies with this assertion can only be computed for a single digest algorithm.
func (b *PolicyBuilderBranch) PolicyNameHash(handles ...Named) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyNameHash", err)
	}

	var handleNames []tpm2.Name
	for i, handle := range handles {
		name := handle.Name()
		if !name.IsValid() {
			return b.policy.fail("PolicyNameHash", fmt.Errorf("invalid name at handle %d", i))
		}
		handleNames = append(handleNames, name)
	}

	id := uint32(len(b.policy.nameHashParams))
	idBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idBytes, id)
	b.policy.nameHashParams[id] = handleNames

	element := &policyElement{
		Type: tpm2.CommandPolicyNameHash,
		Details: makePolicyElementDetails(
			policyNameHashElement{Digest: idBytes},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyPCR adds a TPM2_PolicyPCR assertion to this branch in order to bind the policy to the
// supplied PCR values.
func (b *PolicyBuilderBranch) PolicyPCR(values tpm2.PCRValues) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyPCR", err)
	}

	var pcrs pcrValueList
	for alg := range values {
		if !alg.IsValid() {
			return b.policy.fail("PolicyPCR", fmt.Errorf("invalid digest algorithm %v", alg))
		}
		for pcr := range values[alg] {
			s := tpm2.PCRSelect{pcr}
			if _, err := s.ToBitmap(0); err != nil {
				return b.policy.fail("PolicyPCR", fmt.Errorf("invalid PCR %v: %w", pcr, err))
			}
			digest := values[alg][pcr]
			if len(digest) != alg.Size() {
				return b.policy.fail("PolicyPCR", fmt.Errorf("invalid digest size for PCR %v, algorithm %v", pcr, alg))
			}
			pcrs = append(pcrs, pcrValue{
				PCR:    tpm2.Handle(pcr),
				Digest: tpm2.MakeTaggedHash(alg, digest)})
		}
	}
	sort.Slice(pcrs, func(i, j int) bool {
		return pcrs[i].PCR < pcrs[j].PCR || pcrs[i].Digest.HashAlg < pcrs[j].Digest.HashAlg
	})

	element := &policyElement{
		Type: tpm2.CommandPolicyPCR,
		Details: makePolicyElementDetails(
			policyPCRElement{PCRs: pcrs},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyDuplicationSelect adds a TPM2_PolicyDuplicationSelect assertion to this branch in order
// to permit duplication of object to newParent with the [tpm2.TPMContext.Duplicate] function. Note
// that object must be supplied even if includeObject is false because the assertion sets the name
// hash of the session context to restrict the usage of the session to the specified pair of objects.
func (b *PolicyBuilderBranch) PolicyDuplicationSelect(object, newParent Named, includeObject bool) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyDuplicationSelect", err)
	}

	var objectName tpm2.Name
	if object != nil {
		objectName = object.Name()
		if !objectName.IsValid() {
			return b.policy.fail("PolicyDuplicationSelect", errors.New("invalid object name"))
		}
	}
	var newParentName tpm2.Name
	if newParent != nil {
		newParentName = newParent.Name()
	}
	if newParentName.Type() == tpm2.NameTypeNone || !newParentName.IsValid() {
		return b.policy.fail("PolicyDuplicationSelect", errors.New("invalid newParent name"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyDuplicationSelect,
		Details: makePolicyElementDetails(
			policyDuplicationSelectElement{
				Object:        objectName,
				NewParent:     newParentName,
				IncludeObject: includeObject,
			},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyPassword adds a TPM2_PolicyPassword assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyBuilderBranch) PolicyPassword() error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyPassword", err)
	}

	element := &policyElement{
		Type:    tpm2.CommandPolicyPassword,
		Details: makePolicyElementDetails(policyPasswordElement{}),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// PolicyNvWritten adds a TPM2_PolicyNvWritten assertion to this branch in order to bind the
// policy to the status of the [tpm2.AttrNVWritten] attribute for the NV index on which the
// session is used.
func (b *PolicyBuilderBranch) PolicyNvWritten(writtenSet bool) error {
	if err := b.prepareToModifyBranch(); err != nil {
		return b.policy.fail("PolicyNvWritten", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNvWritten,
		Details: makePolicyElementDetails(
			policyNvWrittenElement{WrittenSet: writtenSet},
		),
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	return nil
}

// AddBranchNode adds a branch node to this branch from which sub-branches can be added.
// This makes it possible to create policies that can be satisified with different sets of
// conditions. One of the sub-branches will be selected during execution, and will be
// executed before the remaining assertions in this branch.
//
// The branches added to the returned branch node will be committed to this branch and
// the branch node will be locked from further modifications by subsequent additions to this
// branch, or any ancestor branches, or by calling [PolicyBuilder.Build]. This ensures
// that branches can only append to a policy with the [PolicyBuilder] API .
func (b *PolicyBuilderBranch) AddBranchNode() *PolicyBuilderBranchNode {
	if err := b.prepareToModifyBranch(); err != nil {
		b.policy.fail("AddBranchNode", err)
	}

	n := &PolicyBuilderBranchNode{parentBranch: b}
	b.currentBranchNode = n
	return n
}

// PolicyBuilder provides a way to compute an authorization policy. A policy consists
// of a sequence of assertions, and may contain sub-branches in order to create a policy
// that can satisfy multiple conditions. A policy can be arbitrarily complex.
//
// All policies have a root branch and execution with [Policy.Execute] starts with this
// branch. Whenever a branch node is encountered, a sub-branch is chosen. Execution then
// continues with the chosen sub-branch until all assertions in it have been executed.
// Execution then resumes in the parent branch, with the assertion immediately following
// the branch node.
//
// The PolicyBuilder API only allows a policy to be appended to.
//
// XXX: Note that the PolicyBuilder API may change.
type PolicyBuilder struct {
	root           *PolicyBuilderBranch
	alg            tpm2.HashAlgorithmId
	cpHashParams   map[uint32]cpHashParams
	nameHashParams map[uint32][]tpm2.Name
	err            error
}

// NewPolicyBuilder returns a new PolicyBuilder.
func NewPolicyBuilder() *PolicyBuilder {
	b := &PolicyBuilder{
		alg:            tpm2.HashAlgorithmNull,
		cpHashParams:   make(map[uint32]cpHashParams),
		nameHashParams: make(map[uint32][]tpm2.Name),
	}
	b.root = newPolicyBuilderBranch(b, "")
	return b
}

// NewPolicyBuilderOR returns a new PolicyBuilder initialized with a TPM2_PolicyOR
// assertion of the supplied policies. This is to make it possible to use this API to
// compute digests of policies with branches without having to use the [Policy] API to
// execute them, or to build policies with branches with low-level control of branch
// execution by manually executing a sequence of [Policy] instances. Applications that
// use [Policy] for execution should normally just make use of [PolicyBuilderBranch.AddBranchNode]
// and [PolicyBuilderBranchNode.AddBranch] for constructing policies with branches though.
func NewPolicyBuilderOR(alg tpm2.HashAlgorithmId, policies ...*Policy) *PolicyBuilder {
	b := NewPolicyBuilder()

	var pHashList tpm2.DigestList
	for i, policy := range policies {
		digest, err := policy.Digest(alg)
		if err != nil {
			b.fail("NewPolicyBuilderOR", fmt.Errorf("cannot add branch %d: %w", i, err))
			return b
		}
		pHashList = append(pHashList, digest)
	}

	element := &policyElement{
		Type: commandRawPolicyOR,
		Details: makePolicyElementDetails(
			policyRawORElement{HashList: pHashList},
		),
	}
	b.root.policyBranch.Policy = append(b.root.policyBranch.Policy, element)
	b.alg = alg

	return b
}

func (b *PolicyBuilder) fail(name string, err error) error {
	if !b.failed() {
		b.err = fmt.Errorf("encountered an error when calling %s: %w", name, err)
	}

	return err
}

func (b *PolicyBuilder) failed() bool { return b.err != nil }

// RootBranch returns the root branch associated with the policy that is being built.
func (b *PolicyBuilder) RootBranch() *PolicyBuilderBranch {
	return b.root
}

// Build builds the policy for the specified algorithm and returns the completed
// policy and digest. This will commit the current [PolicyBuilderBranchNode] to the
// root [PolicyBuilderBranch] if it hasn't been done already.
func (b *PolicyBuilder) Build(alg tpm2.HashAlgorithmId) (tpm2.Digest, *Policy, error) {
	if b.failed() {
		return nil, nil, fmt.Errorf("could not build policy: %w", b.err)
	}
	if b.alg != tpm2.HashAlgorithmNull && alg != b.alg {
		return nil, nil, fmt.Errorf("cannot build policy for algorithm %v", alg)
	}

	if err := b.root.commitCurrentBranchNode(); err != nil {
		return nil, nil, fmt.Errorf("cannot commit current branch node in root branch: %w", err)
	}

	// addDigest copies the policy structure
	policy := &Policy{policy: policy{Policy: b.root.policyBranch.Policy}}
	digest, err := policy.addDigest(alg, b.cpHashParams, b.nameHashParams)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot compute policy: %w", err)
	}

	return digest, policy, nil
}
