// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

type policyBuilderBranchRunner struct {
	policySession   *computePolicySession
	policyTickets   nullTickets
	policyResources mockPolicyResources
}

func (r *policyBuilderBranchRunner) session() policySession {
	return r.policySession
}

func (r *policyBuilderBranchRunner) tickets() policyTickets {
	return &r.policyTickets
}

func (r *policyBuilderBranchRunner) resources() policyResources {
	return &r.policyResources
}

func (r *policyBuilderBranchRunner) authResourceName() tpm2.Name {
	return nil
}

func (*policyBuilderBranchRunner) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewLimitedResourceContext(0x80000000, public.Name())
	return newResourceContext(resource, nil), nil
}

func (r *policyBuilderBranchRunner) authorize(auth ResourceContext, askForPolicy bool, usage *PolicySessionUsage, prefer tpm2.SessionType) (SessionContext, error) {
	return new(mockSessionContext), nil
}

func (r *policyBuilderBranchRunner) runBranch(branches policyBranches) (selected int, err error) {
	return 0, nil
}

func (r *policyBuilderBranchRunner) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*authorizedPolicy) (approvedPolicy tpm2.Digest, checkTicket *tpm2.TkVerified, err error) {
	return nil, nil, nil
}

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

func (n *PolicyBuilderBranchNode) alg() tpm2.HashAlgorithmId {
	return n.parentBranch.alg()
}

func (n *PolicyBuilderBranchNode) digest() (tpm2.Digest, error) {
	return n.parentBranch.digest()
}

func (n *PolicyBuilderBranchNode) commitBranchNode() error {
	if n.committed {
		return errors.New("internal error: branch node already committed")
	}
	n.committed = true

	var branches []*policyBranch
	for _, branch := range n.childBranches {
		if err := branch.lockBranch(); err != nil {
			return err
		}

		if len(branch.policyBranch.Policy) == 0 {
			// omit branches with no assertions
			continue
		}

		branches = append(branches, &branch.policyBranch)
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

	digest, err := n.digest()
	if err != nil {
		n.policy().fail("AddBranch", fmt.Errorf("internal error: %w", err))
	}

	b := newPolicyBuilderBranch(n.policy(), n.alg(), pbn, digest)
	n.childBranches = append(n.childBranches, b)
	return b
}

// PolicyBuilderBranch corresponds to a branch in a policy that is being computed.
type PolicyBuilderBranch struct {
	policy       *PolicyBuilder
	policyBranch policyBranch
	runner       policyBuilderBranchRunner

	parentIsEmpty bool

	currentBranchNode *PolicyBuilderBranchNode
	locked            bool
}

func newPolicyBuilderBranch(policy *PolicyBuilder, alg tpm2.HashAlgorithmId, name policyBranchName, digest tpm2.Digest) *PolicyBuilderBranch {
	out := &PolicyBuilderBranch{
		policy:       policy,
		policyBranch: policyBranch{Name: policyBranchName(name)},
		runner:       policyBuilderBranchRunner{policySession: newComputePolicySession(alg, digest, false)},
	}
	if len(digest) == 0 || bytes.Equal(digest, make(tpm2.Digest, alg.Size())) {
		out.parentIsEmpty = true
	}
	return out
}

func (b *PolicyBuilderBranch) alg() tpm2.HashAlgorithmId {
	return b.runner.session().HashAlg()
}

func (b *PolicyBuilderBranch) digest() (tpm2.Digest, error) {
	return b.runner.session().PolicyGetDigest()
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
			Details: &policyElementDetails{
				OR: &policyORElement{Branches: branches}}}
		if err := element.runner().run(&b.runner); err != nil {
			return err
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

	digest, err := b.digest()
	if err != nil {
		return fmt.Errorf("internal error: %w", err)
	}
	b.policyBranch.PolicyDigests = taggedHashList{{HashAlg: b.alg(), Digest: digest}}
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
func (b *PolicyBuilderBranch) PolicyNV(nvIndex *tpm2.NVPublic, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyNV", err)
	}

	if !nvIndex.Name().IsValid() {
		return nil, b.policy.fail("PolicyNV", errors.New("invalid nvIndex"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNV,
		Details: &policyElementDetails{
			NV: &policyNVElement{
				NvIndex:   nvIndex,
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyNV", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyNV", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicySecret adds a TPM2_PolicySecret assertion to this branch so that the policy requires
// knowledge of the authorization value of the object associated with authObject.
func (b *PolicyBuilderBranch) PolicySecret(authObject Named, policyRef tpm2.Nonce) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicySecret", err)
	}

	authObjectName := authObject.Name()
	if len(authObjectName) == 0 || !authObjectName.IsValid() {
		return nil, b.policy.fail("PolicySecret", errors.New("invalid authObject name"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicySecret,
		Details: &policyElementDetails{
			Secret: &policySecretElement{
				AuthObjectName: authObjectName,
				PolicyRef:      policyRef}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicySecret", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicySecret", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicySigned adds a TPM2_PolicySigned assertion to this branch so that the policy requires
// an assertion signed by the owner of the supplied key.
func (b *PolicyBuilderBranch) PolicySigned(authKey *tpm2.Public, policyRef tpm2.Nonce) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicySigned", err)
	}

	authKeyName := authKey.Name()
	if len(authKeyName) == 0 || !authKeyName.IsValid() {
		return nil, b.policy.fail("PolicySigned", errors.New("invalid authKey"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicySigned,
		Details: &policyElementDetails{
			Signed: &policySignedElement{
				AuthKey:   authKey,
				PolicyRef: policyRef}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicySigned", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicySigned", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyAuthorize adds a TPM2_PolicyAuthorize assertion to this branch so that the policy
// can be changed by allowing the authorizing entity to sign new policies.
//
// When [Policy.Execute] runs this assertion, it will select an execute an appropriate
// authorized policy.
//
// This assertion must come before any other assertions in a policy. Whilst this is not
// a limitation of how this works on the TPM, the [Policy.Authorize] and [Policy.Execute]
// APIs currently do not support authorized policies with a non-empty starting digest.
func (b *PolicyBuilderBranch) PolicyAuthorize(policyRef tpm2.Nonce, keySign *tpm2.Public) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyAuthorize", err)
	}

	if !b.parentIsEmpty || len(b.policyBranch.Policy) > 0 {
		return nil, b.policy.fail("PolicyAuthorize", errors.New("must be before any other assertions"))
	}

	keySignName := keySign.Name()
	if !keySignName.IsValid() {
		return nil, b.policy.fail("PolicyAuthorize", errors.New("invalid keySign"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyAuthorize,
		Details: &policyElementDetails{
			Authorize: &policyAuthorizeElement{
				PolicyRef: policyRef,
				KeySign:   keySign}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyAuthorize", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyAuthorize", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyAuthValue adds a TPM2_PolicyAuthValue assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyBuilderBranch) PolicyAuthValue() (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyAuthValue", err)
	}

	element := &policyElement{
		Type:    tpm2.CommandPolicyAuthValue,
		Details: &policyElementDetails{AuthValue: new(policyAuthValueElement)}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyAuthValue", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyAuthValue", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyCommandCode adds a TPM2_PolicyCommandCode assertion to this branch to bind the policy
// to the specified command.
func (b *PolicyBuilderBranch) PolicyCommandCode(code tpm2.CommandCode) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyCommandCode", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCommandCode,
		Details: &policyElementDetails{
			CommandCode: &policyCommandCodeElement{CommandCode: code}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyAuthValue", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyCommandCode", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyCounterTimer adds a TPM2_PolicyCounterTimer assertion to this branch to bind the policy
// to the contents of the [tpm2.TimeInfo] structure.
func (b *PolicyBuilderBranch) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyCounterTimer", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCounterTimer,
		Details: &policyElementDetails{
			CounterTimer: &policyCounterTimerElement{
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyCounterTimer", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyCounterTimer", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyCpHash adds a TPM2_PolicyCpHash assertion to this branch in order to bind the policy to
// the supplied command parameters.
//
// As this binds the authorization to an object and and a policy has to have the same algorithm as
// this, policies with this assertion can only be computed for a single digest algorithm.
func (b *PolicyBuilderBranch) PolicyCpHash(code tpm2.CommandCode, handles []Named, params ...interface{}) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyCpHash", err)
	}

	cpHash, err := ComputeCpHash(b.alg(), code, handles, params...)
	if err != nil {
		return nil, b.policy.fail("PolicyCpHash", fmt.Errorf("cannot compute cpHashA: %w", err))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyCpHash,
		Details: &policyElementDetails{
			CpHash: &policyCpHashElement{Digest: cpHash}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyCpHash", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyCpHash", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyNameHash adds a TPM2_PolicyNameHash assertion to this branch in order to bind the policy to
// the supplied command handles.
//
// As this binds the authorization to an object and and a policy has to have the same algorithm as
// this, policies with this assertion can only be computed for a single digest algorithm.
func (b *PolicyBuilderBranch) PolicyNameHash(handles ...Named) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyNameHash", err)
	}

	nameHash, err := ComputeNameHash(b.alg(), handles...)
	if err != nil {
		return nil, b.policy.fail("PolicyNameHash", fmt.Errorf("cannot compute nameHash: %w", err))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNameHash,
		Details: &policyElementDetails{
			NameHash: &policyNameHashElement{Digest: nameHash}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyNameHash", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyNameHash", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyPCR adds a TPM2_PolicyPCR assertion to this branch in order to bind the policy to the
// supplied PCR values.
func (b *PolicyBuilderBranch) PolicyPCR(values tpm2.PCRValues) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyPCR", err)
	}

	var pcrs pcrValueList
	for alg := range values {
		if !alg.IsValid() {
			return nil, b.policy.fail("PolicyPCR", fmt.Errorf("invalid digest algorithm %v", alg))
		}
		for pcr := range values[alg] {
			s := tpm2.PCRSelect{pcr}
			if _, err := s.ToBitmap(0); err != nil {
				return nil, b.policy.fail("PolicyPCR", fmt.Errorf("invalid PCR %v: %w", pcr, err))
			}
			digest := values[alg][pcr]
			if len(digest) != alg.Size() {
				return nil, b.policy.fail("PolicyPCR", fmt.Errorf("invalid digest size for PCR %v, algorithm %v", pcr, alg))
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
			PCR: &policyPCRElement{PCRs: pcrs}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyPCR", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyPCR", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyDuplicationSelect adds a TPM2_PolicyDuplicationSelect assertion to this branch in order
// to permit duplication of object to newParent with the [tpm2.TPMContext.Duplicate] function.
// If includeObject is true, then the assertion is bound to both object and newParent. If
// includeObject is false then the assertion is only bound to newParent. In this case, supplying
// object is optional. Note that when the TPM2_PolicyDuplicationSelect assertions is executed,
// the object name must be supplied because the assertion sets the name hash of the session. If
// object is supplied here, then it will be included in the policy and used when the assertion is
// executed. If it isn't supplied here, then it will be obtained from the [PolicySessionUsage]
// supplied to [Policy.Execute].
func (b *PolicyBuilderBranch) PolicyDuplicationSelect(object, newParent Named, includeObject bool) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyDuplicationSelect", err)
	}

	var objectName tpm2.Name
	if object != nil {
		objectName = object.Name()
	}
	if (includeObject && len(objectName) == 0) || !objectName.IsValid() {
		return nil, b.policy.fail("PolicyDuplicationSelect", errors.New("invalid object name"))
	}

	var newParentName tpm2.Name
	if newParent != nil {
		newParentName = newParent.Name()
	}
	if len(newParentName) == 0 || !newParentName.IsValid() {
		return nil, b.policy.fail("PolicyDuplicationSelect", errors.New("invalid newParent name"))
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyDuplicationSelect,
		Details: &policyElementDetails{
			DuplicationSelect: &policyDuplicationSelectElement{
				Object:        objectName,
				NewParent:     newParentName,
				IncludeObject: includeObject}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyDuplicationSelect", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyDuplicationSelect", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyPassword adds a TPM2_PolicyPassword assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyBuilderBranch) PolicyPassword() (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyPassword", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyPassword,
		Details: &policyElementDetails{
			Password: new(policyPasswordElement)}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyPassword", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyPassword", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyNvWritten adds a TPM2_PolicyNvWritten assertion to this branch in order to bind the
// policy to the status of the [tpm2.AttrNVWritten] attribute for the NV index on which the
// session is used.
func (b *PolicyBuilderBranch) PolicyNvWritten(writtenSet bool) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyNvWritten", err)
	}

	element := &policyElement{
		Type: tpm2.CommandPolicyNvWritten,
		Details: &policyElementDetails{
			NvWritten: &policyNvWrittenElement{WrittenSet: writtenSet}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyNvWritten", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyNvWritten", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// PolicyOR adds a TPM2_PolicyOR assertion to this branch for low-level control of policies
// that can be satisfied with different sets of conditions. This is to makeit possible to
// use this API to compute digests of policies with branches without having to use the
// [Policy] API to execute them, or to build policies with branches with low-level control
// of branch execution by manually executing a sequence of [Policy] instances corresponding
// to each branch.  Applications that use [Policy] for execution should normally just make
// use of [PolicyBuilderBranch.AddBranchNode] and [PolicyBuilderBranchNode.AddBranch] for
// constructing policies with branches though.
func (b *PolicyBuilderBranch) PolicyOR(pHashList ...tpm2.Digest) (tpm2.Digest, error) {
	if err := b.prepareToModifyBranch(); err != nil {
		return nil, b.policy.fail("PolicyOR", err)
	}

	if len(pHashList) < 2 || len(pHashList) > 8 {
		return nil, b.policy.fail("PolicyOR", errors.New("invalid number of digests"))
	}
	for i, digest := range pHashList {
		if len(digest) != b.alg().Size() {
			return nil, b.policy.fail("PolicyOR", fmt.Errorf("digest at index %d has the wrong size", i))
		}
	}

	element := &policyElement{
		Type: commandRawPolicyOR,
		Details: &policyElementDetails{
			RawOR: &policyRawORElement{HashList: pHashList}}}
	if err := element.runner().run(&b.runner); err != nil {
		return nil, b.policy.fail("PolicyOR", fmt.Errorf("internal error: %w", err))
	}
	b.policyBranch.Policy = append(b.policyBranch.Policy, element)

	digest, err := b.runner.session().PolicyGetDigest()
	if err != nil {
		return nil, b.policy.fail("PolicyOR", fmt.Errorf("internal error: %w", err))
	}
	return digest, nil
}

// AddBranchNode adds a branch node to this branch from which sub-branches can be added.
// This makes it possible to create policies that can be satisified with different sets of
// conditions. One of the sub-branches will be selected during execution, and will be
// executed before the remaining assertions in this branch.
//
// The branches added to the returned branch node will be committed to this branch and
// the branch node will be locked from further modifications by subsequent additions to this
// branch, or any ancestor branches, or by calling [PolicyBuilder.Policy] or
// [PolicyBuilder.Digest]. This ensures that branches can only append to a policy with
// the [PolicyBuilder] API.
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
// The PolicyBuilder instance will be marked as failed whenever an error occurs. This means
// that it isn't necessary to check errors for every call. In the event of an earlier
// error, calls to [PolicyBuilder.Policy] and [PolicyBuilder.Digest] will return an error.
//
// XXX: Note that the PolicyBuilder API may change.
type PolicyBuilder struct {
	root *PolicyBuilderBranch
	err  error
}

// NewPolicyBuilder returns a new PolicyBuilder.
func NewPolicyBuilder(alg tpm2.HashAlgorithmId) *PolicyBuilder {
	if !alg.Available() {
		panic("invalid algorithm")
	}
	b := new(PolicyBuilder)
	b.root = newPolicyBuilderBranch(b, alg, "", nil)
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
	b := NewPolicyBuilder(alg)

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
		Details: &policyElementDetails{
			RawOR: &policyRawORElement{
				HashList: pHashList,
			}}}
	if err := element.runner().run(&b.root.runner); err != nil {
		b.fail("PolicyOR", err)
	}
	b.root.policyBranch.Policy = append(b.root.policyBranch.Policy, element)

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

// Digest returns the current digest. This will commit the current
// [PolicyBuilderBranchNode] to the root [PolicyBuilderBranch] if it hasn't been
// done already.
//
// This will return an error if any call when building the policy failed.
func (b *PolicyBuilder) Digest() (tpm2.Digest, error) {
	if b.failed() {
		return nil, fmt.Errorf("could not build policy: %w", b.err)
	}

	if err := b.root.commitCurrentBranchNode(); err != nil {
		return nil, fmt.Errorf("cannot commit current branch node in root branch: %w", err)
	}

	digest, err := b.root.digest()
	if err != nil {
		return nil, fmt.Errorf("internal error: %w", err)
	}

	return digest, nil
}

// Policy returns the current policy and digest. This will commit the current
// [PolicyBuilderBranchNode] to the root [PolicyBuilderBranch] if it hasn't been
// done already.
//
// This will return an error if any call when building the policy failed.
func (b *PolicyBuilder) Policy() (tpm2.Digest, *Policy, error) {
	if b.failed() {
		return nil, nil, fmt.Errorf("could not build policy: %w", b.err)
	}

	if err := b.root.commitCurrentBranchNode(); err != nil {
		return nil, nil, fmt.Errorf("cannot commit current branch node in root branch: %w", err)
	}

	digest, err := b.root.digest()
	if err != nil {
		return nil, nil, fmt.Errorf("internal error: %w", err)
	}

	policy := &Policy{
		policy: policy{
			PolicyDigests: taggedHashList{{HashAlg: b.root.alg(), Digest: digest}},
			Policy:        b.root.policyBranch.Policy,
		},
	}
	if err := mu.CopyValue(&policy, policy); err != nil {
		return nil, nil, fmt.Errorf("cannot copy policy metadata: %w", err)
	}

	return digest, policy, nil
}
