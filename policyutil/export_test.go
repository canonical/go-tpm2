// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import "github.com/canonical/go-tpm2"

var (
	NewPolicyOrTree              = newPolicyOrTree
	NewTrialPolicySessionContext = newTrialPolicySessionContext
)

type PcrValue = pcrValue
type PcrValueList = pcrValueList
type PolicyElements = policyElements
type PolicyOrTree = policyOrTree
type TaggedHash = taggedHash
type TaggedHashList = taggedHashList

func (n *policyOrNode) Parent() *policyOrNode {
	return n.parent
}

func (n *policyOrNode) Digests() tpm2.DigestList {
	return n.digests
}

func (t *PolicyOrTree) LeafNodes() []*policyOrNode {
	return t.leafNodes
}

func (t *PolicyOrTree) SelectBranch(i int) policyElements {
	return t.selectBranch(i)
}

func (p PolicyBranchPath) PopNextComponent() (next PolicyBranchPath, remaining PolicyBranchPath, err error) {
	return p.popNextComponent()
}

func NewMockPolicyNVElement(nvIndex tpm2.Handle, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyNV,
		Details: &policyElementDetails{
			NV: &policyNV{
				NvIndex:   nvIndex,
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
}

func NewMockPolicySecretElement(authObjectName tpm2.Name, policyRef tpm2.Nonce) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicySecret,
		Details: &policyElementDetails{
			Secret: &policySecret{
				AuthObjectName: authObjectName,
				PolicyRef:      policyRef}}}
}

func NewMockPolicySignedElement(authKey *tpm2.Public, policyRef tpm2.Nonce) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicySigned,
		Details: &policyElementDetails{
			Signed: &policySigned{
				AuthKey:   authKey,
				PolicyRef: policyRef}}}
}

func NewMockPolicyAuthValueElement() *policyElement {
	return &policyElement{
		Type:    tpm2.CommandPolicyAuthValue,
		Details: &policyElementDetails{AuthValue: new(policyAuthValue)}}
}

func NewMockPolicyCommandCodeElement(code tpm2.CommandCode) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyCommandCode,
		Details: &policyElementDetails{
			CommandCode: &policyCommandCode{CommandCode: code}}}
}

func NewMockPolicyCounterTimerElement(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyCounterTimer,
		Details: &policyElementDetails{
			CounterTimer: &policyCounterTimer{
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
}

func NewMockPolicyCpHashElement(digests taggedHashList) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyCpHash,
		Details: &policyElementDetails{
			CpHash: &policyCpHash{Digests: digests}}}
}

func NewMockPolicyNameHashElement(digests taggedHashList) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyNameHash,
		Details: &policyElementDetails{
			NameHash: &policyNameHash{Digests: digests}}}
}

func NewMockPolicyORElement(hashList []taggedHashList) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyOR,
		Details: &policyElementDetails{
			OR: &policyOR{HashList: hashList}}}
}

func NewMockPolicyBranch(name PolicyBranchName, digests taggedHashList, elements ...*policyElement) policyBranch {
	return policyBranch{
		Name:          name,
		PolicyDigests: digests,
		Policy:        elements}
}

func NewMockPolicyBranchNodeElement(branches ...policyBranch) *policyElement {
	return &policyElement{
		Type: commandPolicyBranchNode,
		Details: &policyElementDetails{
			BranchNode: &policyBranchNode{Branches: branches}}}
}

func NewMockPolicyPCRElement(pcrs PcrValueList) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyPCR,
		Details: &policyElementDetails{
			PCR: &policyPCR{PCRs: pcrs}}}
}

func NewMockPolicyDuplicationSelectElement(objectName, newParentName tpm2.Name, includeObject bool) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyDuplicationSelect,
		Details: &policyElementDetails{
			DuplicationSelect: &policyDuplicationSelect{
				Object:        objectName,
				NewParent:     newParentName,
				IncludeObject: includeObject}}}
}

func NewMockPolicyPasswordElement() *policyElement {
	return &policyElement{
		Type:    tpm2.CommandPolicyPassword,
		Details: &policyElementDetails{Password: new(policyPassword)}}
}

func NewMockPolicyNvWrittenElement(writtenSet bool) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyNvWritten,
		Details: &policyElementDetails{
			NvWritten: &policyNvWritten{WrittenSet: writtenSet}}}
}

func NewMockPolicy(elements ...*policyElement) *Policy {
	return &Policy{policy: policy{Policy: elements}}
}
