// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import "github.com/canonical/go-tpm2"

var (
	NewPolicyOrTree         = newPolicyOrTree
	NewComputePolicySession = newComputePolicySession
)

type PcrValue = pcrValue
type PcrValueList = pcrValueList
type PolicyBranchName = policyBranchName
type PolicyBranchPath = policyBranchPath
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

func (t *PolicyOrTree) SelectBranch(i int) []tpm2.DigestList {
	return t.selectBranch(i)
}

func NewMockPolicyNVElement(nvIndex *tpm2.NVPublic, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyNV,
		Details: &policyElementDetails{
			NV: &policyNVElement{
				NvIndex:   nvIndex,
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
}

func NewMockPolicySecretElement(authObjectName tpm2.Name, policyRef tpm2.Nonce) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicySecret,
		Details: &policyElementDetails{
			Secret: &policySecretElement{
				AuthObjectName: authObjectName,
				PolicyRef:      policyRef}}}
}

func NewMockPolicySignedElement(authKey *tpm2.Public, policyRef tpm2.Nonce) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicySigned,
		Details: &policyElementDetails{
			Signed: &policySignedElement{
				AuthKey:   authKey,
				PolicyRef: policyRef}}}
}

func NewMockPolicyAuthorizeElement(policyRef tpm2.Nonce, keySign *tpm2.Public) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyAuthorize,
		Details: &policyElementDetails{
			Authorize: &policyAuthorizeElement{
				PolicyRef: policyRef,
				KeySign:   keySign}}}
}

func NewMockPolicyAuthValueElement() *policyElement {
	return &policyElement{
		Type:    tpm2.CommandPolicyAuthValue,
		Details: &policyElementDetails{AuthValue: new(policyAuthValueElement)}}
}

func NewMockPolicyCommandCodeElement(code tpm2.CommandCode) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyCommandCode,
		Details: &policyElementDetails{
			CommandCode: &policyCommandCodeElement{CommandCode: code}}}
}

func NewMockPolicyCounterTimerElement(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyCounterTimer,
		Details: &policyElementDetails{
			CounterTimer: &policyCounterTimerElement{
				OperandB:  operandB,
				Offset:    offset,
				Operation: operation}}}
}

func NewMockPolicyCpHashElement(digest tpm2.Digest) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyCpHash,
		Details: &policyElementDetails{
			CpHash: &policyCpHashElement{
				Digest: digest}}}
}

func NewMockPolicyNameHashElement(digest tpm2.Digest) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyNameHash,
		Details: &policyElementDetails{
			NameHash: &policyNameHashElement{
				Digest: digest}}}
}

func NewMockPolicyBranch(name policyBranchName, digests taggedHashList, elements ...*policyElement) *policyBranch {
	return &policyBranch{
		Name:          name,
		PolicyDigests: digests,
		Policy:        elements}
}

func NewMockPolicyORElement(branches ...*policyBranch) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyOR,
		Details: &policyElementDetails{
			OR: &policyORElement{Branches: branches}}}
}

func NewMockPolicyPCRElement(pcrs PcrValueList) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyPCR,
		Details: &policyElementDetails{
			PCR: &policyPCRElement{PCRs: pcrs}}}
}

func NewMockPolicyPCRDigestElement(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) *policyElement {
	return &policyElement{
		Type: commandPolicyPCRDigest,
		Details: &policyElementDetails{
			PCRDigest: &policyPCRDigestElement{
				PCRDigest: pcrDigest,
				PCRs:      pcrs}}}
}

func NewMockPolicyDuplicationSelectElement(objectName, newParentName tpm2.Name, includeObject bool) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyDuplicationSelect,
		Details: &policyElementDetails{
			DuplicationSelect: &policyDuplicationSelectElement{
				Object:        objectName,
				NewParent:     newParentName,
				IncludeObject: includeObject}}}
}

func NewMockPolicyPasswordElement() *policyElement {
	return &policyElement{
		Type:    tpm2.CommandPolicyPassword,
		Details: &policyElementDetails{Password: new(policyPasswordElement)}}
}

func NewMockPolicyNvWrittenElement(writtenSet bool) *policyElement {
	return &policyElement{
		Type: tpm2.CommandPolicyNvWritten,
		Details: &policyElementDetails{
			NvWritten: &policyNvWrittenElement{WrittenSet: writtenSet}}}
}

func NewMockPolicyRawORElement(pHashList tpm2.DigestList) *policyElement {
	return &policyElement{
		Type: commandRawPolicyOR,
		Details: &policyElementDetails{
			RawOR: &policyRawORElement{HashList: pHashList}}}
}

func NewMockPolicy(digests taggedHashList, authorizations []PolicyAuthorization, elements ...*policyElement) *Policy {
	return &Policy{
		policy: policy{
			PolicyDigests:        digests,
			PolicyAuthorizations: authorizations,
			Policy:               elements,
		},
	}
}
