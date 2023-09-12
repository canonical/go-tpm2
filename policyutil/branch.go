// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

const (
	// policyOrMaxDigests sets a reasonable limit on the maximum number of or
	// digests.
	policyOrMaxDigests = 4096 // equivalent to a depth of 4
)

// ensureSufficientORDigests turns a single digest in to a pair of identical digests.
// This is because TPM2_PolicyOR assertions require more than one digest. This avoids
// having a separate policy sequence when there is only a single digest, without having
// to store duplicate digests on disk.
func ensureSufficientORDigests(digests tpm2.DigestList) tpm2.DigestList {
	if len(digests) == 1 {
		return tpm2.DigestList{digests[0], digests[0]}
	}
	return digests
}

type policyOrNode struct {
	parent  *policyOrNode
	digests tpm2.DigestList
}

type policyOrTree struct {
	alg       tpm2.HashAlgorithmId
	leafNodes []*policyOrNode
}

func newPolicyOrTree(alg tpm2.HashAlgorithmId, digests tpm2.DigestList) (out *policyOrTree, err error) {
	if len(digests) == 0 {
		return nil, errors.New("no digests")
	}
	if len(digests) > policyOrMaxDigests {
		return nil, errors.New("too many digests")
	}

	var prev []*policyOrNode

	for len(prev) != 1 {
		// The outer loop runs on each level of the tree. If
		// len(prev) == 1, then we have produced the root node
		// and the loop should not continue.

		var current []*policyOrNode
		var nextDigests tpm2.DigestList

		for len(digests) > 0 {
			// The inner loop runs on each sibling node within a level.

			n := len(digests)
			if n > 8 {
				// The TPM only supports 8 conditions in TPM2_PolicyOR.
				n = 8
			}

			// Create a new node with the next n digests and save it.
			node := &policyOrNode{digests: ensureSufficientORDigests(digests[:n])}
			current = append(current, node)

			// Consume the next n digests to fit in to this node and produce a single digest
			// that will go in to the parent node.
			trial := newComputePolicySession(&taggedHash{HashAlg: alg, Digest: make(tpm2.Digest, alg.Size())})
			trial.PolicyOR(node.digests)
			nextDigests = append(nextDigests, trial.digest.Digest)

			// We've consumed n digests, so adjust the slice to point to the next ones to consume to
			// produce a sibling node.
			digests = digests[n:]
		}

		// There are no digests left to produce sibling nodes.
		// Link child nodes to parents.
		for i, child := range prev {
			child.parent = current[i>>3]
		}

		// Grab the digests for the nodes we've just produced to create the parent nodes.
		prev = current
		digests = nextDigests

		if out == nil {
			// Save the leaf nodes to return.
			out = &policyOrTree{
				alg:       alg,
				leafNodes: current,
			}
		}
	}

	return out, nil
}

func (t *policyOrTree) selectBranch(i int) (out []tpm2.DigestList) {
	node := t.leafNodes[i>>3]

	for node != nil {
		out = append(out, ensureSufficientORDigests(node.digests))
		node = node.parent
	}

	return out
}

type policyBranchSelectMixin struct{}

func (*policyBranchSelectMixin) selectBranch(branches policyBranches, next policyBranchPath) (int, error) {
	switch {
	case strings.HasPrefix(string(next), "…"):
		return 0, fmt.Errorf("cannot select branch: invalid component \"%s\"", next)
	case next[0] == '$':
		// select branch by index
		var selected int
		if _, err := fmt.Sscanf(string(next), "$[%d]", &selected); err != nil {
			return 0, fmt.Errorf("cannot select branch: badly formatted path component \"%s\": %w", next, err)
		}
		if selected < 0 || selected >= len(branches) {
			return 0, fmt.Errorf("cannot select branch: selected path %d out of range", selected)
		}
		return selected, nil
	default:
		// select branch by name
		for i, branch := range branches {
			if len(branch.Name) == 0 {
				continue
			}
			if policyBranchPath(branch.Name) == next {
				return i, nil
			}
		}
		return 0, fmt.Errorf("cannot select branch: no branch with name \"%s\"", next)
	}
}

type candidateBranch struct {
	path    policyBranchPath
	details PolicyBranchDetails
}

type policyBranchFilter struct {
	mockResources

	sessionAlg tpm2.HashAlgorithmId
	params     policyParams
	resources  policyResources
	tpm        tpmConnection
	usage      *PolicySessionUsage

	paths      []policyBranchPath
	detailsMap map[policyBranchPath]PolicyBranchDetails
}

func newPolicyBranchFilter(sessionAlg tpm2.HashAlgorithmId, params policyParams, resources policyResources, tpm tpmConnection, usage *PolicySessionUsage) *policyBranchFilter {
	return &policyBranchFilter{
		sessionAlg: sessionAlg,
		params:     params,
		resources:  resources,
		tpm:        tpm,
		usage:      usage,
	}
}

func (f *policyBranchFilter) filterInvalidBranches() {
	for p, r := range f.detailsMap {
		if r.IsValid() {
			continue
		}
		delete(f.detailsMap, p)
	}
}

func (f *policyBranchFilter) filterMissingAuthBranches() {
	for p, r := range f.detailsMap {
		missing := false
		for _, signed := range r.Signed {
			auth := f.params.signedAuthorization(signed.AuthName, signed.PolicyRef)
			ticket := f.params.ticket(signed.AuthName, signed.PolicyRef)
			if auth == nil && ticket == nil {
				missing = true
				break
			}
		}
		if !missing {
			for _, auth := range r.Authorize {
				policies, err := f.resources.LoadAuthorizedPolicies(auth.AuthName, auth.PolicyRef)
				if err != nil || len(policies) == 0 {
					missing = true
					break
				}
			}
		}
		if missing {
			delete(f.detailsMap, p)
		}
	}
}

func (f *policyBranchFilter) filterUsageIncompatibleBranches() error {
	if f.usage == nil {
		return nil
	}

	for p, r := range f.detailsMap {
		code, set := r.CommandCode()
		if set && code != f.usage.commandCode {
			delete(f.detailsMap, p)
			continue
		}

		cpHash, set := r.CpHash()
		if set {
			d, err := ComputeCpHash(f.sessionAlg, f.usage.commandCode, f.usage.handles, f.usage.params...)
			if err != nil {
				return fmt.Errorf("cannot obtain cpHash from usage parameters: %w", err)
			}
			if !bytes.Equal(d, cpHash) {
				delete(f.detailsMap, p)
				continue
			}
		}

		nameHash, set := r.NameHash()
		if set {
			d, err := ComputeNameHash(f.sessionAlg, f.usage.handles...)
			if err != nil {
				return fmt.Errorf("cannot obtain nameHash from usage parameters: %w", err)
			}
			if !bytes.Equal(d, nameHash) {
				delete(f.detailsMap, p)
				continue
			}
		}

		nvWritten, set := r.NvWritten()
		if set && f.usage.nvHandle.Type() == tpm2.HandleTypeNVIndex {
			pub, err := f.tpm.NVReadPublic(f.usage.nvHandle)
			if err != nil {
				return fmt.Errorf("cannot obtain NV index public area: %w", err)
			}
			written := pub.Attrs&tpm2.AttrNVWritten != 0
			if nvWritten != written {
				delete(f.detailsMap, p)
				continue
			}
		}
	}

	return nil
}

func (f *policyBranchFilter) filterPcrIncompatibleBranches() error {
	var pcrs tpm2.PCRSelectionList
	for p, r := range f.detailsMap {
		var err error
		for _, item := range r.PCR {
			var tmpPcrs tpm2.PCRSelectionList
			tmpPcrs, err = pcrs.Merge(item.PCRs)
			if err != nil {
				break
			}
			pcrs = tmpPcrs
		}
		if err != nil {
			delete(f.detailsMap, p)
		}
	}

	if pcrs.IsEmpty() {
		return nil
	}

	pcrValues, err := f.tpm.PCRRead(pcrs)
	if err != nil {
		return fmt.Errorf("cannot obtain PCR values: %w", err)
	}

	for p, r := range f.detailsMap {
		incompatible := false
		for _, item := range r.PCR {
			pcrDigest, err := ComputePCRDigest(f.sessionAlg, item.PCRs, pcrValues)
			if err != nil {
				return fmt.Errorf("cannot compute PCR digest: %w", err)
			}
			if !bytes.Equal(pcrDigest, item.PCRDigest) {
				incompatible = true
				break
			}
		}
		if incompatible {
			delete(f.detailsMap, p)
		}
	}

	return nil
}

func (r *policyBranchFilter) bufferMatch(operandA, operandB tpm2.Operand, operation tpm2.ArithmeticOp) bool {
	if len(operandA) != len(operandB) {
		panic("mismatched operand sizes")
	}

	switch operation {
	case tpm2.OpEq:
		return bytes.Equal(operandA, operandB)
	case tpm2.OpNeq:
		return !bytes.Equal(operandA, operandB)
	case tpm2.OpSignedGT:
		switch {
		case len(operandA) == 0:
			return false
		case (operandA[0]^operandB[0])&0x80 > 0:
			return operandA[0]&0x80 == 0
		default:
			return bytes.Compare(operandA, operandB) > 0
		}
	case tpm2.OpUnsignedGT:
		return bytes.Compare(operandA, operandB) > 0
	case tpm2.OpSignedLT:
		switch {
		case len(operandA) == 0:
			return false
		case (operandA[0]^operandB[0])&0x80 > 0:
			return operandA[0]&0x80 > 0
		default:
			return bytes.Compare(operandA, operandB) < 0
		}
	case tpm2.OpUnsignedLT:
		return bytes.Compare(operandA, operandB) < 0
	case tpm2.OpSignedGE:
		switch {
		case len(operandA) == 0:
			return true
		case (operandA[0]^operandB[0])&0x80 > 0:
			return operandA[0]&0x80 == 0
		default:
			return bytes.Compare(operandA, operandB) >= 0
		}
	case tpm2.OpUnsignedGE:
		return bytes.Compare(operandA, operandB) >= 0
	case tpm2.OpSignedLE:
		switch {
		case len(operandA) == 0:
			return true
		case (operandA[0]^operandB[0])&0x80 > 0:
			return operandA[0]&0x80 > 0
		default:
			return bytes.Compare(operandA, operandB) <= 0
		}
	case tpm2.OpUnsignedLE:
		return bytes.Compare(operandA, operandB) <= 0
	case tpm2.OpBitset:
		for i := range operandA {
			if operandA[i]&operandB[i] != operandB[i] {
				return false
			}
		}
		return true
	case tpm2.OpBitclear:
		for i := range operandA {
			if operandA[i]&operandB[i] > 0 {
				return false
			}
		}
		return true
	default:
		panic("not reached")
	}
}

func (f *policyBranchFilter) filterCounterTimerIncompatibleBranches() error {
	hasCounterTimerAssertions := false
	for _, r := range f.detailsMap {
		if len(r.CounterTimer) > 0 {
			hasCounterTimerAssertions = true
			break
		}
	}

	if !hasCounterTimerAssertions {
		return nil
	}

	timeInfo, err := f.tpm.ReadClock()
	if err != nil {
		return fmt.Errorf("cannot obtain time info: %w", err)
	}

	timeInfoData, err := mu.MarshalToBytes(timeInfo)
	if err != nil {
		return fmt.Errorf("cannot marshal time info: %w", err)
	}

	for p, r := range f.detailsMap {
		incompatible := false
		for _, item := range r.CounterTimer {
			if int(item.Offset) > len(timeInfoData) {
				incompatible = true
				break
			}
			if int(item.Offset)+len(item.OperandB) > len(timeInfoData) {
				incompatible = true
				break
			}

			operandA := timeInfoData[int(item.Offset) : int(item.Offset)+len(item.OperandB)]
			operandB := item.OperandB

			if !f.bufferMatch(operandA, operandB, item.Operation) {
				incompatible = true
				break
			}
		}

		if incompatible {
			delete(f.detailsMap, p)
		}
	}

	return nil
}

func (f *policyBranchFilter) filterBranches(branches policyBranches) ([]candidateBranch, error) {
	// reset state
	f.paths = nil
	f.detailsMap = make(map[policyBranchPath]PolicyBranchDetails)

	var (
		currentPath    policyBranchPath
		currentDetails PolicyBranchDetails
	)

	var walker *treeWalker
	walker = newTreeWalker(
		&observingPolicySession{session: newNullPolicySession(f.sessionAlg), details: &currentDetails},
		f,
		func() (treeWalkerBeginBranchFn, error) {
			details := currentDetails
			path := currentPath

			return func(name policyBranchPath) error {
				currentPath = path.Concat(name)
				currentDetails = details
				walker.runner.setSession(&observingPolicySession{session: newNullPolicySession(f.sessionAlg), details: &currentDetails})
				return nil
			}, nil
		},
		nil,
		func() error {
			f.detailsMap[currentPath] = currentDetails
			f.paths = append(f.paths, currentPath)
			return nil
		})
	if err := walker.run(policyElements{
		&policyElement{
			Type: tpm2.CommandPolicyOR,
			Details: &policyElementDetails{
				OR: &policyORElement{Branches: branches},
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("cannot perform tree walk: %w", err)
	}

	f.filterInvalidBranches()
	f.filterMissingAuthBranches()
	if err := f.filterUsageIncompatibleBranches(); err != nil {
		return nil, fmt.Errorf("cannot filter branches incompatible with usage: %w", err)
	}
	if err := f.filterPcrIncompatibleBranches(); err != nil {
		return nil, fmt.Errorf("cannot filter branches incompatible with TPM2_PolicyPCR assertions: %w", err)
	}
	if err := f.filterCounterTimerIncompatibleBranches(); err != nil {
		return nil, fmt.Errorf("cannot filter branches incompatible with TPM2_PolicyCounterTimer assertions: %w", err)
	}

	var result []candidateBranch
	for _, path := range f.paths {
		details, exists := f.detailsMap[path]
		if !exists {
			continue
		}
		result = append(result, candidateBranch{path: path, details: details})
	}
	return result, nil
}

func (r *policyBranchFilter) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return r.resources.LoadAuthorizedPolicies(keySign, policyRef)
}

var errTreeWalkerSkipBranch = errors.New("")

type (
	treeWalkerBeginBranchNodeFn func() (treeWalkerBeginBranchFn, error)
	treeWalkerBeginBranchFn     func(policyBranchPath) error
	treeWalkerCompleteBranchFn  func() error
)

type treeWalkerHelper struct {
	sessionAlg tpm2.HashAlgorithmId
	controller policyRunnerController

	beginBranchNodeFn treeWalkerBeginBranchNodeFn
	beginAuthorizedFn treeWalkerBeginBranchNodeFn
	completeBranchFn  treeWalkerCompleteBranchFn

	started          bool
	beginBranchQueue []taskFn
}

func newTreeWalkerHelper(runner *policyRunner, beginBranchNode, beginAuthorized treeWalkerBeginBranchNodeFn, completeBranch treeWalkerCompleteBranchFn) *treeWalkerHelper {
	if beginAuthorized == nil {
		beginAuthorized = beginBranchNode
	}
	return &treeWalkerHelper{
		sessionAlg:        runner.session().HashAlg(),
		controller:        runner,
		beginBranchNodeFn: beginBranchNode,
		beginAuthorizedFn: beginAuthorized,
		completeBranchFn:  completeBranch,
	}
}

func (h *treeWalkerHelper) pushNextBranchWalk() {
	done := len(h.beginBranchQueue) == 0
	switch done {
	case false:
		task := h.beginBranchQueue[0]
		h.beginBranchQueue = h.beginBranchQueue[1:]
		h.controller.pushTasks(task)
	case true:
		h.started = false
	}
}

func (h *treeWalkerHelper) walkBranch(parentPath policyBranchPath, beginBranchFn treeWalkerBeginBranchFn, index int, branch *policyBranch, restoreTasks func()) error {
	if beginBranchFn != nil {
		name := policyBranchPath(branch.Name)
		if len(name) == 0 {
			name = policyBranchPath(fmt.Sprintf("$[%d]", index))
		}
		if err := beginBranchFn(name); err != nil {
			if err == errTreeWalkerSkipBranch {
				h.pushNextBranchWalk()
				return nil
			}
			return fmt.Errorf("cannot begin walk branch: %w", err)
		}
		h.controller.setCurrentPath(parentPath.Concat(name))
	}

	restoreTasks()
	h.controller.pushElements(branch.Policy)
	return nil
}

func (h *treeWalkerHelper) cpHash(cpHash *policyCpHashElement) error {
	return nil
}

func (h *treeWalkerHelper) nameHash(nameHash *policyNameHashElement) error {
	return nil
}

func (h *treeWalkerHelper) handleBranches(branches policyBranches, complete func(tpm2.DigestList, int) error) error {
	if len(branches) == 0 {
		return errors.New("branch node with no branches")
	}

	restoreTasks, numOfTasks := h.controller.snapshotTasks()
	currentPath := h.controller.currentPath()

	if !h.started {
		if len(branches) != 1 || numOfTasks != 0 {
			return errors.New("internal error: inconsistent starting state")
		}
		if len(h.beginBranchQueue) != 0 {
			return errors.New("internal error: unexpected state")
		}

		h.controller.appendTask(func() error {
			if err := h.completeBranchFn(); err != nil {
				return fmt.Errorf("cannot complete walk branch: %w", err)
			}
			h.pushNextBranchWalk()
			return nil
		})
		restoreTasks, _ = h.controller.snapshotTasks()
	}

	h.controller.clearTasks()

	var beginBranchFn treeWalkerBeginBranchFn
	if h.started {
		var err error
		beginBranchFn, err = h.beginBranchNodeFn()
		if err != nil {
			return fmt.Errorf("cannot begin walk branch node: %w", err)
		}
	}

	var tasks []taskFn
	for i, branch := range branches {
		i := i
		branch := branch
		tasks = append(tasks, func() error {
			return h.walkBranch(currentPath, beginBranchFn, i, branch, restoreTasks)
		})
	}

	h.beginBranchQueue = append(tasks, h.beginBranchQueue...)

	// run the first branch
	h.pushNextBranchWalk()

	h.started = true
	return nil
}

func (h *treeWalkerHelper) handleAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*Policy, complete func(tpm2.Digest, *tpm2.TkVerified) error) error {
	h.controller.pushTasks(func() error {
		if err := complete(nil, nil); err != nil {
			return fmt.Errorf("cannot complete: %w", err)
		}
		return nil
	})

	restoreTasks, _ := h.controller.snapshotTasks()
	h.controller.clearTasks()
	currentPath := h.controller.currentPath()

	beginBranchFn, err := h.beginAuthorizedFn()
	if err != nil {
		return err
	}

	var tasks []taskFn
	for i, policy := range policies {
		i := i

		var branch *policyBranch
		for _, digest := range policy.policy.PolicyDigests {
			if digest.HashAlg != h.sessionAlg {
				continue
			}

			branch = &policyBranch{
				Name:   policyBranchName(fmt.Sprintf("%x", digest.Digest)),
				Policy: policy.policy.Policy,
			}
			break
		}
		if branch == nil {
			continue
		}

		tasks = append(tasks, func() error {
			return h.walkBranch(currentPath, beginBranchFn, i, branch, restoreTasks)
		})
	}
	if len(tasks) == 0 {
		tasks = append(tasks, func() error {
			return h.walkBranch(currentPath, beginBranchFn, 0, &policyBranch{Name: "…"}, restoreTasks)
		})
	}

	h.beginBranchQueue = append(tasks, h.beginBranchQueue...)

	// run the first branch
	h.pushNextBranchWalk()

	return nil
}

type treeWalker struct {
	runner *policyRunner
}

func newTreeWalker(session PolicySession, resources policyResources, beginBranchNode, beginAuthorized treeWalkerBeginBranchNodeFn, completeBranch treeWalkerCompleteBranchFn) *treeWalker {
	return &treeWalker{
		runner: newPolicyRunner(
			session,
			new(mockPolicyParams),
			resources,
			func(runner *policyRunner) policyRunnerHelper {
				return newTreeWalkerHelper(runner, beginBranchNode, beginAuthorized, completeBranch)
			},
		),
	}
}

func (w *treeWalker) run(elements policyElements) error {
	return w.runner.run(policyElements{
		&policyElement{
			Type: tpm2.CommandPolicyOR,
			Details: &policyElementDetails{
				OR: &policyORElement{Branches: policyBranches{{Policy: elements}}},
			},
		},
	})
}
