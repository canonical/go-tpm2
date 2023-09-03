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

func newPolicyBranchAutoSelectorContext(s *policyBranchAutoSelector) *policyRunnerContext {
	return newPolicyRunnerContext(
		&observingPolicySession{session: newNullPolicySession(s.sessionAlg), report: &s.report},
		s,
		new(mockResources),
		s.treeWalker,
	)
}

type policyBranchAutoSelector struct {
	runner     *policyRunner
	state      tpmState
	params     policyParams
	usage      *PolicySessionUsage
	sessionAlg tpm2.HashAlgorithmId

	external   map[*tpm2.Public]tpm2.Name
	treeWalker *treeWalkerPolicyRunnerHelper

	paths     []policyBranchPath
	reportMap map[policyBranchPath]*policySessionReport

	path   policyBranchPath
	report policySessionReport
}

func newPolicyBranchAutoSelector(runner *policyRunner, state tpmState, usage *PolicySessionUsage) *policyBranchAutoSelector {
	return &policyBranchAutoSelector{
		runner:     runner,
		state:      state,
		params:     runner.params(),
		usage:      usage,
		sessionAlg: runner.session().HashAlg(),
	}
}

func (s *policyBranchAutoSelector) filterInvalidBranches() {
	for p, r := range s.reportMap {
		if r.checkValid(s.sessionAlg) {
			continue
		}
		delete(s.reportMap, p)
	}
}

func (s *policyBranchAutoSelector) filterMissingAuthBranches() {
	for p, r := range s.reportMap {
		missing := false
		for _, signed := range r.signed {
			auth := s.params.signedAuthorization(signed.authKey.Name(), signed.policyRef)
			ticket := s.params.ticket(signed.authKey.Name(), signed.policyRef)
			if auth == nil && ticket == nil {
				missing = true
				break
			}
		}
		if missing {
			delete(s.reportMap, p)
		}
	}
}

func (s *policyBranchAutoSelector) filterUsageIncompatibleBranches() error {
	if s.usage == nil {
		return nil
	}

	for p, r := range s.reportMap {
		code, set := r.commandCode()
		if set && code != s.usage.commandCode {
			delete(s.reportMap, p)
			continue
		}

		cpHash, set := r.cpHash()
		if set {
			d, err := ComputeCpHash(s.sessionAlg, s.usage.commandCode, s.usage.handles, s.usage.params...)
			if err != nil {
				return fmt.Errorf("cannot obtain cpHash from usage parameters: %w", err)
			}
			if !bytes.Equal(d, cpHash) {
				delete(s.reportMap, p)
				continue
			}
		}

		nameHash, set := r.nameHash()
		if set {
			d, err := ComputeNameHash(s.sessionAlg, s.usage.handles...)
			if err != nil {
				return fmt.Errorf("cannot obtain nameHash from usage parameters: %w", err)
			}
			if !bytes.Equal(d, nameHash) {
				delete(s.reportMap, p)
				continue
			}
		}

		nvWritten, set := r.nvWritten()
		if set && s.usage.nvHandle.Type() == tpm2.HandleTypeNVIndex {
			pub, err := s.state.NVPublic(s.usage.nvHandle)
			if err != nil {
				return fmt.Errorf("cannot obtain NV index public area: %w", err)
			}
			written := pub.Attrs&tpm2.AttrNVWritten != 0
			if nvWritten != written {
				delete(s.reportMap, p)
				continue
			}
		}
	}

	return nil
}

func (s *policyBranchAutoSelector) filterPcrIncompatibleBranches() error {
	var pcrs tpm2.PCRSelectionList
	for p, r := range s.reportMap {
		var err error
		for _, item := range r.pcr {
			var tmpPcrs tpm2.PCRSelectionList
			tmpPcrs, err = pcrs.Merge(item.pcrs)
			if err != nil {
				break
			}
			pcrs = tmpPcrs
		}
		if err != nil {
			delete(s.reportMap, p)
		}
	}

	if pcrs.IsEmpty() {
		return nil
	}

	pcrValues, err := s.state.PCRValues(pcrs)
	if err != nil {
		return fmt.Errorf("cannot obtain PCR values: %w", err)
	}

	for p, r := range s.reportMap {
		incompatible := false
		for _, item := range r.pcr {
			pcrDigest, err := ComputePCRDigest(s.sessionAlg, item.pcrs, pcrValues)
			if err != nil {
				return fmt.Errorf("cannot compute PCR digest: %w", err)
			}
			if !bytes.Equal(pcrDigest, item.pcrDigest) {
				incompatible = true
				break
			}
		}
		if incompatible {
			delete(s.reportMap, p)
		}
	}

	return nil
}

func (s *policyBranchAutoSelector) filterCounterTimerIncompatibleBranches() error {
	hasCounterTimerAssertions := false
	for _, r := range s.reportMap {
		if len(r.counterTimer) > 0 {
			hasCounterTimerAssertions = true
			break
		}
	}

	if !hasCounterTimerAssertions {
		return nil
	}

	timeInfo, err := s.state.ReadClock()
	if err != nil {
		return fmt.Errorf("cannot obtain time info: %w", err)
	}

	timeInfoData, err := mu.MarshalToBytes(timeInfo)
	if err != nil {
		return fmt.Errorf("cannot marshal time info: %w", err)
	}

	for p, r := range s.reportMap {
		incompatible := false
		for _, item := range r.counterTimer {
			if int(item.offset) > len(timeInfoData) {
				incompatible = true
				break
			}
			if int(item.offset)+len(item.operandB) > len(timeInfoData) {
				incompatible = true
				break
			}

			operandA := timeInfoData[int(item.offset) : int(item.offset)+len(item.operandB)]
			operandB := item.operandB

			switch item.operation {
			case tpm2.OpEq:
				incompatible = !bytes.Equal(operandA, operandB)
			case tpm2.OpNeq:
				incompatible = bytes.Equal(operandA, operandB)
			case tpm2.OpSignedGT:
				switch {
				case len(operandA) == 0:
					incompatible = true
				case (operandA[0]^operandB[0])&0x80 > 0:
					incompatible = operandA[0]&0x80 > 0
				default:
					incompatible = bytes.Compare(operandA, operandB) < 1
				}
			case tpm2.OpUnsignedGT:
				incompatible = bytes.Compare(operandA, operandB) < 1
			case tpm2.OpSignedLT:
				switch {
				case len(operandA) == 0:
					incompatible = true
				case (operandA[0]^operandB[0])&0x80 > 0:
					incompatible = operandA[0]&0x80 == 0
				default:
					incompatible = bytes.Compare(operandA, operandB) > -1
				}
			case tpm2.OpUnsignedLT:
				incompatible = bytes.Compare(operandA, operandB) > -1
			case tpm2.OpSignedGE:
				switch {
				case len(operandA) == 0:
				case (operandA[0]^operandB[0])&0x80 > 0:
					incompatible = operandA[0]&0x80 > 0
				default:
					incompatible = bytes.Compare(operandA, operandB) < 0
				}
			case tpm2.OpUnsignedGE:
				incompatible = bytes.Compare(operandA, operandB) < 0
			case tpm2.OpSignedLE:
				switch {
				case len(operandA) == 0:
				case (operandA[0]^operandB[0])&0x80 > 0:
					incompatible = operandA[0]&0x80 == 0
				default:
					incompatible = bytes.Compare(operandA, operandB) > 0
				}
			case tpm2.OpUnsignedLE:
				incompatible = bytes.Compare(operandA, operandB) > 0
			case tpm2.OpBitset:
				for i := range operandA {
					if operandA[i]&operandB[i] != operandB[i] {
						incompatible = true
						break
					}
				}
			case tpm2.OpBitclear:
				for i := range operandA {
					if operandA[i]&operandB[i] > 0 {
						incompatible = true
						break
					}
				}
			}

			if incompatible {
				break
			}
		}

		if incompatible {
			delete(s.reportMap, p)
		}
	}

	return nil
}

func (s *policyBranchAutoSelector) filterAndChooseBranch() (policyBranchPath, error) {
	s.filterInvalidBranches()
	s.filterMissingAuthBranches()
	if err := s.filterUsageIncompatibleBranches(); err != nil {
		return "", fmt.Errorf("cannot filter branches incompatible with usage: %w", err)
	}
	if err := s.filterPcrIncompatibleBranches(); err != nil {
		return "", fmt.Errorf("cannot filter branches incompatible with TPM2_PolicyPCR assertions: %w", err)
	}
	if err := s.filterCounterTimerIncompatibleBranches(); err != nil {
		return "", fmt.Errorf("cannot filter branches incompatible with TPM2_PolicyCounterTimer assertions: %w", err)
	}

	// return the first branch that doesn't use TPM2_PolicyPassword, TPM2_PolicyAuthValue,
	// or TPM2_PolicySecret, else just return the first good branch.
	var first policyBranchPath

	for _, path := range s.paths {
		if report, exists := s.reportMap[path]; exists {
			if first == "" {
				first = path
			}
			if !report.authValueNeeded && len(report.secret) == 0 {
				return path, nil
			}
		}
	}

	if first == "" {
		return "", errors.New("no appropriate branches")
	}
	return first, nil
}

func (s *policyBranchAutoSelector) selectBranch(branches policyBranches, callback func(policyBranchPath) error) error {
	// reset state
	s.external = make(map[*tpm2.Public]tpm2.Name)

	s.paths = nil
	s.reportMap = make(map[policyBranchPath]*policySessionReport)

	s.path = ""
	s.report = policySessionReport{}

	// switch the context
	oldContext := s.runner.policyRunnerContext
	s.treeWalker = newTreeWalkerPolicyRunnerHelper(s.runner, s.sessionAlg, false, s.beginBranchNode, func(done bool) error {
		s.completeBranch()
		if !done {
			return nil
		}

		// we've committed the last branch, so restore the state
		s.runner.policyRunnerContext = oldContext

		s.runner.pushTask("complete branch auto selection", func() error {
			path, err := s.filterAndChooseBranch()
			if err != nil {
				return fmt.Errorf("cannot select branch: %w", err)
			}
			return callback(path)
		})

		return nil

	})
	s.runner.policyRunnerContext = newPolicyBranchAutoSelectorContext(s)

	s.runner.pushElements(policyElements{
		&policyElement{
			Type: tpm2.CommandPolicyOR,
			Details: &policyElementDetails{
				OR: &policyOR{Branches: branches},
			},
		},
	})
	return nil
}

func (s *policyBranchAutoSelector) signedAuthorization(authName tpm2.Name, policyRef tpm2.Nonce) *PolicySignedAuthorization {
	auth := s.params.signedAuthorization(authName, policyRef)
	if auth == nil {
		auth = &PolicySignedAuthorization{
			Authorization: &PolicyAuthorization{
				AuthKey:   new(tpm2.Public),
				PolicyRef: policyRef,
			},
		}
		s.external[auth.Authorization.AuthKey] = authName
	}
	return auth
}

func (s *policyBranchAutoSelector) ticket(authName tpm2.Name, policyRef tpm2.Nonce) *PolicyTicket {
	return nil
}

func (s *policyBranchAutoSelector) beginBranchNode() (treeWalkerBeginBranchFn, error) {
	report := s.report

	return func(path policyBranchPath) error {
		s.path = path
		s.report = report
		s.runner.policyRunnerContext = newPolicyBranchAutoSelectorContext(s)
		return nil
	}, nil
}

func (s *policyBranchAutoSelector) completeBranch() {
	report := s.report
	s.reportMap[s.path] = &report
	s.paths = append(s.paths, s.path)
}

type (
	treeWalkerBeginBranchNodeFn func() (treeWalkerBeginBranchFn, error)
	treeWalkerBeginBranchFn     func(policyBranchPath) error
	treeWalkerCompleteBranchFn  func(bool) error
)

type treeWalkerPolicyRunnerHelper struct {
	runner     *policyRunner
	sessionAlg tpm2.HashAlgorithmId
	fullTree   bool

	beginBranchNodeFn treeWalkerBeginBranchNodeFn
	beginBranchFn     treeWalkerBeginBranchFn
	completeBranchFn  treeWalkerCompleteBranchFn

	path             policyBranchPath
	started          bool
	beginBranchQueue []*policyDeferredTask
}

func newTreeWalkerPolicyRunnerHelper(runner *policyRunner, sessionAlg tpm2.HashAlgorithmId, fullTree bool, beginBranchNode treeWalkerBeginBranchNodeFn, completeBranch treeWalkerCompleteBranchFn) *treeWalkerPolicyRunnerHelper {
	return &treeWalkerPolicyRunnerHelper{
		runner:            runner,
		sessionAlg:        sessionAlg,
		fullTree:          fullTree,
		beginBranchNodeFn: beginBranchNode,
		completeBranchFn:  completeBranch,
	}
}

func (h *treeWalkerPolicyRunnerHelper) pushNextBranchWalk() {
	task := h.beginBranchQueue[0]
	h.beginBranchQueue = h.beginBranchQueue[1:]
	h.runner.pushTask(task.name(), task.fn)
}

func (h *treeWalkerPolicyRunnerHelper) walkBranch(parentPath policyBranchPath, index int, branch *policyBranch, isRootBranch bool) error {
	if !isRootBranch {
		var pathElements []string
		if len(parentPath) > 0 {
			pathElements = append(pathElements, string(parentPath))
		}
		name := branch.Name
		if len(name) == 0 {
			name = policyBranchName(fmt.Sprintf("$[%d]", index))
		}
		pathElements = append(pathElements, string(name))

		h.path = policyBranchPath(strings.Join(pathElements, "/"))
	}

	if h.beginBranchFn != nil {
		if err := h.beginBranchFn(h.path); err != nil {
			return err
		}
	}

	h.runner.pushElements(branch.Policy)
	return nil
}

func (h *treeWalkerPolicyRunnerHelper) cpHash(cpHash *policyCpHash) (tpm2.Digest, error) {
	if h.sessionAlg == tpm2.HashAlgorithmNull {
		return nil, nil
	}
	for _, digest := range cpHash.Digests {
		if digest.HashAlg != h.sessionAlg {
			continue
		}
		return digest.Digest, nil
	}
	return make(tpm2.Digest, h.sessionAlg.Size()), nil
}

func (h *treeWalkerPolicyRunnerHelper) nameHash(nameHash *policyNameHash) (tpm2.Digest, error) {
	if h.sessionAlg == tpm2.HashAlgorithmNull {
		return nil, nil
	}
	for _, digest := range nameHash.Digests {
		if digest.HashAlg != h.sessionAlg {
			continue
		}
		return digest.Digest, nil
	}
	return make(tpm2.Digest, h.sessionAlg.Size()), nil
}

func (h *treeWalkerPolicyRunnerHelper) handleBranches(branches policyBranches) error {
	if len(branches) == 0 {
		return nil
	}

	remaining := h.runner.tasks

	if !h.started {
		if (h.fullTree && len(branches) != 1) || len(h.beginBranchQueue) != 0 {
			return errors.New("internal error: unexpected state")
		}

		remaining = append([]policySessionTask{newDeferredTask("tree walk complete branch", func() error {
			if h.completeBranchFn != nil {
				done := len(h.beginBranchQueue) == 0
				if err := h.completeBranchFn(done); err != nil {
					return err
				}
				switch done {
				case false:
					h.pushNextBranchWalk()
				case true:
					h.started = false
				}
				return nil
			}
			return nil
		})}, remaining...)

		h.path = ""
	}

	isRootBranch := !h.started && h.fullTree
	path := h.path

	var tasks []*policyDeferredTask
	for i, branch := range branches {
		i := i
		branch := branch
		task := newDeferredTask("tree walk begin branch", func() error {
			h.runner.tasks = remaining
			return h.walkBranch(path, i, branch, isRootBranch)
		})
		if i == 0 {
			innerTask := task
			task = newDeferredTask("tree walk begin branch node", func() error {
				if h.beginBranchNodeFn != nil {
					beginBranchFn, err := h.beginBranchNodeFn()
					if err != nil {
						return err
					}
					h.beginBranchFn = beginBranchFn
				}
				h.runner.pushTask(innerTask.name(), innerTask.fn)
				return nil
			})
		}
		tasks = append(tasks, task)
	}

	h.beginBranchQueue = append(tasks, h.beginBranchQueue...)

	// run the first branch
	h.pushNextBranchWalk()

	h.started = true
	return nil
}
