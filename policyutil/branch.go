// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"

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

type pathSelectorBranchDetails struct {
	PolicyBranchDetails
	missingAuthorized bool
}

type policyPathSelector struct {
	mockPolicyResources

	sessionAlg           tpm2.HashAlgorithmId
	resources            *executePolicyResources
	tpm                  TPMConnection
	usage                *PolicySessionUsage
	ignoreAuthorizations []PolicyAuthorizationID
	ignoreNV             []Named

	paths      []policyBranchPath
	detailsMap map[policyBranchPath]pathSelectorBranchDetails
	nvOk       map[nvAssertionMapKey]struct{}
}

func newPolicyPathSelector(sessionAlg tpm2.HashAlgorithmId, resources *executePolicyResources, tpm TPMConnection, usage *PolicySessionUsage, ignoreAuthorizations []PolicyAuthorizationID, ignoreNV []Named) *policyPathSelector {
	return &policyPathSelector{
		sessionAlg:           sessionAlg,
		resources:            resources,
		tpm:                  tpm,
		usage:                usage,
		ignoreAuthorizations: ignoreAuthorizations,
		ignoreNV:             ignoreNV,
	}
}

// filterInvalidBranches removes branches that are definitely invalid.
func (s *policyPathSelector) filterInvalidBranches() {
	for p, d := range s.detailsMap {
		if d.IsValid() {
			continue
		}
		delete(s.detailsMap, p)
	}
}

// filterIgnoredResources removes branches that require resources that the caller
// requested to not be used.
func (s *policyPathSelector) filterIgnoredResources() {
	for _, ignore := range s.ignoreAuthorizations {
		for p, d := range s.detailsMap {
			var auths []PolicyAuthorizationID
			auths = append(auths, d.Secret...)
			auths = append(auths, d.Signed...)
			auths = append(auths, d.Authorize...)

			for _, auth := range auths {
				if bytes.Equal(auth.AuthName, ignore.AuthName) && bytes.Equal(auth.PolicyRef, ignore.PolicyRef) {
					delete(s.detailsMap, p)
					break
				}
			}
		}
	}

	for _, ignore := range s.ignoreNV {
		for p, d := range s.detailsMap {
			for _, nv := range d.NV {
				if bytes.Equal(nv.Name, ignore.Name()) {
					delete(s.detailsMap, p)
					break
				}
			}
		}
	}
}

// filterMissingAuthorizedBranches removes branches that contain TPM2_PolicyAuthorize
// assertions with no candidate authorized policies.
func (s *policyPathSelector) filterMissingAuthorizedBranches() {
	for p, d := range s.detailsMap {
		if d.missingAuthorized {
			delete(s.detailsMap, p)
		}
	}
}

// filterUsageIncompatibleBranches removes branches that are not compatible with
// the specified session usage.
func (s *policyPathSelector) filterUsageIncompatibleBranches() error {
	if s.usage == nil {
		return nil
	}

	for p, d := range s.detailsMap {
		code, set := d.CommandCode()
		if set && code != s.usage.commandCode {
			delete(s.detailsMap, p)
			continue
		}

		cpHash, set := d.CpHash()
		if set {
			usageCpHash, err := ComputeCpHash(s.sessionAlg, s.usage.commandCode, s.usage.handles, s.usage.params...)
			if err != nil {
				return fmt.Errorf("cannot obtain cpHash from usage parameters: %w", err)
			}
			if !bytes.Equal(usageCpHash, cpHash) {
				delete(s.detailsMap, p)
				continue
			}
		}

		nameHash, set := d.NameHash()
		if set {
			usageNameHash, err := ComputeNameHash(s.sessionAlg, s.usage.handles...)
			if err != nil {
				return fmt.Errorf("cannot obtain nameHash from usage parameters: %w", err)
			}
			if !bytes.Equal(usageNameHash, nameHash) {
				delete(s.detailsMap, p)
				continue
			}
		}

		if d.AuthValueNeeded && s.usage.noAuthValue {
			delete(s.detailsMap, p)
			continue
		}

		nvWritten, set := d.NvWritten()
		if set && s.usage.nvHandle.Type() == tpm2.HandleTypeNVIndex {
			pub, _, err := s.tpm.NVReadPublic(tpm2.NewLimitedHandleContext(s.usage.nvHandle))
			if err != nil {
				return fmt.Errorf("cannot obtain NV index public area: %w", err)
			}
			written := pub.Attrs&tpm2.AttrNVWritten != 0
			if nvWritten != written {
				delete(s.detailsMap, p)
				continue
			}
		}
	}

	return nil
}

// filterPcrIncompatibleBranches removes branches that contain TPM2_PolicyPCR
// assertions with values which don't match the current PCR values.
func (s *policyPathSelector) filterPcrIncompatibleBranches() error {
	var pcrs tpm2.PCRSelectionList
	for p, d := range s.detailsMap {
		for _, item := range d.PCR {
			tmpPcrs, err := pcrs.Merge(item.PCRs)
			if err != nil {
				delete(s.detailsMap, p)
				break
			}
			pcrs = tmpPcrs
		}
	}

	if pcrs.IsEmpty() {
		return nil
	}

	pcrValues, err := s.tpm.PCRRead(pcrs)
	if err != nil {
		return fmt.Errorf("cannot obtain PCR values: %w", err)
	}

	for p, d := range s.detailsMap {
		for _, item := range d.PCR {
			pcrDigest, err := ComputePCRDigest(s.sessionAlg, item.PCRs, pcrValues)
			if err != nil {
				return fmt.Errorf("cannot compute PCR digest: %w", err)
			}
			if !bytes.Equal(pcrDigest, item.PCRDigest) {
				delete(s.detailsMap, p)
				break
			}
		}
	}

	return nil
}

func (s *policyPathSelector) bufferMatch(operandA, operandB tpm2.Operand, operation tpm2.ArithmeticOp) bool {
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

func (s *policyPathSelector) canAuthNV(pub *tpm2.NVPublic, policy *Policy, command tpm2.CommandCode) bool {
	if pub.Attrs&tpm2.AttrNVPolicyRead == 0 {
		return false
	}
	if policy == nil {
		return false
	}

	details, err := policy.Details(pub.Name().Algorithm(), "")
	if err != nil {
		return false
	}

	for _, d := range details {
		if len(d.NV) > 0 {
			continue
		}
		if len(d.Secret) > 0 {
			continue
		}
		if len(d.Signed) > 0 {
			continue
		}
		if len(d.Authorize) > 0 {
			continue
		}
		if d.AuthValueNeeded {
			continue
		}
		code, set := d.CommandCode()
		if set && code != command {
			continue
		}
		if len(d.CounterTimer) > 0 {
			continue
		}
		if _, set := d.CpHash(); set {
			continue
		}
		if _, set := d.NameHash(); set {
			continue
		}
		if len(d.PCR) > 0 {
			continue
		}
		nvWritten, set := d.NvWritten()
		if set && !nvWritten {
			continue
		}
		return true
	}

	return false
}

type nvAssertionMapKey uint32

func makeNvAssertionMapKey(nv *PolicyNVDetails) nvAssertionMapKey {
	return nvAssertionMapKey(mapKey(nv))
}

type nvIndexInfo struct {
	resource tpm2.ResourceContext
	pub      *tpm2.NVPublic
	policy   *Policy
}

// filterNVIncompatibleBranches removes branches that contain TPM2_PolicyNV assertions
// that will fail. This ignores assertions where it's not possible to determine the current
// NV index contents.
func (s *policyPathSelector) filterNVIncompatibleBranches() error {
	nvSeen := make(map[nvAssertionMapKey]struct{})
	nvInfo := make(map[tpm2.Handle]*nvIndexInfo)

	s.nvOk = make(map[nvAssertionMapKey]struct{})

	for p, d := range s.detailsMap {
		incompatible := false
		for _, nv := range d.NV {
			nv := nv

			key := makeNvAssertionMapKey(&nv)
			if _, exists := nvSeen[key]; exists {
				continue
			}
			nvSeen[key] = struct{}{}

			info, exists := nvInfo[nv.Index]
			if !exists {
				pub, name, err := s.tpm.NVReadPublic(tpm2.NewLimitedHandleContext(nv.Index))
				if tpm2.IsTPMHandleError(err, tpm2.ErrorHandle, tpm2.AnyCommandCode, tpm2.AnyHandleIndex) {
					// if no NV index exists, then this branch won't work.
					incompatible = true
					break
				}
				if err != nil {
					return err
				}
				if !bytes.Equal(name, nv.Name) {
					// if the NV index doesn't have the expected name, then this
					// branch won't work.
					incompatible = true
					break
				}
				policy, err := s.resources.policy(nv.Name)
				if err != nil {
					return err
				}

				info = &nvIndexInfo{resource: tpm2.NewNVIndexResourceContext(pub, name), pub: pub, policy: policy}
				nvInfo[nv.Index] = info
			}

			if int(nv.Offset) > int(info.pub.Size) {
				incompatible = true
				break
			}
			if int(nv.Offset)+len(nv.OperandB) > int(info.pub.Size) {
				incompatible = true
				break
			}

			if !s.canAuthNV(info.pub, info.policy, tpm2.CommandNVRead) {
				continue
			}

			// Run the policy session and read the NV index
			err := func() error {
				session, err := s.tpm.StartAuthSession(tpm2.SessionTypePolicy, nv.Name.Algorithm())
				if err != nil {
					return err
				}
				defer s.tpm.FlushContext(session)

				params := &PolicyExecuteParams{
					Usage: NewPolicySessionUsage(tpm2.CommandNVRead, []Named{nv.Name, nv.Name}, uint16(len(nv.OperandB)), nv.Offset).NoAuthValue(),
				}

				resources := new(nullPolicyResources)
				tickets, _ := newExecutePolicyTickets(s.sessionAlg, nil, nil)
				runner := newPolicyExecuteRunner(
					s.tpm,
					session,
					tickets,
					newExecutePolicyResources(s.tpm, resources, tickets, nil, nil),
					resources,
					params,
					new(PolicyBranchDetails),
				)
				if err := runner.run(info.policy.policy.Policy); err != nil {
					// ignore policy execution error
					return nil
				}

				data, err := s.tpm.NVRead(info.resource, info.resource, uint16(len(nv.OperandB)), nv.Offset, session)
				if err != nil {
					// ignore NVRead error
					return nil
				}

				operandA := tpm2.Operand(data)
				operandB := nv.OperandB

				if !s.bufferMatch(operandA, operandB, nv.Operation) {
					incompatible = true
					return nil
				}

				if s.canAuthNV(info.pub, info.policy, tpm2.CommandPolicyNV) {
					s.nvOk[key] = struct{}{}
				}

				return nil
			}()
			if err != nil {
				return err
			}
			if incompatible {
				break
			}
		}
		if incompatible {
			delete(s.detailsMap, p)
		}
	}

	return nil
}

// filterCounterTimerIncompatibleBranches removes branches that contain TPM2_PolicyCounterTimer
// assertions that will fail.
func (s *policyPathSelector) filterCounterTimerIncompatibleBranches() error {
	hasCounterTimerAssertions := false
	for _, d := range s.detailsMap {
		if len(d.CounterTimer) > 0 {
			hasCounterTimerAssertions = true
			break
		}
	}

	if !hasCounterTimerAssertions {
		return nil
	}

	timeInfo, err := s.tpm.ReadClock()
	if err != nil {
		return fmt.Errorf("cannot obtain time info: %w", err)
	}

	timeInfoData, err := mu.MarshalToBytes(timeInfo)
	if err != nil {
		return fmt.Errorf("cannot marshal time info: %w", err)
	}

	for p, d := range s.detailsMap {
		incompatible := false
		for _, item := range d.CounterTimer {
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

			if !s.bufferMatch(operandA, operandB, item.Operation) {
				incompatible = true
				break
			}
		}

		if incompatible {
			delete(s.detailsMap, p)
		}
	}

	return nil
}

type policyPathSelectorTreeWalkError struct {
	err error
}

func (e *policyPathSelectorTreeWalkError) Error() string {
	return fmt.Sprintf("cannot perform tree walk: %v", e.err)
}

func (e *policyPathSelectorTreeWalkError) Unwrap() error {
	return e.err
}

func (*policyPathSelectorTreeWalkError) isPolicyDelimiterError() {}

func (s *policyPathSelector) selectPath(branches policyBranches) (policyBranchPath, error) {
	// reset state
	s.paths = nil
	s.detailsMap = make(map[policyBranchPath]pathSelectorBranchDetails)

	var makeBeginBranchFn func(policyBranchPath, *pathSelectorBranchDetails) treeWalkerBeginBranchFn
	makeBeginBranchFn = func(parentPath policyBranchPath, details *pathSelectorBranchDetails) treeWalkerBeginBranchFn {
		nodeDetails := *details

		return func(name policyBranchPath) (policySession, treeWalkerBeginBranchNodeFn, treeWalkerCompleteFullPathFn, error) {
			branchPath := parentPath.Concat(name)
			branchDetails := nodeDetails

			if name == "…" {
				branchDetails.missingAuthorized = true
			}

			session := newBranchDetailsCollector(s.sessionAlg, &branchDetails.PolicyBranchDetails)

			beginBranchNodeFn := func() (treeWalkerBeginBranchFn, error) {
				return makeBeginBranchFn(branchPath, &branchDetails), nil
			}

			completeFullPath := func() error {
				s.detailsMap[branchPath] = branchDetails
				s.paths = append(s.paths, branchPath)
				return nil
			}

			return session, beginBranchNodeFn, completeFullPath, nil
		}
	}

	walker := newTreeWalker(s, makeBeginBranchFn("", new(pathSelectorBranchDetails)))
	if err := walker.run(policyElements{
		&policyElement{
			Type: tpm2.CommandPolicyOR,
			Details: makePolicyElementDetails(
				policyORElement{Branches: branches},
			),
		},
	}); err != nil {
		return "", &policyPathSelectorTreeWalkError{err: err}
	}

	s.filterInvalidBranches()
	s.filterIgnoredResources()
	s.filterMissingAuthorizedBranches()
	if err := s.filterUsageIncompatibleBranches(); err != nil {
		return "", fmt.Errorf("cannot filter branches incompatible with usage: %w", err)
	}
	if err := s.filterPcrIncompatibleBranches(); err != nil {
		return "", fmt.Errorf("cannot filter branches with TPM2_PolicyPCR assertions that will fail: %w", err)
	}
	if err := s.filterCounterTimerIncompatibleBranches(); err != nil {
		return "", fmt.Errorf("cannot filter branches with TPM2_PolicyCounterTimer assertions that will fail: %w", err)
	}
	if err := s.filterNVIncompatibleBranches(); err != nil {
		return "", fmt.Errorf("cannot filter branches with TPM2_PolicyNV assertions that will fail: %w", err)
	}

	var candidates []policyBranchPath
	for _, path := range s.paths {
		if _, exists := s.detailsMap[path]; !exists {
			continue
		}
		candidates = append(candidates, path)
	}

	if len(candidates) == 0 {
		return "", errors.New("no appropriate paths found")
	}

	path := candidates[0]
	for _, candidate := range candidates {
		details := s.detailsMap[candidate]
		if details.AuthValueNeeded {
			continue
		}
		if len(details.Secret) > 0 {
			continue
		}
		if len(details.Signed) > 0 {
			continue
		}

		nvOK := true
		for _, nv := range details.NV {
			if _, ok := s.nvOk[makeNvAssertionMapKey(&nv)]; !ok {
				nvOK = false
				break
			}
		}
		if !nvOK {
			continue
		}

		path = candidate
		break
	}

	return path, nil
}

func (s *policyPathSelector) AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return s.resources.authorizedPolicies(keySign, policyRef)
}

var errTreeWalkerSkipBranch = errors.New("")

type (
	treeWalkerBeginBranchNodeFn  func() (treeWalkerBeginBranchFn, error)
	treeWalkerBeginBranchFn      func(policyBranchPath) (policySession, treeWalkerBeginBranchNodeFn, treeWalkerCompleteFullPathFn, error)
	treeWalkerCompleteFullPathFn func() error
)

type treeWalker struct {
	policyTickets     nullTickets
	policyResources   policyResources
	beginRootBranchFn treeWalkerBeginBranchFn

	policySession       policySession
	beginBranchNodeFn   treeWalkerBeginBranchNodeFn
	completeFullPathFn  treeWalkerCompleteFullPathFn
	ranCompleteFullPath bool
	currentPath         policyBranchPath
	remaining           policyElements
}

func newTreeWalker(resources policyResources, beginRootBranchFn treeWalkerBeginBranchFn) *treeWalker {
	return &treeWalker{
		policyResources:   resources,
		beginRootBranchFn: beginRootBranchFn,
	}
}

func (w *treeWalker) walkBranch(beginBranchFn treeWalkerBeginBranchFn, index int, branch *policyBranch, remaining policyElements) error {
	name := policyBranchPath(branch.Name)
	if len(name) == 0 {
		name = policyBranchPath(fmt.Sprintf("$[%d]", index))
	}

	session, beginBranchNodeFn, completeFullPathFn, err := beginBranchFn(name)
	if err != nil {
		if err == errTreeWalkerSkipBranch {
			return nil
		}
		return fmt.Errorf("cannot begin branch: %w", err)
	}

	origSession := w.policySession
	origBeginBranchNodeFn := w.beginBranchNodeFn
	origCompleteFullPathFn := w.completeFullPathFn
	origPath := w.currentPath
	defer func() {
		w.policySession = origSession
		w.beginBranchNodeFn = origBeginBranchNodeFn
		w.completeFullPathFn = origCompleteFullPathFn
		w.currentPath = origPath
	}()

	w.policySession = session
	w.beginBranchNodeFn = beginBranchNodeFn
	w.completeFullPathFn = completeFullPathFn
	w.currentPath = w.currentPath.Concat(name)
	w.ranCompleteFullPath = false

	return w.runInternal(append(branch.Policy, remaining...))
}

func (w *treeWalker) session() policySession {
	return w.policySession
}

func (w *treeWalker) tickets() policyTickets {
	return &w.policyTickets
}

func (w *treeWalker) resources() policyResources {
	return w.policyResources
}

func (w *treeWalker) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewLimitedResourceContext(0x80000000, public.Name())
	return newResourceContextFlushable(resource, nil), nil
}

func (w *treeWalker) cpHash(cpHash *policyCpHashElement) error {
	return nil
}

func (w *treeWalker) nameHash(nameHash *policyNameHashElement) error {
	return nil
}

func (w *treeWalker) authorize(auth tpm2.ResourceContext, policy *Policy, usage *PolicySessionUsage, prefer tpm2.SessionType) (tpm2.SessionContext, func(), error) {
	return nil, func() {}, nil
}

func (w *treeWalker) runBranch(branches policyBranches) (int, error) {
	if len(branches) == 0 {
		return 0, errors.New("branch node with no branches")
	}

	remaining := w.remaining
	w.remaining = nil

	beginBranchFn, err := w.beginBranchNodeFn()
	if err != nil {
		return 0, fmt.Errorf("cannot begin branch node: %w", err)
	}

	for i, branch := range branches {
		if err := w.walkBranch(beginBranchFn, i, branch, remaining); err != nil {
			return 0, fmt.Errorf("cannot walk branch %d: %w", i, err)
		}
	}

	return 0, nil
}

func (w *treeWalker) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*Policy) (tpm2.Digest, *tpm2.TkVerified, error) {
	remaining := w.remaining
	w.remaining = nil

	beginBranchFn, err := w.beginBranchNodeFn()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot begin authorized policy node: %w", err)
	}

	if len(policies) > 0 {
		for i, policy := range policies {
			for _, digest := range policy.policy.PolicyDigests {
				if digest.HashAlg != w.session().HashAlg() {
					continue
				}

				branch := &policyBranch{
					Name:   policyBranchName(fmt.Sprintf("%x", digest.Digest())),
					Policy: policy.policy.Policy,
				}
				if err := w.walkBranch(beginBranchFn, i, branch, remaining); err != nil {
					return nil, nil, fmt.Errorf("cannot walk policy: %w", err)
				}

				break
			}
		}
	} else {
		if err := w.walkBranch(beginBranchFn, 0, &policyBranch{Name: "…"}, remaining); err != nil {
			return nil, nil, fmt.Errorf("cannot walk missing policy: %w", err)
		}
	}

	return nil, nil, nil
}

func (w *treeWalker) runInternal(elements policyElements) error {
	w.remaining = elements
	for len(w.remaining) > 0 {
		element := w.remaining[0].runner()
		w.remaining = w.remaining[1:]
		if err := element.run(w); err != nil {
			return makePolicyError(err, w.currentPath, element.name())
		}
	}
	if !w.ranCompleteFullPath {
		w.ranCompleteFullPath = true
		return w.completeFullPathFn()
	}

	return nil
}

func (w *treeWalker) run(elements policyElements) error {
	session, beginBranchNodeFn, completeFullPathFn, err := w.beginRootBranchFn("")
	if err != nil {
		return err
	}

	w.policySession = session
	w.beginBranchNodeFn = beginBranchNodeFn
	w.completeFullPathFn = completeFullPathFn
	w.currentPath = ""

	defer func() {
		w.policySession = nil
		w.beginBranchNodeFn = nil
		w.completeFullPathFn = nil
	}()

	return w.runInternal(elements)
}
