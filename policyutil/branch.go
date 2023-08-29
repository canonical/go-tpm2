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

func (t *policyOrTree) selectBranch(i int) (out []policySessionTask) {
	node := t.leafNodes[i>>3]

	for node != nil {
		var hashList []taggedHashList
		for _, digest := range ensureSufficientORDigests(node.digests) {
			hashList = append(hashList, taggedHashList{{HashAlg: t.alg, Digest: digest}})
		}
		out = append(out, &policyOR{HashList: hashList})
		node = node.parent
	}

	return out
}

func newPolicyBranchAutoSelectorContext(s *policyBranchAutoSelector) *policyRunnerContext {
	return newPolicyRunnerContext(
		s,
		s,
		newMockResourceLoader(s.external),
		s,
	)
}

type policyNVAssertion struct {
	auth      tpm2.Handle
	index     NVIndex
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

type policySecretAssertion struct {
	authObject Named
	policyRef  tpm2.Nonce
}

type policySignedAssertion struct {
	authKey   Named
	policyRef tpm2.Nonce
}

type policyCounterTimerAssertion struct {
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

type policyPCRAssertion struct {
	pcrDigest tpm2.Digest
	pcrs      tpm2.PCRSelectionList
}

type policyAssertions struct {
	policyNv              []policyNVAssertion
	policySecret          []policySecretAssertion
	policySigned          []policySignedAssertion
	policyAuthValueNeeded bool
	policyCommandCode     []tpm2.CommandCode
	policyCounterTimer    []policyCounterTimerAssertion
	policyCpHash          tpm2.DigestList
	policyNameHash        tpm2.DigestList
	policyPcr             []policyPCRAssertion
	policyNvWritten       []bool
}

func (a *policyAssertions) checkValid(alg tpm2.HashAlgorithmId) bool {
	if len(a.policyCommandCode) > 1 {
		for _, code := range a.policyCommandCode[1:] {
			if code != a.policyCommandCode[0] {
				return false
			}
		}
	}

	cpHashNum := 0
	if len(a.policyCpHash) > 0 {
		if len(a.policyCpHash[0]) != alg.Size() {
			return false
		}
		if len(a.policyCpHash) > 1 {
			for _, cpHash := range a.policyCpHash[1:] {
				if !bytes.Equal(cpHash, a.policyCpHash[0]) {
					return false
				}
			}
		}
		cpHashNum += 1
	}
	if len(a.policyNameHash) > 0 {
		if len(a.policyNameHash[0]) != alg.Size() {
			return false
		}
		if len(a.policyNameHash) > 1 {
			return false
		}
		cpHashNum += 1
	}
	if cpHashNum > 1 {
		return false
	}
	if len(a.policyNvWritten) > 1 {
		for _, nvWritten := range a.policyNvWritten[1:] {
			if nvWritten != a.policyNvWritten[0] {
				return false
			}
		}
	}

	return true
}

func (a *policyAssertions) commandCode() (tpm2.CommandCode, bool) {
	if len(a.policyCommandCode) == 0 {
		return 0, false
	}
	return a.policyCommandCode[0], true
}

func (a *policyAssertions) cpHash() (tpm2.Digest, bool) {
	if len(a.policyCpHash) == 0 {
		return nil, false
	}
	return a.policyCpHash[0], true
}

func (a *policyAssertions) nameHash() (tpm2.Digest, bool) {
	if len(a.policyNameHash) == 0 {
		return nil, false
	}
	return a.policyNameHash[0], true
}

func (a *policyAssertions) nvWritten() (bool, bool) {
	if len(a.policyNvWritten) == 0 {
		return false, false
	}
	return a.policyNvWritten[0], true
}

type policyBranchAutoSelector struct {
	state      TPMState
	runner     *policyRunner
	params     policyParams
	usage      *PolicySessionUsage
	sessionAlg tpm2.HashAlgorithmId

	external map[*tpm2.Public]tpm2.Name

	paths         []PolicyBranchPath
	assertionsMap map[PolicyBranchPath]*policyAssertions
	assertions    policyAssertions
	path          PolicyBranchPath

	beginBranchQueue []func() error
}

func newPolicyBranchAutoSelector(state TPMState, runner *policyRunner, usage *PolicySessionUsage) *policyBranchAutoSelector {
	return &policyBranchAutoSelector{
		state:      state,
		runner:     runner,
		params:     runner.params(),
		usage:      usage,
		sessionAlg: runner.session().HashAlg(),
	}
}

func (s *policyBranchAutoSelector) filterInvalidBranches() {
	for k, v := range s.assertionsMap {
		if v.checkValid(s.sessionAlg) {
			continue
		}
		delete(s.assertionsMap, k)
	}
}

func (s *policyBranchAutoSelector) filterMissingAuthBranches() {
	for k, v := range s.assertionsMap {
		missing := false
		for _, signed := range v.policySigned {
			auth := s.params.signedAuthorization(signed.authKey.Name(), signed.policyRef)
			ticket := s.params.ticket(signed.authKey.Name(), signed.policyRef)
			if auth == nil && ticket == nil {
				missing = true
				break
			}
		}
		if missing {
			delete(s.assertionsMap, k)
		}
	}
}

func (s *policyBranchAutoSelector) filterUsageIncompatibleBranches() error {
	if s.usage == nil {
		return nil
	}

	for k, v := range s.assertionsMap {
		code, set := v.commandCode()
		if set && code != s.usage.commandCode {
			delete(s.assertionsMap, k)
			continue
		}

		cpHash, set := v.cpHash()
		if set {
			params := CommandParameters(s.usage.commandCode, s.usage.handles, s.usage.params...)
			d, err := params.Digest(s.sessionAlg)
			if err != nil {
				return fmt.Errorf("cannot obtain cpHash from usage parameters: %w", err)
			}
			if !bytes.Equal(d, cpHash) {
				delete(s.assertionsMap, k)
				continue
			}
		}

		nameHash, set := v.nameHash()
		if set {
			handles := CommandHandles(s.usage.handles...)
			d, err := handles.Digest(s.sessionAlg)
			if err != nil {
				return fmt.Errorf("cannot obtain nameHash from usage parameters: %w", err)
			}
			if !bytes.Equal(d, nameHash) {
				delete(s.assertionsMap, k)
				continue
			}
		}

		if v.policyAuthValueNeeded && !s.usage.canUseAuthValue {
			delete(s.assertionsMap, k)
			continue
		}

		nvWritten, set := v.nvWritten()
		if set && s.usage.nvHandle.Type() == tpm2.HandleTypeNVIndex {
			pub, err := s.state.NVPublic(s.usage.nvHandle)
			if err != nil {
				return fmt.Errorf("cannot obtain NV index public area: %w", err)
			}
			written := pub.Attrs&tpm2.AttrNVWritten != 0
			if nvWritten != written {
				delete(s.assertionsMap, k)
				continue
			}
		}
	}

	return nil
}

func (s *policyBranchAutoSelector) filterPcrIncompatibleBranches() error {
	var pcrs tpm2.PCRSelectionList
	for k, v := range s.assertionsMap {
		var err error
		for _, assertion := range v.policyPcr {
			var tmpPcrs tpm2.PCRSelectionList
			tmpPcrs, err = pcrs.Merge(assertion.pcrs)
			if err != nil {
				break
			}
			pcrs = tmpPcrs
		}
		if err != nil {
			delete(s.assertionsMap, k)
		}
	}

	if pcrs.IsEmpty() {
		return nil
	}

	pcrValues, err := s.state.PCRValues(pcrs)
	if err != nil {
		return fmt.Errorf("cannot obtain PCR values: %w", err)
	}

	for k, v := range s.assertionsMap {
		incompatible := false
		for _, assertion := range v.policyPcr {
			pcrDigest, err := ComputePCRDigest(s.sessionAlg, assertion.pcrs, pcrValues)
			if err != nil {
				return fmt.Errorf("cannot compute PCR digest: %w", err)
			}
			if !bytes.Equal(pcrDigest, assertion.pcrDigest) {
				incompatible = true
				break
			}
		}
		if incompatible {
			delete(s.assertionsMap, k)
		}
	}

	return nil
}

func (s *policyBranchAutoSelector) filterCounterTimerIncompatibleBranches() error {
	hasCounterTimerAssertions := false
	for _, v := range s.assertionsMap {
		if len(v.policyCounterTimer) > 0 {
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

	for k, v := range s.assertionsMap {
		incompatible := false
		for _, assertion := range v.policyCounterTimer {
			if int(assertion.offset) > len(timeInfoData) {
				incompatible = true
				break
			}
			if int(assertion.offset)+len(assertion.operandB) > len(timeInfoData) {
				incompatible = true
				break
			}

			operandA := timeInfoData[int(assertion.offset) : int(assertion.offset)+len(assertion.operandB)]
			operandB := assertion.operandB

			switch assertion.operation {
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
			delete(s.assertionsMap, k)
		}
	}

	return nil
}

func (s *policyBranchAutoSelector) filterAndChooseBranch() (PolicyBranchPath, error) {
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

	for _, path := range s.paths {
		if _, exists := s.assertionsMap[path]; exists {
			return path, nil
		}
	}

	return "", errors.New("no appropriate branches")
}

func (s *policyBranchAutoSelector) collectBranchInfo(path PolicyBranchPath, assertions *policyAssertions, index int, branch *policyBranch) {
	var pathElements []string
	if len(path) > 0 {
		pathElements = append(pathElements, string(path))
	}
	name := branch.Name
	if len(name) == 0 {
		name = PolicyBranchName(fmt.Sprintf("$[%d]", index))
	}
	pathElements = append(pathElements, string(name))

	s.path = PolicyBranchPath(strings.Join(pathElements, "/"))
	s.assertions = *assertions

	s.runner.runElementsNext(branch.Policy, nil)
}

func (s *policyBranchAutoSelector) runBeginCollectNextBranchInfo() {
	fn := s.beginBranchQueue[0]
	s.beginBranchQueue = s.beginBranchQueue[1:]
	s.runner.runNext("begin collect branch information for branch auto selection", fn)
}

func (s *policyBranchAutoSelector) selectBranch(branches policyBranches, done func(PolicyBranchPath) error) error {
	if len(s.beginBranchQueue) > 0 {
		return errors.New("internal error: unexpected state")
	}

	// reset state
	s.external = make(map[*tpm2.Public]tpm2.Name)

	s.assertionsMap = make(map[PolicyBranchPath]*policyAssertions)
	s.assertions = policyAssertions{}
	s.path = ""

	// switch the context
	oldContext := s.runner.policyRunnerContext
	s.runner.policyRunnerContext = newPolicyBranchAutoSelectorContext(s)

	// switch out all of the pending tasks
	next := s.runner.next
	s.runner.next = nil
	tasks := s.runner.tasks
	s.runner.tasks = []policySessionTask{
		newDeferredTask("commit branch information for branch auto selection", func() error {
			assertions := s.assertions
			s.assertionsMap[s.path] = &assertions
			s.paths = append(s.paths, s.path)

			if len(s.beginBranchQueue) == 0 {
				// we've committed the last branch, so restore the state
				s.runner.policyRunnerContext = oldContext
				s.runner.next = next
				s.runner.tasks = tasks

				s.runner.runNext("auto select branch", func() error {
					path, err := s.filterAndChooseBranch()
					if err != nil {
						return fmt.Errorf("cannot select branch: %w", err)
					}
					return done(path)
				})

				return nil
			}

			s.runBeginCollectNextBranchInfo()
			return nil
		}),
	}

	return s.handleBranches(branches)
}

func (s *policyBranchAutoSelector) HashAlg() tpm2.HashAlgorithmId {
	return s.sessionAlg
}

func (s *policyBranchAutoSelector) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	s.assertions.policyNv = append(s.assertions.policyNv, policyNVAssertion{
		auth:      auth.Handle(),
		index:     index,
		operandB:  operandB,
		offset:    offset,
		operation: operation,
	})
	return nil
}

func (s *policyBranchAutoSelector) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	s.assertions.policySecret = append(s.assertions.policySecret, policySecretAssertion{
		authObject: authObject,
		policyRef:  policyRef,
	})
	if len(cpHashA) > 0 {
		s.assertions.policyCpHash = append(s.assertions.policyCpHash, cpHashA)
	}
	return nil, nil, nil
}

func (s *policyBranchAutoSelector) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	s.assertions.policySigned = append(s.assertions.policySigned, policySignedAssertion{
		authKey:   authKey,
		policyRef: policyRef,
	})
	if len(cpHashA) > 0 {
		s.assertions.policyCpHash = append(s.assertions.policyCpHash, cpHashA)
	}
	return nil, nil, nil
}

func (s *policyBranchAutoSelector) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return errors.New("not implemented")
}

func (s *policyBranchAutoSelector) PolicyAuthValue() error {
	s.assertions.policyAuthValueNeeded = true
	return nil
}

func (s *policyBranchAutoSelector) PolicyCommandCode(code tpm2.CommandCode) error {
	s.assertions.policyCommandCode = append(s.assertions.policyCommandCode, code)
	return nil
}

func (s *policyBranchAutoSelector) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	s.assertions.policyCounterTimer = append(s.assertions.policyCounterTimer, policyCounterTimerAssertion{
		operandB:  operandB,
		offset:    offset,
		operation: operation,
	})
	return nil
}

func (s *policyBranchAutoSelector) PolicyCpHash(cpHashA tpm2.Digest) error {
	s.assertions.policyCpHash = append(s.assertions.policyCpHash, cpHashA)
	return nil
}

func (s *policyBranchAutoSelector) PolicyNameHash(nameHash tpm2.Digest) error {
	s.assertions.policyNameHash = append(s.assertions.policyNameHash, nameHash)
	return nil
}

func (s *policyBranchAutoSelector) PolicyOR(pHashList tpm2.DigestList) error {
	return nil
}

func (s *policyBranchAutoSelector) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	panic("not reached")
}

func (s *policyBranchAutoSelector) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	s.assertions.policyPcr = append(s.assertions.policyPcr, policyPCRAssertion{
		pcrDigest: pcrDigest,
		pcrs:      pcrs,
	})
	return nil
}

func (s *policyBranchAutoSelector) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	nameHash := CommandHandles(objectName, newParentName)
	digest, err := nameHash.Digest(s.sessionAlg)
	if err != nil {
		return err
	}
	s.assertions.policyNameHash = append(s.assertions.policyNameHash, digest)
	s.assertions.policyCommandCode = append(s.assertions.policyCommandCode, tpm2.CommandPolicyDuplicationSelect)
	return nil
}

func (s *policyBranchAutoSelector) PolicyPassword() error {
	s.assertions.policyAuthValueNeeded = true
	return nil
}

func (s *policyBranchAutoSelector) PolicyNvWritten(writtenSet bool) error {
	s.assertions.policyNvWritten = append(s.assertions.policyNvWritten, writtenSet)
	return nil
}

func (s *policyBranchAutoSelector) PolicyGetDigest() (tpm2.Digest, error) {
	return make(tpm2.Digest, s.sessionAlg.Size()), nil
}

func (s *policyBranchAutoSelector) secretParams(authName tpm2.Name, policyRef tpm2.Nonce) *PolicySecretParams {
	return s.params.secretParams(authName, policyRef)
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

func (s *policyBranchAutoSelector) handleBranches(branches policyBranches) error {
	// callers to this shouldn't have used policyRunnerDispatcher
	if len(s.runner.next) > 0 {
		return errors.New("internal error: caller to handleBranches used policyRunnerDispatcher")
	}

	path := s.path
	assertions := s.assertions

	// capture the pending running tasks so that each branch begins with
	// the same state
	remaining := s.runner.tasks

	// queue tasks for processing each branch at this node
	var tasks []func() error
	for i, branch := range branches {
		i := i
		branch := branch
		task := func() error {
			s.runner.tasks = remaining
			s.collectBranchInfo(path, &assertions, i, &branch)
			return nil
		}
		tasks = append(tasks, task)
	}

	s.beginBranchQueue = append(tasks, s.beginBranchQueue...)

	// run the first branch
	s.runBeginCollectNextBranchInfo()
	return nil
}

func (s *policyBranchAutoSelector) pushComputeContext(digest *taggedHash) (restore func()) {
	return nil
}
