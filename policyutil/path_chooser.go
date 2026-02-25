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

type policyPathChooserTreeWalkerResult struct {
	paths             []policyBranchPath                       // ordered collection of paths
	details           map[policyBranchPath]PolicyBranchDetails // map of details collected for each path
	missingAuthorized map[policyBranchPath]struct{}            // map of each collected path with missing authorized policies
}

type policyPathChooserTreeWalkerBranchContext struct {
	nodeCtx           *policyPathChooserTreeWalkerBranchNodeContext
	policySession     *recorderPolicySession
	path              policyBranchPath
	missingAuthorized bool
	details           PolicyBranchDetails
}

func (c *policyPathChooserTreeWalkerBranchContext) session() policySession {
	return c.policySession
}

func (c *policyPathChooserTreeWalkerBranchContext) beginBranchNode() (treeWalkerBranchNodeContext, error) {
	return &policyPathChooserTreeWalkerBranchNodeContext{
		branchCtx: c,
		alg:       c.nodeCtx.alg,
		path:      c.path,
		details:   c.details,
		result:    c.nodeCtx.result,
	}, nil
}

func (c *policyPathChooserTreeWalkerBranchContext) completeFullPath() error {
	result := c.nodeCtx.result
	result.paths = append(result.paths, c.path)
	result.details[c.path] = c.details
	if c.missingAuthorized {
		result.missingAuthorized[c.path] = struct{}{}
	}
	return nil
}

type policyPathChooserTreeWalkerBranchNodeContext struct {
	branchCtx *policyPathChooserTreeWalkerBranchContext
	alg       tpm2.HashAlgorithmId
	path      policyBranchPath
	details   PolicyBranchDetails
	result    *policyPathChooserTreeWalkerResult
}

func (c *policyPathChooserTreeWalkerBranchNodeContext) beginBranch(name string) (treeWalkerBranchContext, error) {
	branchCtx := &policyPathChooserTreeWalkerBranchContext{
		nodeCtx: c,
		path:    c.path.Concat(name),
		details: c.details,
	}
	branchCtx.policySession = newRecorderPolicySession(c.alg, &branchCtx.details)
	switch {
	case name != "" && name[0] == '<':
		branchCtx.missingAuthorized = true // this path is missing authorized policies
	case c.branchCtx != nil:
		branchCtx.missingAuthorized = c.branchCtx.missingAuthorized
	}

	return branchCtx, nil
}

// policyPathChooser attempts to automatically select a sequence of paths to execute.
type policyPathChooser struct {
	mockPolicyResources

	sessionAlg           tpm2.HashAlgorithmId
	resources            *executePolicyResources
	tpm                  TPMHelper
	usage                *policySessionUsageConstraints
	ignoreAuthorizations []PolicyAuthorizationID
	ignoreNV             []Named

	// These fields are reset on each call to choose
	walkResult  *policyPathChooserTreeWalkerResult
	nvCheckedOk map[nvAssertionMapKey]struct{} // map of PolicyNV assertions that would succeed
}

func newPolicyPathChooser(sessionAlg tpm2.HashAlgorithmId, resources *executePolicyResources, tpm TPMHelper, usage *policySessionUsageConstraints, ignoreAuthorizations []PolicyAuthorizationID, ignoreNV []Named) *policyPathChooser {
	return &policyPathChooser{
		sessionAlg:           sessionAlg,
		resources:            resources,
		tpm:                  tpm,
		usage:                usage,
		ignoreAuthorizations: ignoreAuthorizations,
		ignoreNV:             ignoreNV,
	}
}

// filterInvalidBranches removes branches that are definitely invalid.
func (s *policyPathChooser) filterInvalidBranches() {
	// iterate over each execution path
	for p, d := range s.walkResult.details {
		if d.IsValid() {
			continue
		}
		delete(s.walkResult.details, p)
	}
}

// filterIgnoredResources removes branches that require resources that the caller
// requested to not be used.
func (s *policyPathChooser) filterIgnoredResources() {
	for _, ignore := range s.ignoreAuthorizations {
		// iterate over each execution path
		for p, d := range s.walkResult.details {
			var auths []PolicyAuthorizationID
			auths = append(auths, d.Secret...)
			auths = append(auths, d.Signed...)
			auths = append(auths, d.Authorize...)

			// iterate over each authorization in this path
			for _, auth := range auths {
				if bytes.Equal(auth.AuthName, ignore.AuthName) && bytes.Equal(auth.PolicyRef, ignore.PolicyRef) {
					// this path contains an authorization to ignore, so drop it
					delete(s.walkResult.details, p)
					break
				}
			}
		}
	}

	for _, ignore := range s.ignoreNV {
		// iterate over each execution path
		for p, d := range s.walkResult.details {
			// iterate over each PolicyNV assertion in this path
			for _, nv := range d.NV {
				if bytes.Equal(nv.Name, ignore.Name()) {
					// this path contains a PolicyNV assertion to ignore, so drop it
					delete(s.walkResult.details, p)
					break
				}
			}
		}
	}
}

// filterMissingAuthorizedBranches removes branches that contain TPM2_PolicyAuthorize
// assertions with no candidate authorized policies returned from the supplied
// PolicyResources.
func (s *policyPathChooser) filterMissingAuthorizedBranches() {
	// iterate over each execution path
	for p := range s.walkResult.details {
		if _, missing := s.walkResult.missingAuthorized[p]; missing {
			delete(s.walkResult.details, p)
		}
	}
}

// filterUsageIncompatibleBranches removes branches that are not compatible with
// the specified session usage, if it is supplied.
func (s *policyPathChooser) filterUsageIncompatibleBranches() error {
	// iterate over each execution path
	for p, d := range s.walkResult.details {
		if s.usage.hasCommand {
			code, set := d.CommandCode()
			if set && code != s.usage.commandCode {
				// this path doesn't match the command code, so drop it
				delete(s.walkResult.details, p)
				continue
			}
		}

		if s.usage.canCpHash() {
			cpHash, set := d.CpHash()
			if set {
				usageCpHash, err := s.usage.cpHash(s.sessionAlg)
				if err != nil {
					return fmt.Errorf("cannot obtain cpHash from usage parameters: %w", err)
				}
				if !bytes.Equal(usageCpHash, cpHash) {
					// this path doesn't match the command parameters, so drop it
					delete(s.walkResult.details, p)
					continue
				}
			}
		}

		if s.usage.canNameHash() {
			nameHash, set := d.NameHash()
			if set {
				usageNameHash, err := s.usage.nameHash(s.sessionAlg)
				if err != nil {
					return fmt.Errorf("cannot obtain nameHash from usage parameters: %w", err)
				}
				if !bytes.Equal(usageNameHash, nameHash) {
					// this path doesn't match the command handles, so drop it
					delete(s.walkResult.details, p)
					continue
				}
			}
		}

		if d.AuthValueNeeded && s.usage.noAuthValue {
			// this path requires an auth value which the usage indicates is not possible, so drop it
			delete(s.walkResult.details, p)
			continue
		}

		if s.usage.hasHandles {
			nvWritten, set := d.NvWritten()
			if set {
				authHandle := s.usage.authHandle()
				if authHandle.Handle().Type() != tpm2.HandleTypeNVIndex {
					// this path uses TPM2_PolicyNvWritten but the auth handle is not a
					// NV index, so drop this path
					delete(s.walkResult.details, p)
					continue
				}
				pub, err := s.tpm.NVReadPublic(tpm2.NewHandleContext(authHandle.Handle()))
				if err != nil {
					return fmt.Errorf("cannot obtain NV index public area: %w", err)
				}
				written := pub.Attrs&tpm2.AttrNVWritten != 0
				if nvWritten != written {
					// this path uses TPM2_PolicyNvWritten but the auth handle attributes
					// are incompatible, so drop this path.
					delete(s.walkResult.details, p)
					continue
				}
			}
		}
	}

	return nil
}

// filterPcrIncompatibleBranches removes branches that contain TPM2_PolicyPCR
// assertions with values which don't match the current PCR values.
func (s *policyPathChooser) filterPcrIncompatibleBranches() error {
	// Build a list of PCR selections from the paths
	var pcrs tpm2.PCRSelectionList
	// iterate over each execution path
	for p, d := range s.walkResult.details {
		// iterate over each PolicyPCR assertion in this path
		for _, item := range d.PCR {
			// merge the selections
			tmpPcrs, err := pcrs.Merge(item.PCRs)
			if err != nil {
				// this assertion is invalid, so drop this path
				delete(s.walkResult.details, p)
				break
			}
			pcrs = tmpPcrs
		}
	}

	if pcrs.IsEmpty() {
		// There are no PolicyPCR assertions
		return nil
	}

	// Read the current PCR values
	pcrValues, err := s.tpm.PCRRead(pcrs)
	if err != nil {
		return fmt.Errorf("cannot obtain PCR values: %w", err)
	}

	// iterate over each execution path
	for p, d := range s.walkResult.details {
		// iterate over each PolicyPCR assertion in this path
		for _, item := range d.PCR {
			// compare the assertion to the current values
			pcrDigest, err := ComputePCRDigest(s.sessionAlg, item.PCRs, pcrValues)
			if err != nil {
				return fmt.Errorf("cannot compute PCR digest: %w", err)
			}
			if !bytes.Equal(pcrDigest, item.PCRDigest) {
				// the assertion doesn't match the current PCR values, so drop this path
				delete(s.walkResult.details, p)
				break
			}
		}
	}

	return nil
}

func (s *policyPathChooser) bufferMatch(operandA, operandB tpm2.Operand, operation tpm2.ArithmeticOp) bool {
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

func (s *policyPathChooser) canAuthNV(pub *tpm2.NVPublic, policy *Policy, command tpm2.CommandCode) bool {
	if pub.Attrs&tpm2.AttrNVPolicyRead == 0 {
		return false
	}
	if policy == nil {
		return false
	}

	details, err := policy.Details(pub.Name().Algorithm(), "", nil)
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

type nvAssertionStatus int

const (
	nvAssertionStatusIndeterminate nvAssertionStatus = iota
	nvAssertionStatusIncompatible
	nvAssertionStatusOK
)

// filterNVIncompatibleBranches removes branches that contain TPM2_PolicyNV assertions
// that will fail. This ignores assertions where it's not possible to determine the current
// NV index contents because it requires authorization to read. It populates the nvCheckedOk
// map for assertions that were checked to be good.
func (s *policyPathChooser) filterNVIncompatibleBranches() error {
	nvResult := make(map[nvAssertionMapKey]nvAssertionStatus) // a map of assertion IDs to status
	nvInfo := make(map[tpm2.Handle]*nvIndexInfo)              // a map of handles to information about the corresponding index

	// iterate over each execution path
	for p, d := range s.walkResult.details {
		incompatible := false
		// iterate over each PolicyNV assertion in this path
		for _, nv := range d.NV {
			nv := nv

			// check if we have a result for this assertion
			key := makeNvAssertionMapKey(&nv)
			if status, exists := nvResult[key]; exists {
				// We have a result.
				if status == nvAssertionStatusIncompatible {
					// The assertion is incompatible with the current index
					// contents. Mark this path as bad and break early.
					incompatible = true
					break
				}
				// Nothing else to do for this assertion
				continue
			}

			// add preliminary result
			nvResult[key] = nvAssertionStatusIndeterminate

			// obtain NV index info
			info, exists := nvInfo[nv.Index]
			if !exists {
				// Read the index info from the TPM
				pub, err := s.tpm.NVReadPublic(tpm2.NewHandleContext(nv.Index))
				if tpm2.IsTPMHandleError(err, tpm2.ErrorHandle, tpm2.AnyCommandCode, tpm2.AnyHandleIndex) {
					// if no NV index exists, then this branch won't work.
					nvResult[key] = nvAssertionStatusIncompatible
					incompatible = true
					break
				}
				if err != nil {
					return err
				}
				name := pub.Name()
				if !bytes.Equal(name, nv.Name) {
					// if the NV index doesn't have the expected name, then this
					// branch won't work.
					nvResult[key] = nvAssertionStatusIncompatible
					incompatible = true
					break
				}
				// Obtain the policy for the index
				policy, err := s.resources.policy(nv.Name)
				if err != nil {
					return err
				}

				info = &nvIndexInfo{resource: tpm2.NewNVIndexResourceContext(pub, name), pub: pub, policy: policy}
				nvInfo[nv.Index] = info
			}

			// Check the assertion is compatible with the public area
			if int(nv.Offset) > int(info.pub.Size) {
				nvResult[key] = nvAssertionStatusIncompatible
				incompatible = true
				break
			}
			if int(nv.Offset)+len(nv.OperandB) > int(info.pub.Size) {
				nvResult[key] = nvAssertionStatusIncompatible
				incompatible = true
				break
			}

			// If we can't execute TPM2_NV_Read without authorization, then the result
			// is indeterminate. We don't mark this path as bad, but we don't add it to
			// nvCheckedOk.
			if !s.canAuthNV(info.pub, info.policy, tpm2.CommandNVRead) {
				continue
			}

			// Run the policy session and read the NV index
			status, err := func() (nvAssertionStatus, error) {
				session, policySession, err := s.tpm.StartAuthSession(tpm2.SessionTypePolicy, nv.Name.Algorithm())
				if err != nil {
					return nvAssertionStatusIndeterminate, err
				}
				defer session.Flush()

				rc := tpm2.NewResourceContext(nv.Index, nv.Name)
				params := &policyExecuteParams{
					tpm: s.tpm,
					usage: policySessionUsageConstraints{
						hasCommand:  true,
						hasHandles:  true,
						hasParams:   true,
						commandCode: tpm2.CommandNVRead,
						handles:     []NamedHandle{rc, rc},
						params:      []any{uint16(len(nv.OperandB)), nv.Offset},
						noAuthValue: true,
					},
				}

				resources := new(nullPolicyResources)
				tickets, _ := newExecutePolicyTickets(s.sessionAlg, nil, &params.usage)
				runner := newPolicyExecuteRunner(
					policySession,
					params,
					tickets,
					newExecutePolicyResources(session, resources, tickets, nil, nil),
					resources,
					new(PolicyBranchDetails),
				)
				if err := runner.run(info.policy.policy.Policy); err != nil {
					// ignore policy execution error
					return nvAssertionStatusIndeterminate, nil
				}

				data, err := s.tpm.NVRead(info.resource, info.resource, uint16(len(nv.OperandB)), nv.Offset, session.Session())
				if err != nil {
					// ignore NVRead error
					return nvAssertionStatusIndeterminate, nil
				}

				operandA := tpm2.Operand(data)
				operandB := nv.OperandB

				if !s.bufferMatch(operandA, operandB, nv.Operation) {
					return nvAssertionStatusIncompatible, nil
				}

				return nvAssertionStatusOK, nil
			}()
			if err != nil {
				return err
			}
			// update the result for this assertion
			nvResult[key] = status
			if status == nvAssertionStatusIncompatible {
				// the assertion is incompatible, so mark this path as bad and break early
				incompatible = true
				break
			}
			if status == nvAssertionStatusOK {
				// the assertion is good, so add it to nvCheckedOk
				s.nvCheckedOk[key] = struct{}{}
			}
		}
		if incompatible {
			// the last checked PolicyNV assertion for this path is bad, so
			// drop the whole path
			delete(s.walkResult.details, p)
		}
	}

	return nil
}

// filterCounterTimerIncompatibleBranches removes branches that contain TPM2_PolicyCounterTimer
// assertions that will fail.
func (s *policyPathChooser) filterCounterTimerIncompatibleBranches() error {
	// determine whether any paths use TPM2_PolicyCounterTimer
	hasCounterTimerAssertions := false
	// iterate over each execution path
	for _, d := range s.walkResult.details {
		if len(d.CounterTimer) > 0 {
			// we've found one - no need to check any more
			hasCounterTimerAssertions = true
			break
		}
	}

	if !hasCounterTimerAssertions {
		// no TPM2_PolicyCounterTimer assertions
		return nil
	}

	// Read the current time info
	timeInfo, err := s.tpm.ReadClock()
	if err != nil {
		return fmt.Errorf("cannot obtain time info: %w", err)
	}

	// Serialize the current time info
	timeInfoData, err := mu.MarshalToBytes(timeInfo)
	if err != nil {
		return fmt.Errorf("cannot marshal time info: %w", err)
	}

	// iterate over each execution path
	for p, d := range s.walkResult.details {
		incompatible := false
		// iterate over each PolicyCounterTimer assertion in this path
		for _, item := range d.CounterTimer {
			if int(item.Offset) > len(timeInfoData) {
				// the assertion is invalid, so drop this path and break early
				incompatible = true
				break
			}
			if int(item.Offset)+len(item.OperandB) > len(timeInfoData) {
				// the assertion is invalid, so drop this path and break early
				incompatible = true
				break
			}

			operandA := timeInfoData[int(item.Offset) : int(item.Offset)+len(item.OperandB)]
			operandB := item.OperandB

			if !s.bufferMatch(operandA, operandB, item.Operation) {
				// the assertion doesn't match the current time info, so drop this path and
				// break early
				incompatible = true
				break
			}
		}

		if incompatible {
			// the last checked PolicyCounterTimer assertion for this path is bad, so
			// drop the whole path
			delete(s.walkResult.details, p)
		}
	}

	return nil
}

type policyPathChooserTreeWalkError struct {
	err error
}

func (e *policyPathChooserTreeWalkError) Error() string {
	return fmt.Sprintf("cannot perform tree walk: %v", e.err)
}

func (e *policyPathChooserTreeWalkError) Unwrap() error {
	return e.err
}

func (*policyPathChooserTreeWalkError) isPolicyDelimiterError() {}

func (s *policyPathChooser) choose(branches policyBranches) (policyBranchPath, error) {
	// reset state
	s.walkResult = &policyPathChooserTreeWalkerResult{
		details:           make(map[policyBranchPath]PolicyBranchDetails),
		missingAuthorized: make(map[policyBranchPath]struct{}),
	}
	s.nvCheckedOk = make(map[nvAssertionMapKey]struct{})

	walker := newTreeWalker(s, &policyPathChooserTreeWalkerBranchNodeContext{
		alg:    s.sessionAlg,
		result: s.walkResult,
	})
	if err := walker.run(policyElements{
		&policyElement{
			Type: commandPolicyBranchNode,
			Details: &policyElementDetails{
				BranchNode: &policyBranchNodeElement{Branches: branches},
			},
		},
	}); err != nil {
		return "", &policyPathChooserTreeWalkError{err: err}
	}

	// Drop incompatible paths
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
	for _, path := range s.walkResult.paths {
		if _, exists := s.walkResult.details[path]; !exists {
			continue
		}
		candidates = append(candidates, path)
	}

	if len(candidates) == 0 {
		return "", errors.New("no appropriate paths found")
	}

	// Provisionally select the first path
	path := candidates[0]

	// Try to find a better path
	for _, candidate := range candidates {
		details := s.walkResult.details[candidate]
		// prefer paths without TPM2_PolicyAuthValue and TPM2_PolicyPassword
		if details.AuthValueNeeded {
			continue
		}

		// prefer paths without TPM2_PolicySecret
		if len(details.Secret) > 0 {
			continue
		}

		// prefer paths without TPM2_PolicySigned
		if len(details.Signed) > 0 {
			continue
		}

		// prefer paths without unchecked TPM2_PolicyNV
		nvOK := true
		for _, nv := range details.NV {
			if _, ok := s.nvCheckedOk[makeNvAssertionMapKey(&nv)]; !ok {
				nvOK = false
				break
			}
		}
		if !nvOK {
			continue
		}

		// prefer paths without TPM2_PolicyCommandCode if we don't know the usage
		if _, set := details.CommandCode(); set && !s.usage.hasCommand {
			continue
		}

		// prefer paths without TPM2_PolicyCpHash if we don't know the usage
		if _, set := details.CpHash(); set && !s.usage.canCpHash() {
			continue
		}

		// prefer paths without TPM2_PolicyNameHash if we don't know the usage
		if _, set := details.NameHash(); set && !s.usage.canNameHash() {
			continue
		}

		// we've found the perfect path!
		path = candidate
		break
	}

	return path, nil
}
