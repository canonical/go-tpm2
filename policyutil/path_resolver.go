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

// policyPathWildcardResolver attempts to automatically select a sequence of paths to execute.
type policyPathWildcardResolver struct {
	mockPolicyResources

	sessionAlg           tpm2.HashAlgorithmId
	resources            *executePolicyResources
	tpm                  TPMHelper
	usage                *PolicySessionUsage
	ignoreAuthorizations []PolicyAuthorizationID
	ignoreNV             []Named

	// These fields are reset on each call to resolve.
	paths             []policyBranchPath                       // ordered collection of paths
	details           map[policyBranchPath]PolicyBranchDetails // map of details collected for each path
	missingAuthorized map[policyBranchPath]struct{}            // map of each collected path with missing authorized policies
	nvCheckedOk       map[nvAssertionMapKey]struct{}           // map of PolicyNV assertions that would succeed
}

func newPolicyPathWildcardResolver(sessionAlg tpm2.HashAlgorithmId, resources *executePolicyResources, tpm TPMHelper, usage *PolicySessionUsage, ignoreAuthorizations []PolicyAuthorizationID, ignoreNV []Named) *policyPathWildcardResolver {
	return &policyPathWildcardResolver{
		sessionAlg:           sessionAlg,
		resources:            resources,
		tpm:                  tpm,
		usage:                usage,
		ignoreAuthorizations: ignoreAuthorizations,
		ignoreNV:             ignoreNV,
	}
}

// filterInvalidBranches removes branches that are definitely invalid.
func (s *policyPathWildcardResolver) filterInvalidBranches() {
	// iterate over each execution path
	for p, d := range s.details {
		if d.IsValid() {
			continue
		}
		delete(s.details, p)
	}
}

// filterIgnoredResources removes branches that require resources that the caller
// requested to not be used.
func (s *policyPathWildcardResolver) filterIgnoredResources() {
	for _, ignore := range s.ignoreAuthorizations {
		// iterate over each execution path
		for p, d := range s.details {
			var auths []PolicyAuthorizationID
			auths = append(auths, d.Secret...)
			auths = append(auths, d.Signed...)
			auths = append(auths, d.Authorize...)

			// iterate over each authorization in this path
			for _, auth := range auths {
				if bytes.Equal(auth.AuthName, ignore.AuthName) && bytes.Equal(auth.PolicyRef, ignore.PolicyRef) {
					// this path contains an authorization to ignore, so drop it
					delete(s.details, p)
					break
				}
			}
		}
	}

	for _, ignore := range s.ignoreNV {
		// iterate over each execution path
		for p, d := range s.details {
			// iterate over each PolicyNV assertion in this path
			for _, nv := range d.NV {
				if bytes.Equal(nv.Name, ignore.Name()) {
					// this path contains a PolicyNV assertion to ignore, so drop it
					delete(s.details, p)
					break
				}
			}
		}
	}
}

// filterMissingAuthorizedBranches removes branches that contain TPM2_PolicyAuthorize
// assertions with no candidate authorized policies returned from the supplied
// PolicyResources.
func (s *policyPathWildcardResolver) filterMissingAuthorizedBranches() {
	// iterate over each execution path
	for p := range s.details {
		if _, missing := s.missingAuthorized[p]; missing {
			delete(s.details, p)
		}
	}
}

// filterUsageIncompatibleBranches removes branches that are not compatible with
// the specified session usage, if it is supplied.
func (s *policyPathWildcardResolver) filterUsageIncompatibleBranches() error {
	if s.usage == nil {
		return nil
	}

	// iterate over each execution path
	for p, d := range s.details {
		code, set := d.CommandCode()
		if set && code != s.usage.CommandCode() {
			// this path doesn't match the command code, so drop it
			delete(s.details, p)
			continue
		}

		cpHash, set := d.CpHash()
		if set {
			usageCpHash, err := s.usage.CpHash(s.sessionAlg)
			if err != nil {
				return fmt.Errorf("cannot obtain cpHash from usage parameters: %w", err)
			}
			if !bytes.Equal(usageCpHash, cpHash) {
				// this path doesn't match the command parameters, so drop it
				delete(s.details, p)
				continue
			}
		}

		nameHash, set := d.NameHash()
		if set {
			usageNameHash, err := s.usage.NameHash(s.sessionAlg)
			if err != nil {
				return fmt.Errorf("cannot obtain nameHash from usage parameters: %w", err)
			}
			if !bytes.Equal(usageNameHash, nameHash) {
				// this path doesn't match the command handles, so drop it
				delete(s.details, p)
				continue
			}
		}

		if d.AuthValueNeeded && !s.usage.AllowAuthValue() {
			// this path requires an auth value which the usage indicates is not possible, so drop it
			delete(s.details, p)
			continue
		}

		nvWritten, set := d.NvWritten()
		if set {
			authHandle := s.usage.AuthHandle()
			if authHandle.Handle().Type() != tpm2.HandleTypeNVIndex {
				// this path uses TPM2_PolicyNvWritten but the auth handle is not a
				// NV index, so drop this path
				delete(s.details, p)
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
				delete(s.details, p)
				continue
			}
		}
	}

	return nil
}

// filterPcrIncompatibleBranches removes branches that contain TPM2_PolicyPCR
// assertions with values which don't match the current PCR values.
func (s *policyPathWildcardResolver) filterPcrIncompatibleBranches() error {
	// Build a list of PCR selections from the paths
	var pcrs tpm2.PCRSelectionList
	// iterate over each execution path
	for p, d := range s.details {
		// iterate over each PolicyPCR assertion in this path
		for _, item := range d.PCR {
			// merge the selections
			tmpPcrs, err := pcrs.Merge(item.PCRs)
			if err != nil {
				// this assertion is invalid, so drop this path
				delete(s.details, p)
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
	for p, d := range s.details {
		// iterate over each PolicyPCR assertion in this path
		for _, item := range d.PCR {
			// compare the assertion to the current values
			pcrDigest, err := ComputePCRDigest(s.sessionAlg, item.PCRs, pcrValues)
			if err != nil {
				return fmt.Errorf("cannot compute PCR digest: %w", err)
			}
			if !bytes.Equal(pcrDigest, item.PCRDigest) {
				// the assertion doesn't match the current PCR values, so drop this path
				delete(s.details, p)
				break
			}
		}
	}

	return nil
}

func (s *policyPathWildcardResolver) bufferMatch(operandA, operandB tpm2.Operand, operation tpm2.ArithmeticOp) bool {
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

func (s *policyPathWildcardResolver) canAuthNV(pub *tpm2.NVPublic, policy *Policy, command tpm2.CommandCode) bool {
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
func (s *policyPathWildcardResolver) filterNVIncompatibleBranches() error {
	nvResult := make(map[nvAssertionMapKey]nvAssertionStatus) // a map of assertion IDs to status
	nvInfo := make(map[tpm2.Handle]*nvIndexInfo)              // a map of handles to information about the corresponding index

	// iterate over each execution path
	for p, d := range s.details {
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
				params := &PolicyExecuteParams{
					Usage: NewPolicySessionUsage(tpm2.CommandNVRead, []NamedHandle{rc, rc}, uint16(len(nv.OperandB)), nv.Offset).WithoutAuthValue(),
				}

				resources := new(nullPolicyResources)
				tickets, _ := newExecutePolicyTickets(s.sessionAlg, nil, nil)
				runner := newPolicyExecuteRunner(
					policySession,
					tickets,
					newExecutePolicyResources(session, resources, tickets, nil, nil),
					resources,
					s.tpm,
					params,
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
			delete(s.details, p)
		}
	}

	return nil
}

// filterCounterTimerIncompatibleBranches removes branches that contain TPM2_PolicyCounterTimer
// assertions that will fail.
func (s *policyPathWildcardResolver) filterCounterTimerIncompatibleBranches() error {
	// determine whether any paths use TPM2_PolicyCounterTimer
	hasCounterTimerAssertions := false
	// iterate over each execution path
	for _, d := range s.details {
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
	for p, d := range s.details {
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
			delete(s.details, p)
		}
	}

	return nil
}

type policyPathWildcardResolverTreeWalkError struct {
	err error
}

func (e *policyPathWildcardResolverTreeWalkError) Error() string {
	return fmt.Sprintf("cannot perform tree walk: %v", e.err)
}

func (e *policyPathWildcardResolverTreeWalkError) Unwrap() error {
	return e.err
}

func (*policyPathWildcardResolverTreeWalkError) isPolicyDelimiterError() {}

func (s *policyPathWildcardResolver) resolve(branches policyBranches) (policyBranchPath, error) {
	// reset state
	s.paths = nil
	s.details = make(map[policyBranchPath]PolicyBranchDetails)
	s.missingAuthorized = make(map[policyBranchPath]struct{})
	s.nvCheckedOk = make(map[nvAssertionMapKey]struct{})

	// Walk every path from the supplied branches
	var makeBeginBranchFn func(policyBranchPath, *PolicyBranchDetails, bool) treeWalkerBeginBranchFn
	makeBeginBranchFn = func(parentPath policyBranchPath, details *PolicyBranchDetails, missingAuthorized bool) treeWalkerBeginBranchFn {
		// This function is called when starting a new branch node. It is called with information
		// about the parent branch

		nodeDetails := *details // copy the details collected from the parent branch

		return func(name string) (policySession, treeWalkerBeginBranchNodeFn, treeWalkerCompleteFullPathFn, error) {
			// This function is called at the start of a new branch. It inherits the current details
			// at the point that the node was entered (nodeDetails) as well as the path of the parent
			// branch (parentPath) and whether this path has any missing authorized policies (missingAuthorized).

			branchPath := parentPath.Concat(name)        // Create the new path of this branch
			branchDetails := nodeDetails                 // Copy the details from the node to this branch
			branchMissingAuthorized := missingAuthorized // Copy whether this path has been flagged as having missing authorized policies

			if name != "" && name[0] == '<' {
				branchMissingAuthorized = true // this path is missing authorized policies
			}

			// Create a new session for this branch
			session := newRecorderPolicySession(s.sessionAlg, &branchDetails)

			// Create a new function for entering a new branch node from this branch
			beginBranchNodeFn := func() (treeWalkerBeginBranchFn, error) {
				// We're entering a new branch node

				// Create a new function for entering a new branch from this branch node, which
				// inherits the properties of the current branch
				return makeBeginBranchFn(branchPath, &branchDetails, branchMissingAuthorized), nil
			}

			// Create a new function that signals the end of a complete path (ie, no more elements)
			completeFullPath := func() error {
				s.paths = append(s.paths, branchPath)
				s.details[branchPath] = branchDetails
				if branchMissingAuthorized {
					s.missingAuthorized[branchPath] = struct{}{}
				}
				return nil
			}

			return session, beginBranchNodeFn, completeFullPath, nil
		}
	}

	walker := newTreeWalker(s, makeBeginBranchFn("", new(PolicyBranchDetails), false))
	if err := walker.run(policyElements{
		&policyElement{
			Type: commandPolicyBranchNode,
			Details: &policyElementDetails{
				BranchNode: &policyBranchNodeElement{Branches: branches},
			},
		},
	}); err != nil {
		return "", &policyPathWildcardResolverTreeWalkError{err: err}
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
	for _, path := range s.paths {
		if _, exists := s.details[path]; !exists {
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
		details := s.details[candidate]
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
		if _, set := details.CommandCode(); set && s.usage == nil {
			continue
		}

		// prefer paths without TPM2_PolicyCpHash if we don't know the usage
		if _, set := details.CpHash(); set && s.usage == nil {
			continue
		}

		// prefer paths without TPM2_PolicyNameHash if we don't know the usage
		if _, set := details.NameHash(); set && s.usage == nil {
			continue
		}

		// we've found the perfect path!
		path = candidate
		break
	}

	return path, nil
}
