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

type pathWildcardResolverBranchDetails struct {
	PolicyBranchDetails
	missingAuthorized bool
}

type policyPathWildcardResolver struct {
	mockPolicyResources

	sessionAlg           tpm2.HashAlgorithmId
	resources            *executePolicyResources
	tpm                  TPMHelper
	usage                *PolicySessionUsage
	ignoreAuthorizations []PolicyAuthorizationID
	ignoreNV             []Named

	paths       []policyBranchPath
	detailsMap  map[policyBranchPath]pathWildcardResolverBranchDetails
	nvCheckedOk map[nvAssertionMapKey]struct{}
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
	for p, d := range s.detailsMap {
		if d.IsValid() {
			continue
		}
		delete(s.detailsMap, p)
	}
}

// filterIgnoredResources removes branches that require resources that the caller
// requested to not be used.
func (s *policyPathWildcardResolver) filterIgnoredResources() {
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
func (s *policyPathWildcardResolver) filterMissingAuthorizedBranches() {
	for p, d := range s.detailsMap {
		if d.missingAuthorized {
			delete(s.detailsMap, p)
		}
	}
}

// filterUsageIncompatibleBranches removes branches that are not compatible with
// the specified session usage.
func (s *policyPathWildcardResolver) filterUsageIncompatibleBranches() error {
	if s.usage == nil {
		return nil
	}

	for p, d := range s.detailsMap {
		code, set := d.CommandCode()
		if set && code != s.usage.CommandCode() {
			delete(s.detailsMap, p)
			continue
		}

		cpHash, set := d.CpHash()
		if set {
			usageCpHash, err := s.usage.CpHash(s.sessionAlg)
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
			usageNameHash, err := s.usage.NameHash(s.sessionAlg)
			if err != nil {
				return fmt.Errorf("cannot obtain nameHash from usage parameters: %w", err)
			}
			if !bytes.Equal(usageNameHash, nameHash) {
				delete(s.detailsMap, p)
				continue
			}
		}

		if d.AuthValueNeeded && !s.usage.AllowAuthValue() {
			delete(s.detailsMap, p)
			continue
		}

		nvWritten, set := d.NvWritten()
		if set {
			authHandle := s.usage.AuthHandle()
			if authHandle.Handle().Type() != tpm2.HandleTypeNVIndex {
				delete(s.detailsMap, p)
				continue
			}
			pub, err := s.tpm.NVReadPublic(tpm2.NewLimitedHandleContext(authHandle.Handle()))
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
func (s *policyPathWildcardResolver) filterPcrIncompatibleBranches() error {
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
// NV index contents.
func (s *policyPathWildcardResolver) filterNVIncompatibleBranches() error {
	nvResult := make(map[nvAssertionMapKey]nvAssertionStatus)
	nvInfo := make(map[tpm2.Handle]*nvIndexInfo)

	for p, d := range s.detailsMap {
		incompatible := false
		for _, nv := range d.NV {
			nv := nv

			// check if we have a result for this assertion
			key := makeNvAssertionMapKey(&nv)
			if status, exists := nvResult[key]; exists {
				if status == nvAssertionStatusIncompatible {
					incompatible = true
					break
				}
				continue
			}

			// add preliminary result
			nvResult[key] = nvAssertionStatusIndeterminate

			// obtain NV index info
			info, exists := nvInfo[nv.Index]
			if !exists {
				pub, err := s.tpm.NVReadPublic(tpm2.NewLimitedHandleContext(nv.Index))
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
			// is indeterminate.
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

				rc := tpm2.NewLimitedResourceContext(nv.Index, nv.Name)
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
			nvResult[key] = status
			if status == nvAssertionStatusIncompatible {
				incompatible = true
				break
			}
			if status == nvAssertionStatusOK {
				s.nvCheckedOk[key] = struct{}{}
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
func (s *policyPathWildcardResolver) filterCounterTimerIncompatibleBranches() error {
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
	s.detailsMap = make(map[policyBranchPath]pathWildcardResolverBranchDetails)
	s.nvCheckedOk = make(map[nvAssertionMapKey]struct{})

	var makeBeginBranchFn func(policyBranchPath, *pathWildcardResolverBranchDetails) treeWalkerBeginBranchFn
	makeBeginBranchFn = func(parentPath policyBranchPath, details *pathWildcardResolverBranchDetails) treeWalkerBeginBranchFn {
		nodeDetails := *details

		return func(name string) (policySession, treeWalkerBeginBranchNodeFn, treeWalkerCompleteFullPathFn, error) {
			branchPath := parentPath.Concat(name)
			branchDetails := nodeDetails

			if name != "" && name[0] == '<' {
				branchDetails.missingAuthorized = true
			}

			session := newRecorderPolicySession(s.sessionAlg, &branchDetails.PolicyBranchDetails)

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

	walker := newTreeWalker(s, makeBeginBranchFn("", new(pathWildcardResolverBranchDetails)))
	if err := walker.run(policyElements{
		&policyElement{
			Type: tpm2.CommandPolicyOR,
			Details: &policyElementDetails{
				OR: &policyORElement{Branches: branches},
			},
		},
	}); err != nil {
		return "", &policyPathWildcardResolverTreeWalkError{err: err}
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
			if _, ok := s.nvCheckedOk[makeNvAssertionMapKey(&nv)]; !ok {
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
