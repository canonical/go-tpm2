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

type trialPolicySessionContext struct {
	digest *taggedHash
}

func newTrialPolicySessionContext(digest *taggedHash) *trialPolicySessionContext {
	return &trialPolicySessionContext{digest: digest}
}

func (s *trialPolicySessionContext) updateForCommand(command tpm2.CommandCode, params ...interface{}) error {
	h := s.digest.HashAlg.NewHash()
	h.Write(s.digest.Digest)
	mu.MustMarshalToWriter(h, command)
	if _, err := mu.MarshalToWriter(h, params...); err != nil {
		return err
	}
	s.digest.Digest = h.Sum(nil)
	return nil
}

func (s *trialPolicySessionContext) mustUpdateForCommand(command tpm2.CommandCode, params ...interface{}) {
	if err := s.updateForCommand(command, params...); err != nil {
		panic(err)
	}
}

func (s *trialPolicySessionContext) policyUpdate(command tpm2.CommandCode, name tpm2.Name, policyRef tpm2.Nonce) {
	s.mustUpdateForCommand(command, mu.Raw(name))

	h := s.digest.HashAlg.NewHash()
	h.Write(s.digest.Digest)
	mu.MustMarshalToWriter(h, mu.Raw(policyRef))
	s.digest.Digest = h.Sum(nil)
}

func (s *trialPolicySessionContext) HashAlg() tpm2.HashAlgorithmId {
	return s.digest.HashAlg
}

func (s *trialPolicySessionContext) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	if !index.Name().IsValid() {
		return errors.New("invalid index name")
	}
	h := s.digest.HashAlg.NewHash()
	mu.MustMarshalToWriter(h, mu.Raw(operandB), offset, operation)

	s.mustUpdateForCommand(tpm2.CommandPolicyNV, mu.Raw(h.Sum(nil)), mu.Raw(index.Name()))
	return nil
}

func (s *trialPolicySessionContext) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	if !authObject.Name().IsValid() {
		return nil, nil, errors.New("invalid authObject name")
	}
	s.policyUpdate(tpm2.CommandPolicySecret, authObject.Name(), policyRef)
	return nil, nil, nil
}

func (s *trialPolicySessionContext) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	s.policyUpdate(tpm2.CommandPolicySigned, authKey.Name(), policyRef)
	return nil, nil, nil
}

func (s *trialPolicySessionContext) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	s.policyUpdate(tpm2.CommandPolicyAuthorize, keySign, policyRef)
	return nil
}

func (s *trialPolicySessionContext) PolicyAuthValue() error {
	s.mustUpdateForCommand(tpm2.CommandPolicyAuthValue)
	return nil
}

func (s *trialPolicySessionContext) PolicyCommandCode(code tpm2.CommandCode) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyCommandCode, code)
	return nil
}

func (s *trialPolicySessionContext) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	h := s.digest.HashAlg.NewHash()
	mu.MustMarshalToWriter(h, mu.Raw(operandB), offset, operation)

	s.mustUpdateForCommand(tpm2.CommandPolicyCounterTimer, mu.Raw(h.Sum(nil)))
	return nil
}

func (s *trialPolicySessionContext) PolicyCpHash(cpHashA tpm2.Digest) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyCpHash, mu.Raw(cpHashA))
	return nil
}

func (s *trialPolicySessionContext) PolicyNameHash(nameHash tpm2.Digest) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyNameHash, mu.Raw(nameHash))
	return nil
}

func (s *trialPolicySessionContext) PolicyOR(pHashList tpm2.DigestList) error {
	if len(pHashList) < 2 || len(pHashList) > 8 {
		return errors.New("invalid number of branches")
	}

	digests := new(bytes.Buffer)
	for i, digest := range pHashList {
		if len(digest) != s.digest.HashAlg.Size() {
			return fmt.Errorf("invalid digest length at branch %d", i)
		}
		digests.Write(digest)
	}
	s.mustUpdateForCommand(tpm2.CommandPolicyOR, mu.Raw(digests.Bytes()))
	return nil
}

func (s *trialPolicySessionContext) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	panic("not reached")
}

func (s *trialPolicySessionContext) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return s.updateForCommand(tpm2.CommandPolicyPCR, pcrs, mu.Raw(pcrDigest))
}

func (s *trialPolicySessionContext) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	if !newParentName.IsValid() {
		return errors.New("invalid newParent name")
	}
	if includeObject {
		if !objectName.IsValid() {
			return errors.New("invalid object name")
		}
		s.mustUpdateForCommand(tpm2.CommandPolicyDuplicationSelect, mu.Raw(objectName), mu.Raw(newParentName), includeObject)
	} else {
		s.mustUpdateForCommand(tpm2.CommandPolicyDuplicationSelect, mu.Raw(newParentName), includeObject)
	}
	return nil
}

func (s *trialPolicySessionContext) PolicyPassword() error {
	s.mustUpdateForCommand(tpm2.CommandPolicyAuthValue)
	return nil
}

func (s *trialPolicySessionContext) PolicyNvWritten(writtenSet bool) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyNvWritten, writtenSet)
	return nil
}

type trialPolicyParams struct{}

func (p *trialPolicyParams) secretParams(authName tpm2.Name, policyRef tpm2.Nonce) *PolicySecretParams {
	return nil
}

func (p *trialPolicyParams) signedAuthorization(authName tpm2.Name, policyRef tpm2.Nonce) *PolicyAuthorization {
	return new(PolicyAuthorization)
}

func (p *trialPolicyParams) ticket(authName tpm2.Name, policyRef tpm2.Nonce) *PolicyTicket {
	return nil
}

type trialPolicyResources struct {
	nvIndices map[tpm2.Handle]tpm2.Name
}

func newTrialPolicyResources(nvIndices map[tpm2.Handle]tpm2.Name) *trialPolicyResources {
	return &trialPolicyResources{nvIndices: nvIndices}
}

func (r *trialPolicyResources) loadHandle(handle tpm2.Handle) (tpm2.ResourceContext, error) {
	switch handle.Type() {
	case tpm2.HandleTypePCR, tpm2.HandleTypePermanent:
		// the handle is not relevant here
		return tpm2.NewLimitedResourceContext(0x80000000, tpm2.MakeHandleName(handle)), nil
	case tpm2.HandleTypeNVIndex:
		name, exists := r.nvIndices[handle]
		if !exists {
			return nil, errors.New("unrecognized NV index handle")
		}
		return tpm2.NewLimitedResourceContext(handle, name), nil
	default:
		return nil, errors.New("invalid handle type")
	}
}

func (r *trialPolicyResources) loadName(name tpm2.Name) (policyResourceContext, error) {
	// the handle is not relevant here
	return newPolicyResourceContextNonFlushable(tpm2.NewLimitedResourceContext(0x80000000, name)), nil
}

func (r *trialPolicyResources) loadExternal(public *tpm2.Public) (policyResourceContext, error) {
	// the handle is not relevant here
	resource, err := tpm2.NewObjectResourceContextFromPub(0x80000000, public)
	if err != nil {
		return nil, err
	}
	return newPolicyResourceContextNonFlushable(resource), nil
}

func (r *trialPolicyResources) nvReadPublic(context tpm2.HandleContext) (*tpm2.NVPublic, error) {
	return new(tpm2.NVPublic), nil
}

func (r *trialPolicyResources) authorize(context tpm2.ResourceContext) (tpm2.SessionContext, error) {
	return nil, nil
}

// PolicyComputeBranch corresponds to a branch in a policy that is being computed.
type PolicyComputeBranch struct {
	c        *PolicyComputer
	contexts []policyRunContext
	policy   *policyBranch
}

func (b *PolicyComputeBranch) runElementForEachContext(element policyElementRunner) error {
	for _, context := range b.contexts {
		if err := element.run(context); err != nil {
			return fmt.Errorf("cannot update context for algorithm %v: %w", context.session().HashAlg(), err)
		}
	}

	return nil
}

// PolicyNV adds a TPM2_PolicyNV assertion to this branch in order to bind the policy to the
// contents of the specified index. The caller specifies a value to be used for the comparison
// via the operandB argument, an offset from the start of the NV index data from which to start
// the comparison via the offset argument, and a comparison operator via the operation argument.
func (b *PolicyComputeBranch) PolicyNV(nvIndex NVIndex, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	if nvIndex.Handle().Type() != tpm2.HandleTypeNVIndex {
		return b.c.fail("PolicyNV", errors.New("nvIndex has invalid handle type"))
	}
	if name, exists := b.c.nvIndices[nvIndex.Handle()]; exists && !bytes.Equal(name, nvIndex.Name()) {
		return b.c.fail("PolicyNV", errors.New("nvIndex already exists in this profile but with a different name"))
	}

	element := &policyNV{
		NvIndex:   nvIndex.Handle(),
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyNV,
		Details: &policyElementDetails{NV: element}})
	b.c.nvIndices[nvIndex.Handle()] = nvIndex.Name()

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicySecret adds a TPM2_PolicySecret assertion to this branch so that the policy requires
// knowledge of the authorization value of the object associated with authObject.
func (b *PolicyComputeBranch) PolicySecret(authObject Named, policyRef tpm2.Nonce) error {
	var authObjectName tpm2.Name
	if authObject != nil {
		authObjectName = authObject.Name()
	}

	element := &policySecret{
		AuthObjectName: authObjectName,
		PolicyRef:      policyRef}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicySecret,
		Details: &policyElementDetails{Secret: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicySigned adds a TPM2_PolicySigned assertion to this branch so that the policy requires
// an assertion signed by the owner of the supplied key.
func (b *PolicyComputeBranch) PolicySigned(authKey *tpm2.Public, policyRef tpm2.Nonce) error {
	element := &policySigned{
		AuthKey:   authKey,
		PolicyRef: policyRef}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicySigned,
		Details: &policyElementDetails{Signed: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyAuthValue adds a TPM2_PolicyAuthValue assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyComputeBranch) PolicyAuthValue() error {
	element := new(policyAuthValue)
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyAuthValue,
		Details: &policyElementDetails{AuthValue: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyCommandCode adds a TPM2_PolicyCommandCode assertion to this branch to bind the policy
// to the specified command.
func (b *PolicyComputeBranch) PolicyCommandCode(code tpm2.CommandCode) error {
	element := &policyCommandCode{CommandCode: code}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyCommandCode,
		Details: &policyElementDetails{CommandCode: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyCounterTimer adds a TPM2_PolicyCounterTimer assertion to this branch to bind the policy
// to the contents of the [tpm2.TimeInfo] structure.
func (b *PolicyComputeBranch) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	element := &policyCounterTimer{
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyCounterTimer,
		Details: &policyElementDetails{CounterTimer: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyCpHash adds a TPM2_PolicyCpHash assertion to this branch in order to bind the policy to
// the supplied command parameters.
func (b *PolicyComputeBranch) PolicyCpHash(cpHashA CpHash) error {
	var digests taggedHashList
	for _, d := range b.policy.PolicyDigests {
		digest, err := cpHashA.Digest(d.HashAlg)
		if err != nil {
			return b.c.fail("PolicyCpHash", fmt.Errorf("cannot compute cpHash for algorithm %v: %w", d.HashAlg, err))
		}
		digests = append(digests, taggedHash{HashAlg: d.HashAlg, Digest: digest})
	}

	element := &policyCpHash{Digests: digests}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyCpHash,
		Details: &policyElementDetails{CpHash: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyNameHash adds a TPM2_PolicyNameHash assertion to this branch in order to bind the policy to
// the supplied command handles.
func (b *PolicyComputeBranch) PolicyNameHash(nameHash NameHash) error {
	var digests taggedHashList
	for _, d := range b.policy.PolicyDigests {
		digest, err := nameHash.Digest(d.HashAlg)
		if err != nil {
			return b.c.fail("PolicyNameHash", fmt.Errorf("cannot compute nameHash for algorithm %v: %w", d.HashAlg, err))
		}
		digests = append(digests, taggedHash{HashAlg: d.HashAlg, Digest: digest})
	}

	element := &policyNameHash{Digests: digests}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyNameHash,
		Details: &policyElementDetails{NameHash: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyPCR adds a TPM2_PolicyPCR assertion to this branch in order to bind the policy to the
// supplied PCR values.
func (b *PolicyComputeBranch) PolicyPCR(values tpm2.PCRValues) error {
	var pcrs pcrValueList
	for alg := range values {
		if !alg.IsValid() {
			return b.c.fail("PolicyPCR", fmt.Errorf("invalid digest algorithm %v", alg))
		}
		for pcr := range values[alg] {
			digest := values[alg][pcr]
			if len(digest) != alg.Size() {
				return b.c.fail("PolicyPCR", fmt.Errorf("invalid digest size for PCR %v, algorithm %v", pcr, alg))
			}
			pcrs = append(pcrs, pcrValue{
				PCR:    tpm2.Handle(pcr),
				Digest: taggedHash{HashAlg: alg, Digest: digest}})
		}
	}
	sort.Slice(pcrs, func(i, j int) bool {
		return pcrs[i].PCR < pcrs[j].PCR || pcrs[i].Digest.HashAlg < pcrs[j].Digest.HashAlg
	})

	element := &policyPCR{PCRs: pcrs}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyPCR,
		Details: &policyElementDetails{PCR: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyDuplicationSelect adds a TPM2_PolicyDuplicationSelect assertion to this branch in order
// to permit duplication of object to newParent with the [tpm2.TPMContext.Duplicate] function. Note
// that object must be supplied even if includeObject is false because the assertion sets the name
// hash of the session context to restrict the usage of the session to the specified pair of objects.
func (b *PolicyComputeBranch) PolicyDuplicationSelect(object, newParent Named, includeObject bool) error {
	var objectName tpm2.Name
	if object != nil {
		objectName = object.Name()
	}
	var newParentName tpm2.Name
	if newParent != nil {
		newParentName = newParent.Name()
	}

	element := &policyDuplicationSelect{
		Object:        objectName,
		NewParent:     newParentName,
		IncludeObject: includeObject}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyDuplicationSelect,
		Details: &policyElementDetails{DuplicationSelect: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyPassword adds a TPM2_PolicyPassword assertion to this branch so that the policy
// requires knowledge of the authorization value of the resource on which the policy session
// is used.
func (b *PolicyComputeBranch) PolicyPassword() error {
	element := new(policyPassword)
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyPassword,
		Details: &policyElementDetails{Password: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyNvWritten adds a TPM2_PolicyNvWritten assertion to this branch in order to bind the
// policy to the status of the [tpm2.AttrNVWritten] attribute for the NV index on which the
// session is used.
func (b *PolicyComputeBranch) PolicyNvWritten(writtenSet bool) error {
	element := &policyNvWritten{WrittenSet: writtenSet}
	b.policy.Policy = append(b.policy.Policy, &policyElement{
		Type:    tpm2.CommandPolicyNvWritten,
		Details: &policyElementDetails{NvWritten: element}})

	if err := b.runElementForEachContext(element); err != nil {
		return b.c.fail(element.name(), err)
	}

	return nil
}

// PolicyComputer provides a way to compute an authorization policy.
type PolicyComputer struct {
	root      *PolicyComputeBranch
	nvIndices map[tpm2.Handle]tpm2.Name

	err error
}

// ComputePolicy begins the process of computing an authorization policy for the specified
// algorithms.
func ComputePolicy(algs ...tpm2.HashAlgorithmId) *PolicyComputer {
	for _, alg := range algs {
		if !alg.Available() {
			panic(fmt.Sprintf("digest algorithm %v is not available", alg))
		}
	}
	c := &PolicyComputer{nvIndices: make(map[tpm2.Handle]tpm2.Name)}
	c.root = &PolicyComputeBranch{
		c:      c,
		policy: new(policyBranch),
	}
	for _, alg := range algs {
		c.root.policy.PolicyDigests = append(c.root.policy.PolicyDigests, taggedHash{HashAlg: alg, Digest: make(tpm2.Digest, alg.Size())})
	}
	for i := range c.root.policy.PolicyDigests {
		c.root.contexts = append(c.root.contexts, newPolicyRunner(
			newTrialPolicySessionContext(&c.root.policy.PolicyDigests[i]),
			new(trialPolicyParams),
			newTrialPolicyResources(c.nvIndices),
		))
	}
	return c
}

func (c *PolicyComputer) fail(name string, err error) error {
	if c.err == nil {
		c.err = fmt.Errorf("encountered an error when processing %s: %w", name, err)
	}

	return err
}

// RootBranch returns the root branch associated with the policy that is being computed.
func (c *PolicyComputer) RootBranch() *PolicyComputeBranch {
	return c.root
}

// Policy returns the computed authorization policy digests and policy metadata. The
// returned metadata can be used to execute the computed policy.
func (c *PolicyComputer) Policy() (tpm2.TaggedHashList, *Policy, error) {
	if c.err != nil {
		return nil, nil, fmt.Errorf("could not compute policy: %w", c.err)
	}

	var digests tpm2.TaggedHashList
	for _, digest := range c.root.policy.PolicyDigests {
		digests = append(digests, tpm2.MakeTaggedHash(digest.HashAlg, digest.Digest))
	}

	var policy policy
	if err := mu.CopyValue(&policy.Policy, c.root.policy.Policy); err != nil {
		return nil, nil, fmt.Errorf("cannot copy policy metadata: %w", err)
	}

	return digests, &Policy{policy: policy}, nil
}
