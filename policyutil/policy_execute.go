package policyutil

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
)

type executePolicyTickets struct {
	usageCpHash tpm2.Digest

	tickets        map[authMapKey][]*PolicyTicket
	newTickets     map[*PolicyTicket]struct{}
	invalidTickets map[*PolicyTicket]struct{}
}

func newExecutePolicyTickets(alg tpm2.HashAlgorithmId, tickets []*PolicyTicket, usage *PolicySessionUsage) (*executePolicyTickets, error) {
	var usageCpHash tpm2.Digest
	if usage != nil {
		var handleNames []Named
		for _, handle := range usage.handles {
			handleNames = append(handleNames, handle)
		}

		var err error
		usageCpHash, err = ComputeCpHash(alg, usage.commandCode, handleNames, usage.params...)
		if err != nil {
			return nil, fmt.Errorf("cannot compute cpHash from usage: %w", err)
		}

	}

	// Drop any tickets with the duplicate authName, policyRef and cpHash
	ticketsFiltered := make(map[ticketMapKey]*PolicyTicket)
	for _, ticket := range tickets {
		key := makeTicketMapKey(ticket)
		if _, exists := ticketsFiltered[key]; exists {
			continue
		}
		ticketsFiltered[key] = ticket
	}

	ticketMap := make(map[authMapKey][]*PolicyTicket)
	for _, ticket := range ticketsFiltered {
		key := makeAuthMapKey(ticket.AuthName, ticket.PolicyRef)
		if _, exists := ticketMap[key]; !exists {
			ticketMap[key] = []*PolicyTicket{}
		}
		ticketMap[key] = append(ticketMap[key], ticket)
	}

	return &executePolicyTickets{
		usageCpHash:    usageCpHash,
		tickets:        ticketMap,
		newTickets:     make(map[*PolicyTicket]struct{}),
		invalidTickets: make(map[*PolicyTicket]struct{}),
	}, nil
}

func (t *executePolicyTickets) ticket(authName tpm2.Name, policyRef tpm2.Nonce) *PolicyTicket {
	tickets := t.tickets[makeAuthMapKey(authName, policyRef)]
	if len(tickets) == 0 {
		return nil
	}
	if len(t.usageCpHash) == 0 {
		return tickets[0]
	}
	for _, ticket := range tickets {
		if len(ticket.CpHash) == 0 {
			return ticket
		}
		if bytes.Equal(ticket.CpHash, t.usageCpHash) {
			return ticket
		}
	}
	return nil
}

func (t *executePolicyTickets) addTicket(ticket *PolicyTicket) {
	if ticket.Ticket == nil || (ticket.Ticket.Hierarchy == tpm2.HandleNull && len(ticket.Ticket.Digest) == 0) {
		// skip null tickets
		return
	}

	key := makeAuthMapKey(ticket.AuthName, ticket.PolicyRef)
	if _, exists := t.tickets[key]; !exists {
		t.tickets[key] = []*PolicyTicket{}
	}
	t.tickets[key] = append([]*PolicyTicket{ticket}, t.tickets[key]...)

	t.newTickets[ticket] = struct{}{}
}

func (t *executePolicyTickets) invalidTicket(ticket *PolicyTicket) {
	key := makeAuthMapKey(ticket.AuthName, ticket.PolicyRef)

	var tickets []*PolicyTicket
	for _, tk := range t.tickets[key] {
		if tk == ticket {
			continue
		}
		tickets = append(tickets, tk)
	}
	t.tickets[key] = tickets

	if _, exists := t.newTickets[ticket]; exists {
		delete(t.newTickets, ticket)
	} else {
		t.invalidTickets[ticket] = struct{}{}
	}
}

func (t *executePolicyTickets) currentTickets() (out []*PolicyTicket) {
	for _, tickets := range t.tickets {
		for _, ticket := range tickets {
			out = append(out, ticket)
		}
	}
	return out
}

type executePolicyResourcesAuthorizer interface {
	Authorize(tpm2.ResourceContext) error
}

type policyExecuteRunner struct {
	policySessionContext SessionContext
	policySession        *teePolicySession
	policyTickets        *executePolicyTickets
	policyResources      *executePolicyResources

	authorizer executePolicyResourcesAuthorizer
	tpm        TPMHelper

	usage                *PolicySessionUsage
	ignoreAuthorizations []PolicyAuthorizationID
	ignoreNV             []Named

	pathChooser *policyPathChooser

	remaining   policyBranchPath
	currentPath policyBranchPath
}

func newPolicyExecuteRunner(session PolicySession, tickets *executePolicyTickets, resources *executePolicyResources, authorizer executePolicyResourcesAuthorizer, tpm TPMHelper, params *PolicyExecuteParams, details *PolicyBranchDetails) *policyExecuteRunner {
	return &policyExecuteRunner{
		policySessionContext: session.Context(),
		policySession: newTeePolicySession(
			session,
			newRecorderPolicySession(session.HashAlg(), details),
		),
		policyTickets:        tickets,
		policyResources:      resources,
		authorizer:           authorizer,
		tpm:                  tpm,
		usage:                params.Usage,
		ignoreAuthorizations: params.IgnoreAuthorizations,
		ignoreNV:             params.IgnoreNV,
		pathChooser:          newPolicyPathChooser(session.HashAlg(), resources, tpm, params.Usage, params.IgnoreAuthorizations, params.IgnoreNV),
		remaining:            policyBranchPath(params.Path),
	}
}

func (r *policyExecuteRunner) session() policySession {
	return r.policySession
}

func (r *policyExecuteRunner) tickets() policyTickets {
	return r.policyTickets
}

func (r *policyExecuteRunner) resources() policyResources {
	return r.policyResources
}

func (r *policyExecuteRunner) authResourceName() tpm2.Name {
	if r.usage == nil {
		return nil
	}
	return r.usage.handles[r.usage.authIndex].Name()
}

func (r *policyExecuteRunner) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	if public.IsAsymmetric() {
		return r.tpm.LoadExternal(nil, public, tpm2.HandleOwner)
	}

	if !public.Name().IsValid() {
		return nil, errors.New("invalid name")
	}
	sensitive, err := r.policyResources.externalSensitive(public.Name())
	if err != nil {
		return nil, fmt.Errorf("cannot obtain external sensitive area: %w", err)
	}

	return r.tpm.LoadExternal(sensitive, public, tpm2.HandleNull)
}

func (r *policyExecuteRunner) authorize(auth ResourceContext, askForPolicy bool, usage *PolicySessionUsage, prefer tpm2.SessionType) (sessionOut SessionContext, err error) {
	policy := auth.Policy()
	if policy == nil && askForPolicy {
		policy, err = r.policyResources.policy(auth.Resource().Name())
		if err != nil {
			return nil, fmt.Errorf("cannot load policy: %w", err)
		}
	}

	// build available session types
	availableSessionTypes := map[tpm2.SessionType]bool{
		tpm2.SessionTypeHMAC:   true,
		tpm2.SessionTypePolicy: true,
	}
	if policy == nil {
		// no policy was supplied for the resource
		availableSessionTypes[tpm2.SessionTypePolicy] = false
	}

	var alg tpm2.HashAlgorithmId

	switch auth.Resource().Handle().Type() {
	case tpm2.HandleTypeNVIndex:
		pub, err := r.tpm.NVReadPublic(auth.Resource())
		if err != nil {
			return nil, fmt.Errorf("cannot obtain NVPublic: %w", err)
		}
		switch {
		case pub.Attrs&(tpm2.AttrNVAuthRead|tpm2.AttrNVPolicyRead) == tpm2.AttrNVAuthRead:
			// index only supports auth read
			availableSessionTypes[tpm2.SessionTypePolicy] = false
		case pub.Attrs&(tpm2.AttrNVAuthRead|tpm2.AttrNVPolicyRead) == tpm2.AttrNVPolicyRead:
			// index only supports policy read
			availableSessionTypes[tpm2.SessionTypeHMAC] = false
		}
		alg = auth.Resource().Name().Algorithm()
	case tpm2.HandleTypePermanent:
		// Auth value is always available for permanent resources. Auth policy
		// is available if
		policyDigest, err := r.tpm.GetPermanentHandleAuthPolicy(auth.Resource().Handle())
		if err != nil {
			return nil, fmt.Errorf("cannot obtain permanent handle auth policy: %w", err)
		}
		switch {
		case policyDigest.HashAlg == tpm2.HashAlgorithmNull:
			// policy is not enabled for this resource
			alg = r.session().HashAlg()
			availableSessionTypes[tpm2.SessionTypePolicy] = false
		default:
			// policy is enabled for this resource
			alg = policyDigest.HashAlg
		}
	case tpm2.HandleTypeTransient, tpm2.HandleTypePersistent:
		pub, err := r.tpm.ReadPublic(auth.Resource())
		if err != nil {
			return nil, fmt.Errorf("cannot obtain Public: %w", err)
		}
		if pub.Attrs&tpm2.AttrUserWithAuth == 0 {
			// object only supports policy for user role
			availableSessionTypes[tpm2.SessionTypeHMAC] = false
		}
		alg = auth.Resource().Name().Algorithm()
	default:
		return nil, errors.New("unexpected handle type")
	}

	// Select session type
	sessionType := prefer
	if !availableSessionTypes[prefer] {
		var try tpm2.SessionType
		switch prefer {
		case tpm2.SessionTypeHMAC:
			try = tpm2.SessionTypePolicy
		case tpm2.SessionTypePolicy:
			try = tpm2.SessionTypeHMAC
		default:
			panic("invalid preferred session type")
		}
		if !availableSessionTypes[try] {
			return nil, errors.New("no auth types available")
		}
		sessionType = try
	}

	// Save the current policy session to make space for others that might be loaded
	restore, err := r.policySessionContext.Save()
	if err != nil {
		return nil, fmt.Errorf("cannot save session: %w", err)
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil && err == nil {
			err = fmt.Errorf("cannot restore saved session: %w", restoreErr)
		}
	}()

	session, policySession, err := r.tpm.StartAuthSession(sessionType, alg)
	if err != nil {
		return nil, fmt.Errorf("cannot create session to authorize auth object: %w", err)
	}
	defer func() {
		if err == nil {
			return
		}
		session.Flush()
	}()

	var authValueNeeded bool
	if sessionType == tpm2.SessionTypePolicy {
		params := &PolicyExecuteParams{
			Usage:                usage,
			IgnoreAuthorizations: r.ignoreAuthorizations,
			IgnoreNV:             r.ignoreNV,
		}

		var details PolicyBranchDetails
		runner := newPolicyExecuteRunner(policySession, r.policyTickets, r.policyResources.forSession(session), r.authorizer, r.tpm, params, &details)
		if err := runner.run(policy.policy.Policy); err != nil {
			return nil, err
		}

		authValueNeeded = details.AuthValueNeeded
	} else {
		authValueNeeded = true
	}

	if authValueNeeded {
		if err := r.authorizer.Authorize(auth.Resource()); err != nil {
			return nil, fmt.Errorf("cannot authorize resource: %w", err)
		}
	}

	return session, nil
}

func (r *policyExecuteRunner) runBranch(branches policyBranches) (selected int, err error) {
	if len(branches) == 0 {
		return 0, errors.New("no branches")
	}

	// Select a branch
	selected, name, err := r.selectBranch(branches)
	if err != nil {
		return 0, err
	}

	// Run it!
	r.currentPath = r.currentPath.Concat(name)
	if err := r.run(branches[selected].Policy); err != nil {
		return 0, err
	}

	return selected, nil
}

func (r *policyExecuteRunner) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*authorizedPolicy) (approvedPolicy tpm2.Digest, checkTicket *tpm2.TkVerified, err error) {
	if len(policies) == 0 {
		return nil, nil, errors.New("no policies")
	}

	var branches policyBranches
	for _, policy := range policies {
		branches = append(branches, &policy.policyBranch)
	}

	// Select a policy
	selected, name, err := r.selectBranch(branches)
	if err != nil {
		return nil, nil, err
	}

	policy := policies[selected]

	// The approved digest and authorization
	approvedPolicy = policy.PolicyDigests[0].Digest
	auth := policy.authorization

	// Verify the signature
	authKey, err := r.tpm.LoadExternal(nil, keySign, tpm2.HandleOwner)
	if err != nil {
		return nil, nil, err
	}
	defer authKey.Flush()

	tbs := ComputePolicyAuthorizationTBSDigest(keySign.Name().Algorithm().GetHash(), approvedPolicy, policyRef)
	ticket, err := r.tpm.VerifySignature(authKey.Resource(), tbs, auth.Signature)
	if err != nil {
		return nil, nil, err
	}

	// Run the policy
	r.currentPath = r.currentPath.Concat(name)
	if err := r.run(policy.Policy); err != nil {
		return nil, nil, err
	}

	return approvedPolicy, ticket, nil
}

func (r *policyExecuteRunner) notifyPolicyPCRDigest() error {
	return nil
}

func (r *policyExecuteRunner) selectBranch(branches policyBranches) (int, string, error) {
	// Pop the next supplied path component and find matching branches.
	var candidateIndices []int
	next, remaining := r.remaining.PopNextComponent()
	switch next {
	case "":
		// Choose from all branches
		for i := range branches {
			candidateIndices = append(candidateIndices, i)
		}
	default:
		// Filter branches
		var err error
		candidateIndices, err = branches.filterBranches(next)
		if err != nil {
			return 0, "", fmt.Errorf("cannot filter branches with pattern %q: %w", next, err)
		}
	}

	var selected int

	switch len(candidateIndices) {
	case 0:
		return 0, "", fmt.Errorf("no branch with name that matches pattern %q", next) // next is never empty here
	case 1:
		selected = candidateIndices[0]
		r.remaining = remaining
	default:
		// We have muliple candidate branches - try to automatically choose a path.
		var candidateBranches policyBranches
		for _, i := range candidateIndices {
			candidateBranches = append(candidateBranches, branches[i])
		}

		path, err := r.pathChooser.choose(candidateBranches)
		if err != nil {
			var patternStr string
			if next != "" {
				patternStr = fmt.Sprintf(" with pattern %q", next)
			}
			return 0, "", fmt.Errorf("cannot automatically choose path from branches%s: %w", patternStr, err)
		}

		switch next {
		case "":
			// Save the entire path chosen from this subtree.
			r.remaining = path
		case "**":
			// Special case for the greedy wildcard match. Prepend the entire path
			// chosen from this subtree to the remaining components.
			r.remaining = path.Concat(string(remaining))
		default:
			// Prepend the first component of the path chosen from this subtree
			// to the remaining components.
			component, _ := path.PopNextComponent()
			r.remaining = policyBranchPath(component).Concat(string(remaining))
		}

		// Pop the next path component again and find matching branches. This
		// shouldn't fail now.
		next, remaining := r.remaining.PopNextComponent()
		candidateIndices, err = branches.filterBranches(next)
		switch {
		case err != nil:
			return 0, "", fmt.Errorf("internal error: cannot filter branches after automatically choosing path: %w", err)
		case len(candidateIndices) != 1:
			return 0, "", errors.New("internal error: unexpected number of branches after automatically choosing path")
		default:
			selected = candidateIndices[0]
			r.remaining = remaining
		}
	}

	return selected, branches[selected].name(), nil
}

func (r *policyExecuteRunner) run(elements policyElements) error {
	for len(elements) > 0 {
		element := elements[0].runner()
		elements = elements[1:]
		if err := element.run(r); err != nil {
			return makePolicyError(err, r.currentPath, element.name())
		}
	}

	return nil
}

// PolicySessionUsage describes how a policy session will be used, and assists with
// automatically selecting branches where a policy has command context-specific branches.
type PolicySessionUsage struct {
	commandCode tpm2.CommandCode
	handles     []NamedHandle
	params      []interface{}
	authIndex   uint8
	noAuthValue bool
}

// NewPolicySessionUsage creates a new PolicySessionUsage. The returned usage
// will assume that the session is being used for authorization of the first
// handle, which is true in the vast majority of cases. If the session is being
// used for authorization of another handle, use [WithAuthIndex].
func NewPolicySessionUsage(command tpm2.CommandCode, handles []NamedHandle, params ...interface{}) *PolicySessionUsage {
	if len(handles) == 0 || len(handles) > 3 {
		panic("invalid number of handles")
	}
	return &PolicySessionUsage{
		commandCode: command,
		handles:     handles,
		params:      params,
	}
}

// WithAuthIndex indicates that the policy session is being used for authorization
// of the handle at the specified index (zero indexed). This is zero for most commands,
// where most commands only have a single handle that requires authorization. There are
// a few commands that require authorization for 2 handles: TPM2_ActivateCredential,
// TPM2_EventSequenceComplete, TPM2_Certify, TPM2_GetSessionAuditDigest,
// TPM2_GetCommandAuditDigest, TPM2_GetTime, TPM2_CertifyX509, TPM2_NV_UndefineSpaceSpecial,
// TPM2_NV_Certify, and TPM2_AC_Send.
func (u *PolicySessionUsage) WithAuthIndex(index uint8) *PolicySessionUsage {
	if int(index) >= len(u.handles) {
		panic("invalid index")
	}
	u.authIndex = index
	return u
}

// WithoutAuthValue indicates that the policy session is being used to authorize a
// resource that the authorization value cannot be determined for.
func (u *PolicySessionUsage) WithoutAuthValue() *PolicySessionUsage {
	u.noAuthValue = true
	return u
}

// CommandCode returns the command code for this usage.
func (u PolicySessionUsage) CommandCode() tpm2.CommandCode {
	return u.commandCode
}

// CpHash returns the command parameter hash for this usage for the specified session
// algorithm.
func (u PolicySessionUsage) CpHash(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	var handleNames []Named
	for _, handle := range u.handles {
		handleNames = append(handleNames, handle)
	}
	return ComputeCpHash(alg, u.commandCode, handleNames, u.params...)
}

// NameHash returns the name hash for this usage for the specified session algorithm.
func (u PolicySessionUsage) NameHash(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	var handleNames []Named
	for _, handle := range u.handles {
		handleNames = append(handleNames, handle)
	}
	return ComputeNameHash(alg, handleNames...)
}

// AllowAuthValue indicates whether this usage permits use of the auth value for the
// resource being authorized.
func (u PolicySessionUsage) AllowAuthValue() bool {
	return !u.noAuthValue
}

// AuthHandle returns the handle for the resource being authorized.
func (u PolicySessionUsage) AuthHandle() NamedHandle {
	return u.handles[u.authIndex]
}

// PolicyAuthorizationID contains an identifier for a TPM2_PolicySecret,
// TPM2_PolicySigned or TPM2_PolicyAuthorize assertion.
type PolicyAuthorizationID = PolicyAuthorizationDetails

// PolicyExecuteParams contains parameters that are useful for executing a policy.
type PolicyExecuteParams struct {
	// Tickets supplies tickets for TPM2_PolicySecret and TPM2_PolicySigned assertions.
	// These are also passed to sub-policies.
	Tickets []*PolicyTicket

	// Usage describes how the executed policy will be used, and assists with
	// automatically selecting branches where a policy has command context-specific
	// branches.
	Usage *PolicySessionUsage

	// Path provides a way to explicitly select branches or authorized policies to
	// execute. A path consists of zero or more components separated by a '/'
	// character, with each component identifying a branch to select when a branch
	// node is encountered (or a policy to select when an authorized policy is
	// required) during execution. When a branch node or authorized policy is
	// encountered, the selected sub-branch or policy is executed before resuming
	// execution in the original branch.
	//
	// When selecting a branch, a component can either identify a branch by its
	// name (if it has one), or it can be a numeric identifier of the form "{n}"
	// which selects the branch at index n.
	//
	// When selecting an authorized policy, a component identifies the policy by
	// specifying the digest of the policy for the current session algorithm.
	//
	// If a component is "**", then Policy.Execute will attempt to automatically
	// choose an execution path for the entire sub-tree associated with the current
	// branch node or authorized policy. This includes choosing additional
	// branches and authorized policies encountered during the execution of the
	// selected sub-tree. Remaining path components will be consumed when resuming
	// execution in the original branch
	//
	// A component can be a pattern that is compatible with filepath.Match. In the
	// case where the pattern matches more than one branch, then Policy.Execute will
	// attempt to automatically choose an immediate sub-branch or authorized policy,
	// but additional branches and authorized policies encountered during the
	// execution of the selected sub-tree will consume additional path components.
	//
	// If the path has insufficent components for the branch nodes or authorized policies
	// encountered in a policy, Policy.Execute will attempt to select an appropriate
	// execution path for the remainder of the policy automatically.
	Path string

	// IgnoreAuthorizations can be used to indicate that branches containing TPM2_PolicySigned,
	// TPM2_PolicySecret or TPM2_PolicyAuthorize assertions matching the specified ID should
	// be ignored. This can be used where these assertions have failed on previous runs.
	// This propagates to sub-policies.
	IgnoreAuthorizations []PolicyAuthorizationID

	// IgnoreNV can be used to indicate that branches containing TPM2_PolicyNV assertions
	// with an NV index matching the specified name should be ignored. This can be used where
	// these assertions have failed due to an authorization issue on previous runs. This
	// propagates to sub-policies.
	IgnoreNV []Named
}

// PolicyExecuteResult is returned from [Policy.Execute].
type PolicyExecuteResult struct {
	// NewTickets contains tickets that were created as a result of executing this policy.
	NewTickets []*PolicyTicket

	// InvalidTickets contains those tickets originally supplied to [Policy.Execute] that
	// were used but found to be invalid. These tickets shouldn't be supplied to
	// [Policy.Execute] again.
	InvalidTickets []*PolicyTicket

	// AuthValueNeeded indicates that the policy executed the TPM2_PolicyAuthValue or
	// TPM2_PolicyPassword assertion.
	AuthValueNeeded bool

	// Path indicates the executed path.
	Path string

	policyCommandCode *tpm2.CommandCode
	policyCpHash      tpm2.Digest
	policyNameHash    tpm2.Digest
	policyNvWritten   *bool
}

// CommandCode returns the command code if a TPM2_PolicyCommandCode or
// TPM2_PolicyDuplicationSelect assertion was executed.
func (r *PolicyExecuteResult) CommandCode() (code tpm2.CommandCode, set bool) {
	if r.policyCommandCode == nil {
		return 0, false
	}
	return *r.policyCommandCode, true
}

// CpHash returns the command parameter hash if a TPM2_PolicyCpHash assertion
// was executed or a TPM2_PolicySecret or TPM2_PolicySigned assertion was executed
// with a cpHash.
func (r *PolicyExecuteResult) CpHash() (cpHashA tpm2.Digest, set bool) {
	if len(r.policyCpHash) == 0 {
		return nil, false
	}
	return r.policyCpHash, true
}

// NameHash returns the name hash if a TPM2_PolicyNameHash or TPM2_PolicyDuplicationSelect
// assertion was executed.
func (r *PolicyExecuteResult) NameHash() (nameHash tpm2.Digest, set bool) {
	if len(r.policyNameHash) == 0 {
		return nil, false
	}
	return r.policyNameHash, true
}

// NvWritten returns the nvWrittenSet value if a TPM2_PolicyNvWritten assertion
// was executed.
func (r *PolicyExecuteResult) NvWritten() (nvWrittenSet bool, set bool) {
	if r.policyNvWritten == nil {
		return false, false
	}
	return *r.policyNvWritten, true
}

// Execute runs this policy using the supplied policy session.
//
// The caller may supply additional parameters via the PolicyExecuteParams struct, which is an
// optional argument.
//
// Resources required by a policy are obtained from the supplied PolicyResources, which is
// optional but must be supplied for any policy that executes TPM2_PolicyNV, TPM2_PolicySecret,
// TPM2_PolicySigned or TPM2_PolicyAuthorize assertions.
//
// Some assertions need to make use of other TPM functions. Access to these is provided via
// the TPMHelper argument. This is optional, but must be supplied for any policy that executes
// TPM2_PolicyNV, TPM2_PolicySecret, TPM2_PolicySigned, or TPM2_PolicyAuthorize assertions, or
// any policy that contains branches with TPM2_PolicyPCR or TPM2_PolicyCounterTimer assertions
// where branches aren't selected explicitly.
//
// TPM2_PolicyNV assertions will create a session for authorizing the associated NV index. The
// auth type is determined automatically from the NV index attributes, but where both HMAC and
// policy auth is supported, policy auth is used.
//
// TPM2_PolicySecret assertions will create a session for authorizing the associated resource.
// The auth type is determined automatically based on the public attributes for NV indices and
// ordinary objects, but where both HMAC and policy auth is supported, HMAC auth is used. If the
// resource is a permanent resource, then only HMAC auth is used.
//
// The caller may explicitly select branches and authorized policies to execute via the Path
// argument of [PolicyExecuteParams]. Alternatively, if a path is not specified explicitly,
// or a component contains a wildcard match, an appropriate execution path is selected
// automatically where possible. This works by selecting the first suitable path, with a
// preference for paths that don't include TPM2_PolicySecret, TPM2_PolicySigned,
// TPM2_PolicyAuthValue, and TPM2_PolicyPassword assertions. It also has a preference for paths
// that don't include TPM2_PolicyNV assertions that require authorization to use or read, and for
// paths without TPM2_PolicyCommandCode, TPM2_PolicyCpHash, TPM2_PolicyNameHash and
// TPM2_PolicyDuplicatiionSelect assertions where no [PolicySessionUsage] is supplied. A path
// is omitted from the set of suitable paths if any of the following conditions are true:
//   - It contains a command code, command parameter hash, or name hash that doesn't match
//     the supplied [PolicySessionUsage].
//   - It contains a TPM2_PolicyAuthValue or TPM2_PolicyPassword assertion and this isn't permitted
//     by the supplied [PolicySessionUsage].
//   - It uses TPM2_PolicyNvWritten with a value that doesn't match the public area of the NV index
//     that the session will be used to authorize, provided via the supplied [PolicySessionUsage].
//   - It uses TPM2_PolicySigned, TPM2_PolicySecret or TPM2_PolicyAuthorize and the specific
//     authorization is included in the IgnoreAuthorizations field of [PolicyExecuteParams].
//   - It uses TPM2_PolicyNV and the NV index is included in the IgnoreNV field of
//     [PolicyExecuteParams]
//   - It uses TPM2_PolicyNV with conditions that will fail against the current NV index contents,
//     if the index has an authorization policy that permits the use of TPM2_NV_Read without any
//     other conditions, else the condition isn't checked.
//   - It uses TPM2_PolicyPCR with values that don't match the current PCR values.
//   - It uses TPM2_PolicyCounterTimer with conditions that will fail.
//
// Note that this automatic selection makes the following assumptions:
//   - TPM2_PolicySecret assertions always succeed. Where they are known to not succeed because
//     the authorization value isn't known or the resource can't be loaded, add the assertion
//     details to the IgnoreAuthorizations field of [PolicyExecuteParams].
//   - TPM2_PolicySigned assertions always succeed. Where they are known to not succeed because
//     an assertion can't be provided or it is invalid, add the assertion details to the
//     IgnoreAuthorizations field of [PolicyExecuteParams].
//   - TPM2_PolicyAuthorize assertions always succeed if policies are returned from the
//     implementation of [PolicyResourceLoader.LoadAuthorizedPolicies]. Where these are known
//     to not succeed, add the assertion details to the IgnoreAuthorizations field of
//     [PolicyExecuteParams].
//   - TPM2_PolicyNV assertions on NV indexes that require authorization to read will always
//     succeed. Where these are known to not suceed, add the assertion details to the IgnoreNV
//     field of [PolicyExecuteParams].
//
// On success, the supplied policy session may be used for authorization in a context that requires
// that this policy is satisfied. Information about the result of executing the session is also
// returned.
func (p *Policy) Execute(session PolicySession, resources PolicyExecuteResources, tpm TPMHelper, params *PolicyExecuteParams) (result *PolicyExecuteResult, err error) {
	if session == nil {
		return nil, errors.New("no session")
	}
	if resources == nil {
		resources = new(nullPolicyResources)
	}
	if tpm == nil {
		tpm = new(nullTpmHelper)
	}
	if params == nil {
		params = new(PolicyExecuteParams)
	}

	tickets, err := newExecutePolicyTickets(session.HashAlg(), params.Tickets, params.Usage)
	if err != nil {
		return nil, err
	}

	var details PolicyBranchDetails
	runner := newPolicyExecuteRunner(
		session,
		tickets,
		newExecutePolicyResources(session.Context(), resources, tickets, params.IgnoreAuthorizations, params.IgnoreNV),
		resources,
		tpm,
		params,
		&details,
	)
	if err := runner.run(p.policy.Policy); err != nil {
		return nil, err
	}

	result = &PolicyExecuteResult{
		AuthValueNeeded: details.AuthValueNeeded,
		Path:            string(runner.currentPath),
	}
	if commandCode, set := details.CommandCode(); set {
		result.policyCommandCode = &commandCode
	}
	if cpHash, set := details.CpHash(); set {
		result.policyCpHash = cpHash
	}
	if nameHash, set := details.NameHash(); set {
		result.policyNameHash = nameHash
	}
	if nvWritten, set := details.NvWritten(); set {
		result.policyNvWritten = &nvWritten
	}

	for ticket := range tickets.newTickets {
		result.NewTickets = append(result.NewTickets, ticket)
	}
	for ticket := range tickets.invalidTickets {
		result.InvalidTickets = append(result.InvalidTickets, ticket)
	}

	return result, nil
}
