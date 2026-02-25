// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
)

var errTreeWalkerSkipBranch = errors.New("")

type treeWalkerCompleteFullPathRunner struct {
	walker    *treeWalker
	depth     int
	branchCtx treeWalkerBranchContext
}

func (treeWalkerCompleteFullPathRunner) name() string { return "complete full path" }

func (r treeWalkerCompleteFullPathRunner) run(_ policyRunner) error {
	if r.walker.depth != r.depth {
		return nil
	}
	return r.branchCtx.completeFullPath()
}

type treeWalkerPolicyAuthorizeRunner struct {
	keySign   *tpm2.Public
	policyRef tpm2.Nonce
}

func (r *treeWalkerPolicyAuthorizeRunner) name() string {
	return "TPM2_PolicyAuthorize assertion"
}

func (r *treeWalkerPolicyAuthorizeRunner) run(runner policyRunner) error {
	return runner.session().PolicyAuthorize(nil, r.policyRef, r.keySign.Name(), nil)
}

// treeWalkerBranchContext allows the caller to associate context with
// a branch.
type treeWalkerBranchContext interface {
	session() policySession

	// beginBranchNode is called when a new branch node is encountered.
	beginBranchNode() (treeWalkerBranchNodeContext, error)

	// completeFullPath is called when there are no more elements in
	// this path. This is only called on the last branch of a path.
	completeFullPath() error
}

// treeWalkerBranchNodeContext allows the caller to associate context
// with a branch node.
type treeWalkerBranchNodeContext interface {
	// beginBranch is called when entering a new branch.
	beginBranch(name string) (treeWalkerBranchContext, error)
}

// treeWalker walks every path of elements in a policy, or from a single branch node.
type treeWalker struct {
	policyTickets     nullTickets
	policyResources   policyResources
	rootBranchNodeCtx treeWalkerBranchNodeContext

	currentPath policyBranchPath
	branchCtx   treeWalkerBranchContext
	depth       int

	remaining []policyElementRunner
}

func newTreeWalker(resources policyResources, rootBranchNodeCtx treeWalkerBranchNodeContext) *treeWalker {
	return &treeWalker{
		policyResources:   resources,
		rootBranchNodeCtx: rootBranchNodeCtx,
	}
}

func (w *treeWalker) walkBranch(branchNodeCtx treeWalkerBranchNodeContext, index int, branch *policyBranch, remaining []policyElementRunner) error {
	name := branch.name()

	branchCtx, err := branchNodeCtx.beginBranch(name)
	if err != nil {
		if err == errTreeWalkerSkipBranch {
			return nil
		}
		return fmt.Errorf("cannot begin branch: %w", err)
	}

	origBranchCtx := w.branchCtx
	origPath := w.currentPath
	defer func() {
		w.branchCtx = origBranchCtx
		w.currentPath = origPath
		w.depth--
	}()

	w.branchCtx = branchCtx
	w.currentPath = w.currentPath.Concat(name)
	w.depth++

	var elements []policyElementRunner
	for _, element := range branch.Policy {
		elements = append(elements, element.runner())
	}
	remaining = append(remaining, &treeWalkerCompleteFullPathRunner{walker: w, depth: w.depth, branchCtx: branchCtx})
	return w.runInternal(append(elements, remaining...))
}

func (w *treeWalker) session() policySession {
	return w.branchCtx.session()
}

func (w *treeWalker) tickets() policyTickets {
	return &w.policyTickets
}

func (w *treeWalker) resources() policyResources {
	return w.policyResources
}

func (r *treeWalker) authResourceName() tpm2.Name {
	return nil
}

func (w *treeWalker) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewResourceContext(0x80000000, public.Name())
	return newResourceContext(resource, nil), nil
}

func (w *treeWalker) cpHash(cpHash *policyCpHashElement) error {
	return nil
}

func (w *treeWalker) nameHash(nameHash *policyNameHashElement) error {
	return nil
}

func (w *treeWalker) authorize(auth ResourceContext, askForPolicy bool, commandParams *authorizationCommandParams, prefer tpm2.SessionType) (SessionContext, error) {
	return new(mockSessionContext), nil
}

func (w *treeWalker) runBranch(branches policyBranches) (int, error) {
	if len(branches) == 0 {
		return 0, errors.New("branch node with no branches")
	}

	remaining := w.remaining
	w.remaining = nil

	branchNodeCtx, err := w.branchCtx.beginBranchNode()
	if err != nil {
		return 0, fmt.Errorf("cannot begin branch node: %w", err)
	}

	for i, branch := range branches {
		if err := w.walkBranch(branchNodeCtx, i, branch, remaining); err != nil {
			return 0, fmt.Errorf("cannot walk branch %d: %w", i, err)
		}
	}

	return 0, nil
}

func (w *treeWalker) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*authorizedPolicy) (tpm2.Digest, *tpm2.TkVerified, error) {
	remaining := w.remaining
	w.remaining = nil

	remaining = append([]policyElementRunner{&treeWalkerPolicyAuthorizeRunner{
		keySign:   keySign,
		policyRef: policyRef,
	}}, remaining...)

	branchNodeCtx, err := w.branchCtx.beginBranchNode()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot begin authorized policy node: %w", err)
	}

	if len(policies) > 0 {
		for i, policy := range policies {
			if err := w.walkBranch(branchNodeCtx, i, &policy.policyBranch, remaining); err != nil {
				return nil, nil, fmt.Errorf("cannot walk policy: %w", err)
			}
		}
	} else {
		if err := w.walkBranch(branchNodeCtx, 0, &policyBranch{Name: policyBranchName(fmt.Sprintf("<authorize:key:%#x,ref:%#x>", keySign.Name(), policyRef))}, remaining); err != nil {
			return nil, nil, fmt.Errorf("cannot walk missing policy: %w", err)
		}
	}

	return nil, nil, nil
}

func (r *treeWalker) notifyPolicyPCRDigest() error {
	return nil
}

func (w *treeWalker) runInternal(elements []policyElementRunner) error {
	w.remaining = elements
	for len(w.remaining) > 0 {
		element := w.remaining[0]
		w.remaining = w.remaining[1:]
		if err := element.run(w); err != nil {
			return makePolicyError(err, w.currentPath, element.name())
		}
	}
	return nil
}

func (w *treeWalker) run(elements policyElements) error {
	w.currentPath = ""
	w.depth = 0

	rootBranchCtx, err := w.rootBranchNodeCtx.beginBranch("")
	if err != nil {
		return err
	}

	w.branchCtx = rootBranchCtx

	defer func() {
		w.branchCtx = nil
	}()

	var elementsCopy []policyElementRunner
	for _, element := range elements {
		elementsCopy = append(elementsCopy, element.runner())
	}
	elementsCopy = append(elementsCopy, &treeWalkerCompleteFullPathRunner{walker: w, depth: w.depth, branchCtx: rootBranchCtx})
	return w.runInternal(elementsCopy)
}
