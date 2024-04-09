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

type (
	treeWalkerBeginBranchNodeFn  func() (treeWalkerBeginBranchFn, error)
	treeWalkerBeginBranchFn      func(string) (policySession, treeWalkerBeginBranchNodeFn, treeWalkerCompleteFullPathFn, error)
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

	remaining []policyElementRunner
}

func newTreeWalker(resources policyResources, beginRootBranchFn treeWalkerBeginBranchFn) *treeWalker {
	return &treeWalker{
		policyResources:   resources,
		beginRootBranchFn: beginRootBranchFn,
	}
}

func (w *treeWalker) walkBranch(beginBranchFn treeWalkerBeginBranchFn, index int, branch *policyBranch, remaining []policyElementRunner) error {
	name := string(branch.Name)
	if len(name) == 0 {
		name = fmt.Sprintf("{%d}", index)
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

	var elements []policyElementRunner
	for _, element := range branch.Policy {
		elements = append(elements, element.runner())
	}
	return w.runInternal(append(elements, remaining...))
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

func (r *treeWalker) authResourceName() tpm2.Name {
	return nil
}

func (w *treeWalker) loadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewLimitedResourceContext(0x80000000, public.Name())
	return newResourceContext(resource, nil), nil
}

func (w *treeWalker) cpHash(cpHash *policyCpHashElement) error {
	return nil
}

func (w *treeWalker) nameHash(nameHash *policyNameHashElement) error {
	return nil
}

func (w *treeWalker) authorize(auth ResourceContext, askForPolicy bool, usage *PolicySessionUsage, prefer tpm2.SessionType) (SessionContext, error) {
	return new(mockSessionContext), nil
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

func (w *treeWalker) runAuthorizedPolicy(keySign *tpm2.Public, policyRef tpm2.Nonce, policies []*authorizedPolicy) (tpm2.Digest, *tpm2.TkVerified, error) {
	remaining := w.remaining
	w.remaining = nil

	remaining = append([]policyElementRunner{&treeWalkerPolicyAuthorizeRunner{
		keySign:   keySign,
		policyRef: policyRef,
	}}, remaining...)

	beginBranchFn, err := w.beginBranchNodeFn()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot begin authorized policy node: %w", err)
	}

	if len(policies) > 0 {
		for i, policy := range policies {
			if err := w.walkBranch(beginBranchFn, i, &policy.policyBranch, remaining); err != nil {
				return nil, nil, fmt.Errorf("cannot walk policy: %w", err)
			}
		}
	} else {
		if err := w.walkBranch(beginBranchFn, 0, &policyBranch{Name: policyBranchName(fmt.Sprintf("<authorize:key:%#x,ref:%#x>", keySign.Name(), policyRef))}, remaining); err != nil {
			return nil, nil, fmt.Errorf("cannot walk missing policy: %w", err)
		}
	}

	return nil, nil, nil
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

	var elementsCopy []policyElementRunner
	for _, element := range elements {
		elementsCopy = append(elementsCopy, element.runner())
	}
	return w.runInternal(elementsCopy)
}
