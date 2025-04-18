// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/canonical/go-tpm2/ppi"
)

type acpiPpiImpl struct {
	sysfsPath string
	Version   ppi.Version

	opsOnce  sync.Once
	ops      map[ppi.OperationId]ppi.OperationStatus
	opsError error
}

func (p *acpiPpiImpl) SubmitOperation(op ppi.OperationId, arg *uint32) error {
	if arg != nil && p.Version.Compare(ppi.Version13) < 0 {
		return ppi.ErrOperationUnsupported
	}

	f, err := os.OpenFile(filepath.Join(p.sysfsPath, "request"), os.O_WRONLY, 0)
	switch {
	case errors.Is(err, os.ErrPermission):
		return ppi.ErrPermission
	case err != nil:
		return err
	}
	defer f.Close()

	cmd := strconv.FormatUint(uint64(op), 10)
	if arg != nil {
		cmd += " " + strconv.FormatUint(uint64(*arg), 10)
	}

	_, err = f.WriteString(cmd)
	switch {
	case errors.Is(err, os.ErrPermission):
		return ppi.ErrOperationUnsupported
	case errors.Is(err, syscall.EFAULT):
		return ppi.ErrOperationFailed
	default:
		return err
	}
}

func (p *acpiPpiImpl) StateTransitionAction() (ppi.StateTransitionAction, error) {
	actionBytes, err := os.ReadFile(filepath.Join(p.sysfsPath, "transition_action"))
	if err != nil {
		return 0, err
	}

	var action ppi.StateTransitionAction
	var dummy string
	if _, err := fmt.Sscanf(string(actionBytes), "%d:%s\n", &action, &dummy); err != nil {
		return 0, fmt.Errorf("cannot scan transition action %q: %w", string(actionBytes), err)
	}
	if action > ppi.StateTransitionActionOSVendorSpecific {
		return 0, fmt.Errorf("invalid transition action %d", action)
	}

	return action, nil
}

func (p *acpiPpiImpl) OperationStatus(op ppi.OperationId) (ppi.OperationStatus, error) {
	p.opsOnce.Do(func() {
		p.ops, p.opsError = func() (map[ppi.OperationId]ppi.OperationStatus, error) {
			opsFile, err := os.OpenFile(filepath.Join(p.sysfsPath, "tcg_operations"), os.O_RDONLY, 0)
			if err != nil {
				return nil, err
			}
			defer opsFile.Close()

			ops := make(map[ppi.OperationId]ppi.OperationStatus)

			scanner := bufio.NewScanner(opsFile)
			for scanner.Scan() {
				var op ppi.OperationId
				var status ppi.OperationStatus
				if _, err := fmt.Sscanf(scanner.Text(), "%d%d", &op, &status); err != nil {
					return nil, fmt.Errorf("cannot scan operation \"%s\": %w", scanner.Text(), err)
				}

				ops[op] = status
			}

			switch {
			case errors.Is(scanner.Err(), syscall.EPERM):
				return nil, ppi.ErrOperationUnsupported
			case scanner.Err() != nil:
				return nil, err
			}

			return ops, nil
		}()
	})

	if p.opsError != nil {
		return 0, p.opsError
	}

	status, implemented := p.ops[op]
	if !implemented {
		return ppi.OperationNotImplemented, nil
	}
	if status > ppi.OperationPPNotRequired {
		return 0, fmt.Errorf("invalid operation status %d", status)
	}
	return status, nil
}

func (p *acpiPpiImpl) OperationResponse() (*ppi.OperationResponse, error) {
	rspBytes, err := os.ReadFile(filepath.Join(p.sysfsPath, "response"))
	switch {
	case errors.Is(err, syscall.EFAULT):
		return nil, ppi.ErrOperationFailed
	case err != nil:
		return nil, err
	}

	rsp := string(rspBytes)

	var arg1, arg2 uint32
	if _, err := fmt.Sscanf(rsp, "%d", &arg1); err != nil {
		return nil, fmt.Errorf("cannot scan response %q: %w", rsp, err)
	}
	if arg1 == 0 {
		return nil, nil
	}

	if _, err := fmt.Sscanf(rsp, "%d%v:", &arg1, &arg2); err != nil {
		return nil, fmt.Errorf("cannot scan response %q: %w", rsp, err)
	}

	r := &ppi.OperationResponse{Operation: ppi.OperationId(arg1)}
	if arg2 != 0 {
		r.Err = ppi.OperationError(arg2)
	}
	return r, nil
}

func newAcpiPpi(path string) (*acpiPpiImpl, error) {
	versionBytes, err := os.ReadFile(filepath.Join(path, "version"))
	if err != nil {
		return nil, err
	}

	version, err := ppi.ParseVersion(strings.TrimSpace(string(versionBytes)))
	if err != nil {
		return nil, fmt.Errorf("cannot parse version: %w", err)
	}

	return &acpiPpiImpl{
		sysfsPath: path,
		Version:   version,
	}, nil
}
