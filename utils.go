// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
)

// ComputeCpHash computes a command parameter digest from the specified command code and provided command
// parameters, using the digest algorithm specified by hashAlg. The params argument corresponds to the handle and
// parameters area of a command (in that order), separated by the Separator sentinel value. Handle arguments must
// be represented by either the Handle type or ResourceContext type.
//
// The number of command handles and number / type of command parameters can be determined by looking in part 3
// of the TPM 2.0 Library Specification for the specific command.
//
// The result of this is useful for extended authorization commands that bind an authorization to a command and
// set of command parameters, such as TPMContext.PolicySigned, TPMContext.PolicySecret, TPMContext.PolicyTicket
// and TPMContext.PolicyCpHash.
func ComputeCpHash(hashAlg AlgorithmId, command CommandCode, params ...interface{}) (Digest, error) {
	var handles []Name
	var i int

	for _, param := range params {
		if param == Separator {
			break
		}
		i++
		switch p := param.(type) {
		case Handle:
			handles = append(handles, permanentContext(p).Name())
		case ResourceContext:
			handles = append(handles, p.Name())
		default:
			return nil, makeInvalidParamError("params",
				"parameter in handle area is not a Handle or ResourceContext")
		}
	}

	var cpBytes []byte

	if i < len(params)-1 {
		var err error
		cpBytes, err = MarshalToBytes(params[i+1:]...)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal command parameters: %v", err)
		}
	}

	return cryptComputeCpHash(hashAlg, command, handles, cpBytes), nil
}
