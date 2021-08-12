// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// This file contains types defined in section 8 (Attributes) in
// part 2 of the library spec.

// AlgorithmAttributes corresponds to the TPMA_ALGORITHM type and
// represents the attributes for an algorithm.
type AlgorithmAttributes uint32

// ObjectAttributes corresponds to the TPMA_OBJECT type, and represents
// the attributes for an object.
type ObjectAttributes uint32

// SessionAttributes corresponds to the TPMA_SESSION type, and represents
// the attributes for a session.
type SessionAttributes uint8

func (a SessionAttributes) canonicalize() SessionAttributes {
	if a&AttrAuditExclusive > 0 {
		a |= AttrAudit
	}
	if a&AttrAuditReset > 0 {
		a |= AttrAudit
	}
	return a
}

// Locality corresponds to the TPMA_LOCALITY type.
type Locality uint8

// PermanentAttributes corresponds to the TPMA_PERMANENT type and is returned
// when querying the value of PropertyPermanent.
type PermanentAttributes uint32

// StatupClearAttributes corresponds to the TPMA_STARTUP_CLEAR type and is
// returned when querying the value of PropertyStartupClear.
type StartupClearAttributes uint32

// CommandAttributes corresponds to the TPMA_CC type and represents the
// attributes of a command. It also encodes the command code to which these
// attributes belong, and the number of command handles for the command.
type CommandAttributes uint32

// CommandCode returns the command code that a set of attributes belongs to.
func (a CommandAttributes) CommandCode() CommandCode {
	return CommandCode(a & (AttrV | 0xffff))
}

// NumberOfCommandHandles returns the number of command handles for the
// command that a set of attributes belong to.
func (a CommandAttributes) NumberOfCommandHandles() int {
	return int((a & 0x0e000000) >> 25)
}
