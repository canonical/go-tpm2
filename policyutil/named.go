// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"github.com/canonical/go-tpm2"
)

// Named is some resource that has a name.
type Named interface {
	Name() tpm2.Name
}

// NamedHandle is some resource that has a name and a handle.
type NamedHandle interface {
	Handle() tpm2.Handle
	Named
}
