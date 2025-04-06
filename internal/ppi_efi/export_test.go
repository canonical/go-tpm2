// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_efi

type (
	EfiPpiImpl             = efiPpiImpl
	PhysicalPresence       = physicalPresence
	PhysicalPresenceConfig = physicalPresenceConfig
	PhysicalPresenceFlags  = physicalPresenceFlags
)

var (
	ReadPhysicalPresence = readPhysicalPresence
)
