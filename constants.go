// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"math"
)

const (
	DefaultRSAExponent = 65537
)

const (
	TPMManufacturerAMD  TPMManufacturer = 0x414D4400 // AMD
	TPMManufacturerATML TPMManufacturer = 0x41544D4C // Atmel
	TPMManufacturerBRCM TPMManufacturer = 0x4252434D // Broadcom
	TPMManufacturerHPE  TPMManufacturer = 0x48504500 // HPE
	TPMManufacturerIBM  TPMManufacturer = 0x49424d00 // IBM
	TPMManufacturerIFX  TPMManufacturer = 0x49465800 // Infineon
	TPMManufacturerINTC TPMManufacturer = 0x494E5443 // Intel
	TPMManufacturerLEN  TPMManufacturer = 0x4C454E00 // Lenovo
	TPMManufacturerMSFT TPMManufacturer = 0x4D534654 // Microsoft
	TPMManufacturerNSM  TPMManufacturer = 0x4E534D20 // National Semiconductor
	TPMManufacturerNTZ  TPMManufacturer = 0x4E545A00 // Nationz
	TPMManufacturerNTC  TPMManufacturer = 0x4E544300 // Nuvoton Technology
	TPMManufacturerQCOM TPMManufacturer = 0x51434F4D // Qualcomm
	TPMManufacturerSMSC TPMManufacturer = 0x534D5343 // SMSC
	TPMManufacturerSTM  TPMManufacturer = 0x53544D20 // ST Microelectronics
	TPMManufacturerSMSN TPMManufacturer = 0x534D534E // Samsung
	TPMManufacturerSNS  TPMManufacturer = 0x534E5300 // Sinosun
	TPMManufacturerTXN  TPMManufacturer = 0x54584E00 // Texas Instruments
	TPMManufacturerWEC  TPMManufacturer = 0x57454300 // Winbond
	TPMManufacturerROCC TPMManufacturer = 0x524F4343 // Fuzhou Rockchip
	TPMManufacturerGOOG TPMManufacturer = 0x474F4F47 // Google
)

const (
	CapabilityMaxProperties uint32 = math.MaxUint32
)

const (
	// CFBKey is used as the label for the symmetric key derivation used
	// in parameter encryption.
	CFBKey = "CFB"

	// DuplicateString is used as the label for secret sharing used by
	// object duplication.
	DuplicateString = "DUPLICATE"

	// IdentityKey is used as the label for secret sharing used by
	// when issuing and using credentials.
	IdentityKey = "IDENTITY"

	// IntegrityKey is used as the label for the HMAC key derivation
	// used for outer wrappers.
	IntegrityKey = "INTEGRITY"

	// SecretKey is used as the label for secret sharing used by
	// TPM2_StartAuthSession.
	SecretKey = "SECRET"

	// SessionKey is used as the label for the session key derivation.
	SessionKey = "ATH"

	// StorageKey is used as the label for the symmetric key derivation
	// used for encrypting and decrypting outer wrappers.
	StorageKey = "STORAGE"
)
