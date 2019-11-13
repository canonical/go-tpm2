// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
	"testing"
)

func TestGetCapabilityAlgs(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	data, err := tpm.GetCapabilityAlgs(AlgorithmFirst, CapabilityMaxProperties)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("algorithm property list is empty")
	}

	count := 0
	expected := 16

	for _, prop := range data {
		var a AlgorithmAttributes
		switch prop.Alg {
		case AlgorithmRSA:
			a = AttrAsymmetric | AttrObject
		case AlgorithmSHA1:
			a = AttrHash
		case AlgorithmHMAC:
			a = AttrHash | AttrSigning
		case AlgorithmAES:
			a = AttrSymmetric
		case AlgorithmKeyedHash:
			a = AttrHash | AttrEncrypting | AttrSigning | AttrObject
		case AlgorithmXOR:
			a = AttrHash | AttrSymmetric
		case AlgorithmSHA256:
			a = AttrHash
		case AlgorithmRSASSA:
			a = AttrAsymmetric | AttrSigning
		case AlgorithmRSAES:
			a = AttrAsymmetric | AttrEncrypting
		case AlgorithmRSAPSS:
			a = AttrAsymmetric | AttrSigning
		case AlgorithmOAEP:
			a = AttrAsymmetric | AttrEncrypting
		case AlgorithmECDSA:
			a = AttrAsymmetric | AttrSigning | AttrMethod
		case AlgorithmECDH:
			a = AttrAsymmetric | AttrMethod
		case AlgorithmECDAA:
			a = AttrAsymmetric | AttrSigning
		case AlgorithmECC:
			a = AttrAsymmetric | AttrObject
		case AlgorithmSymCipher:
			a = AttrObject
		default:
			continue
		}
		if a != prop.Properties {
			t.Errorf("Unexpected attributes for algorithm %v (got %v, expected %v)",
				prop.Alg, prop.Properties, a)
		}
		count++
	}

	if count < expected {
		t.Errorf("GetCapability didn't return attributes for all of the algorithms expected")
	}
}

func TestGetCapabilityCommands(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	data, err := tpm.GetCapabilityCommands(CommandFirst, CapabilityMaxProperties)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("command attribute list is empty")
	}

	count := 0
	expected := 12

	for _, attr := range data {
		var a CommandAttributes
		switch attr.CommandCode() {
		case CommandEvictControl:
			a = AttrNV | 0x2<<25
		case CommandNVUndefineSpace:
			a = AttrNV | 0x2<<25
		case CommandClear:
			a = AttrNV | AttrExtensive | 0x1<<25
		case CommandDictionaryAttackLockReset:
			a = AttrNV | 0x1<<25
		case CommandStartup:
			a = AttrNV
		case CommandCertify:
			a = 0x2 << 25
		case CommandLoad:
			a = 0x1<<25 | AttrRHandle
		case CommandContextSave:
			a = 0x1 << 25
		case CommandStartAuthSession:
			a = 0x2<<25 | AttrRHandle
		case CommandGetCapability:
		case CommandPCRRead:
		case CommandPolicyPCR:
			a = 0x1 << 25
		default:
			continue
		}
		a |= CommandAttributes(attr.CommandCode())
		if a != attr {
			t.Errorf("Unexpected attributes for command %v (got 0x%08x, expected 0x%08x)", attr.CommandCode(), attr, a)
		}
		count++
	}
	if count < expected {
		t.Errorf("GetCapability didn't return attributes for all of the commands expected")
	}
}

func TestGetCapabilityHandles(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	data, err := tpm.GetCapabilityHandles(HandleTypePermanent.BaseHandle(), CapabilityMaxProperties)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("command attribute list is empty")
	}

	checkIsInList := func(i Handle) {
		for _, h := range data {
			if h == i {
				return
			}
		}
		t.Errorf("Handle 0x%08x not in list of permanent handles", i)
	}

	checkIsInList(HandleOwner)
	checkIsInList(HandleNull)
	checkIsInList(HandlePW)
	checkIsInList(HandleLockout)
	checkIsInList(HandleEndorsement)
	checkIsInList(HandlePlatform)
	checkIsInList(HandlePlatformNV)
}

func TestGetCapabilityPCRs(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	data, err := tpm.GetCapabilityPCRs()
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("command attribute list is empty")
	}
}

func TestGetCapabilityTPMProperties(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	data, err := tpm.GetCapabilityTPMProperties(PropertyFixed, CapabilityMaxProperties)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("TPM property list is empty")
	}

	count := 0
	expected := 4

	// Check a few properties
	for _, prop := range data {
		var val uint32
		switch prop.Property {
		case PropertyLevel:
			val = 0
		case PropertyPCRCount:
			val = 24
		case PropertyPCRSelectMin:
			val = 3
		case PropertyContextHash:
			found := false
			for _, a := range []AlgorithmId{AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA384,
				AlgorithmSHA512} {
				if uint32(a) == prop.Value {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("GetCapbility returned unexpected value %d for property %v",
					prop.Value, prop.Property)
			}
			count++
			continue
		default:
			continue
		}

		if prop.Value != val {
			t.Errorf("GetCapbility returned unexpected value %d for property %v",
				prop.Value, prop.Property)
		}

		count++
	}

	if count < expected {
		t.Errorf("GetCapability didn't return values for all of the properties expected")
	}
}

func TestGetCapabilityPCRProperties(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	data, err := tpm.GetCapabilityPCRProperties(PropertyPCRFirst, CapabilityMaxProperties)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("TPM property list is empty")
	}
}

func TestGetManufacturer(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	id, err := tpm.GetManufacturer()
	if err != nil {
		t.Fatalf("GetManufacturer failed: %v", err)
	}

	m := fmt.Sprintf("%s", id)
	switch m {
	case "IBM", "Microsoft":
	default:
		t.Errorf("Unexpected manufacturer: %v", id)
	}
}

func TestTestParms(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc  string
		parms *PublicParams
		valid bool
		err   ErrorCode
	}{
		{
			desc: "RSARestrictedDecrypt",
			parms: &PublicParams{
				Type: ObjectTypeRSA,
				Parameters: PublicParamsU{
					Data: &RSAParams{
						Symmetric: SymDefObject{
							Algorithm: SymObjectAlgorithmAES,
							KeyBits:   SymKeyBitsU{Data: uint16(128)},
							Mode:      SymModeU{Data: SymModeCFB}},
						Scheme:   RSAScheme{Scheme: RSASchemeNull},
						KeyBits:  2048,
						Exponent: 0}}},
			valid: true,
		},
		{
			desc: "ECCSigning",
			parms: &PublicParams{
				Type: ObjectTypeECC,
				Parameters: PublicParamsU{
					Data: &ECCParams{
						Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
						Scheme: ECCScheme{
							Scheme:  ECCSchemeECDSA,
							Details: AsymSchemeU{Data: &SigSchemeECDSA{HashAlg: HashAlgorithmSHA256}}},
						CurveID: ECCCurveNIST_P256,
						KDF:     KDFScheme{Scheme: KDFAlgorithmNull}}}},
			valid: true,
		},
		{
			desc: "RSAInvalidKeyBits",
			parms: &PublicParams{
				Type: ObjectTypeRSA,
				Parameters: PublicParamsU{
					Data: &RSAParams{
						Symmetric: SymDefObject{
							Algorithm: SymObjectAlgorithmAES,
							KeyBits:   SymKeyBitsU{Data: uint16(128)},
							Mode:      SymModeU{Data: SymModeCFB}},
						Scheme:   RSAScheme{Scheme: RSASchemeNull},
						KeyBits:  2047,
						Exponent: 0}}},
			err: ErrorValue,
		},
		{
			desc: "Symmetric",
			parms: &PublicParams{
				Type: ObjectTypeSymCipher,
				Parameters: PublicParamsU{
					Data: &SymCipherParams{
						Sym: SymDefObject{
							Algorithm: SymObjectAlgorithmAES,
							KeyBits:   SymKeyBitsU{Data: uint16(256)},
							Mode:      SymModeU{Data: SymModeCFB}}}}},
			valid: true,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			err := tpm.TestParms(data.parms)
			if data.valid {
				if err != nil {
					t.Errorf("TestParms failed: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected TestParms to fail")
				}
				if e, ok := err.(*TPMParameterError); !ok || e.Code() != data.err || e.Index != 1 {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
