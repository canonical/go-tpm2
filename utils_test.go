package tpm2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

type mockResourceContext struct {
	name Name
}

func (c *mockResourceContext) Name() Name {
	return c.name
}
func (c *mockResourceContext) Handle() Handle {
	return HandleNull
}

func TestComputeCpHash(t *testing.T) {
	h := sha256.New()
	h.Write([]byte("foo"))
	name, _ := MarshalToBytes(AlgorithmSHA256, RawBytes(h.Sum(nil)))
	rc := &mockResourceContext{name}

	for _, data := range []struct {
		desc     string
		alg      AlgorithmId
		command  CommandCode
		params   []interface{}
		expected Digest
	}{
		{
			desc:    "Unseal",
			alg:     AlgorithmSHA256,
			command: CommandUnseal,
			params:  []interface{}{rc},
			expected: Digest{0xe5, 0xe8, 0x03, 0xe4, 0xcb, 0xd3, 0x3f, 0x78, 0xc5, 0x65, 0x1b, 0x49, 0xf2, 0x83, 0xba, 0x63, 0x8a, 0xdf, 0x34,
				0xca, 0x69, 0x60, 0x76, 0x40, 0xfb, 0xea, 0x9e, 0xe2, 0x89, 0xfd, 0x93, 0xe7},
		},
		{
			desc:    "EvictControl",
			alg:     AlgorithmSHA1,
			command: CommandEvictControl,
			params:  []interface{}{HandleOwner, rc, Handle(0x8100ffff)},
			expected: Digest{0x40, 0x93, 0x38, 0x44, 0x00, 0xde, 0x24, 0x3a, 0xcb, 0x81, 0x04, 0xba, 0x14, 0xbf, 0x2f, 0x2e, 0xf8, 0xa8, 0x27,
				0x0b},
		},
		{
			desc:    "DAParameters",
			alg:     AlgorithmSHA256,
			command: CommandDictionaryAttackParameters,
			params:  []interface{}{HandleLockout, Separator, uint32(32), uint32(7200), uint32(86400)},
			expected: Digest{0x8e, 0xa6, 0x7e, 0x49, 0x3d, 0x62, 0x56, 0x21, 0x4c, 0x2e, 0xd2, 0xe9, 0xfd, 0x69, 0xbe, 0x71, 0x4a, 0x5e, 0x1b,
				0xab, 0x5d, 0x55, 0x24, 0x56, 0xd0, 0x29, 0x82, 0xe1, 0x5c, 0xd2, 0x61, 0xde},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			cpHash, err := ComputeCpHash(data.alg, data.command, data.params...)
			if err != nil {
				t.Fatalf("ComputeCpHash failed: %v", err)
			}

			if !bytes.Equal(cpHash, data.expected) {
				t.Errorf("Unexpected digest (got %x, expected %x)", cpHash, data.expected)
			}
		})
	}
}

func TestTrialPolicySigned(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	key := createAndLoadRSAPSSKeyForTesting(t, tpm, primary)
	defer flushContext(t, tpm, key)

	for _, data := range []struct {
		desc      string
		alg       AlgorithmId
		policyRef Nonce
	}{
		{
			desc: "NoPolicyRef",
			alg:  AlgorithmSHA256,
		},
		{
			desc:      "WithPolicyRef",
			alg:       AlgorithmSHA256,
			policyRef: []byte("bar"),
		},
		{
			desc: "SHA1",
			alg:  AlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			h := sha256.New()
			binary.Write(h, binary.BigEndian, int32(0))
			h.Write(data.policyRef)
			aHash := h.Sum(nil)

			signature, err := tpm.Sign(key, aHash, nil, nil, nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if _, _, err := tpm.PolicySigned(key, sessionContext, false, nil, data.policyRef, 0,
				signature); err != nil {
				t.Fatalf("PolicySigned failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicySigned(key, data.policyRef)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicySecret(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		alg       AlgorithmId
		policyRef Nonce
	}{
		{
			desc: "NoPolicyRef",
			alg:  AlgorithmSHA256,
		},
		{
			desc:      "WithPolicyRef",
			alg:       AlgorithmSHA256,
			policyRef: []byte("bar"),
		},
		{
			desc: "SHA1",
			alg:  AlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if _, _, err := tpm.PolicySecret(primary, sessionContext, nil, data.policyRef, 0, nil); err != nil {
				t.Fatalf("PolicySecret failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicySecret(primary, data.policyRef)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyOR(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	digests := make(map[AlgorithmId]DigestList)
	for _, d := range []string{"foo", "bar", "xyz"} {
		for _, a := range []AlgorithmId{AlgorithmSHA1, AlgorithmSHA256} {
			if _, exists := digests[a]; !exists {
				digests[a] = make(DigestList, 0)
			}
			h := cryptConstructHash(a)
			h.Write([]byte(d))
			digests[a] = append(digests[a], h.Sum(nil))
		}
	}

	for _, data := range []struct {
		desc      string
		alg       AlgorithmId
		pHashList DigestList
	}{
		{
			desc: "SHA256",
			alg:  AlgorithmSHA256,
			pHashList: DigestList{
				digests[AlgorithmSHA256][0],
				digests[AlgorithmSHA256][2],
				digests[AlgorithmSHA256][1]},
		},
		{
			desc: "SHA1",
			alg:  AlgorithmSHA1,
			pHashList: DigestList{
				digests[AlgorithmSHA1][1],
				digests[AlgorithmSHA1][0]},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyOR(sessionContext, data.pHashList); err != nil {
				t.Fatalf("PolicyOR failed: %v", err)
			}
			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			// Perform another assertion first to make sure that the PolicyOR resets the digest
			trial.PolicyPassword()
			trial.PolicyOR(data.pHashList)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyPCR(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	digests := make(map[AlgorithmId]Digest)
	for _, a := range []AlgorithmId{AlgorithmSHA1, AlgorithmSHA256} {
		h := cryptConstructHash(a)
		h.Write([]byte("foo"))
		digests[a] = h.Sum(nil)
	}

	for _, data := range []struct {
		desc   string
		alg    AlgorithmId
		digest Digest
		pcrs   PCRSelectionList
	}{
		{
			desc:   "SHA256",
			alg:    AlgorithmSHA256,
			digest: digests[AlgorithmSHA256],
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8}}},
		},
		{
			desc:   "SHA1",
			alg:    AlgorithmSHA1,
			digest: digests[AlgorithmSHA1],
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{7, 8}}},
		},
		{
			desc:   "Mixed",
			alg:    AlgorithmSHA256,
			digest: digests[AlgorithmSHA256],
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{7, 8}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{2, 4}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyPCR(sessionContext, data.digest, data.pcrs); err != nil {
				t.Fatalf("PolicyPCR failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyPCR(data.digest, data.pcrs)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyNV(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	nvPub := NVPublic{
		Index:   0x0181ffff,
		NameAlg: AlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
		Size:    64}
	if err := tpm.NVDefineSpace(HandleOwner, nil, &nvPub, nil); err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	index, err := tpm.WrapHandle(nvPub.Index)
	if err != nil {
		t.Fatalf("WrapHandle failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, index, HandleOwner, nil)

	twentyFiveUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(twentyFiveUint64, 25)

	tenUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(tenUint64, 10)

	fortyUint32 := make(Operand, 4)
	binary.BigEndian.PutUint32(fortyUint32, 40)

	for _, data := range []struct {
		desc      string
		alg       AlgorithmId
		operandB  Operand
		offset    uint16
		operation ArithmeticOp
	}{
		{
			desc:      "SHA256",
			alg:       AlgorithmSHA256,
			operandB:  tenUint64,
			offset:    0,
			operation: OpUnsignedLT,
		},
		{
			desc:      "SHA1",
			alg:       AlgorithmSHA1,
			operandB:  twentyFiveUint64,
			offset:    0,
			operation: OpUnsignedGE,
		},
		{
			desc:      "Partial",
			alg:       AlgorithmSHA1,
			operandB:  fortyUint32,
			offset:    4,
			operation: OpUnsignedGE,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyNV(index, index, sessionContext, data.operandB, data.offset, data.operation, nil); err != nil {
				t.Fatalf("PolicyNV failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyNV(index, data.operandB, data.offset, data.operation)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyCommandCode(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  AlgorithmId
		code CommandCode
	}{
		{
			desc: "Unseal",
			alg:  AlgorithmSHA256,
			code: CommandUnseal,
		},
		{
			desc: "NVChangeAuth",
			alg:  AlgorithmSHA256,
			code: CommandNVChangeAuth,
		},
		{
			desc: "SHA1",
			alg:  AlgorithmSHA1,
			code: CommandUnseal,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyCommandCode(sessionContext, data.code); err != nil {
				t.Fatalf("PolicyCommandCode failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyCommandCode(data.code)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyAuthValue(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  AlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  AlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  AlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyAuthValue(sessionContext); err != nil {
				t.Fatalf("PolicyAuthValue failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyAuthValue()

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyPassword(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  AlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  AlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  AlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyPassword(sessionContext); err != nil {
				t.Fatalf("PolicyPassword failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyPassword()

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}
