package tpm2_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
)

type mockHandleContext struct {
	name Name
}

func (c *mockHandleContext) Name() Name {
	return c.name
}
func (c *mockHandleContext) Handle() Handle                    { return HandleNull }
func (c *mockHandleContext) SerializeToBytes() []byte          { return nil }
func (c *mockHandleContext) SerializeToWriter(io.Writer) error { return nil }

func TestComputeCpHash(t *testing.T) {
	h := sha256.New()
	h.Write([]byte("foo"))
	name, _ := MarshalToBytes(HashAlgorithmSHA256, RawBytes(h.Sum(nil)))
	rc := &mockHandleContext{name}

	for _, data := range []struct {
		desc     string
		alg      HashAlgorithmId
		command  CommandCode
		params   []interface{}
		expected Digest
	}{
		{
			desc:    "Unseal",
			alg:     HashAlgorithmSHA256,
			command: CommandUnseal,
			params:  []interface{}{rc},
			expected: Digest{0xe5, 0xe8, 0x03, 0xe4, 0xcb, 0xd3, 0x3f, 0x78, 0xc5, 0x65, 0x1b, 0x49, 0xf2, 0x83, 0xba, 0x63, 0x8a, 0xdf, 0x34,
				0xca, 0x69, 0x60, 0x76, 0x40, 0xfb, 0xea, 0x9e, 0xe2, 0x89, 0xfd, 0x93, 0xe7},
		},
		{
			desc:    "EvictControl",
			alg:     HashAlgorithmSHA1,
			command: CommandEvictControl,
			params:  []interface{}{HandleOwner, rc, Handle(0x8100ffff)},
			expected: Digest{0x40, 0x93, 0x38, 0x44, 0x00, 0xde, 0x24, 0x3a, 0xcb, 0x81, 0x04, 0xba, 0x14, 0xbf, 0x2f, 0x2e, 0xf8, 0xa8, 0x27,
				0x0b},
		},
		{
			desc:    "DAParameters",
			alg:     HashAlgorithmSHA256,
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
	tpm := openTPMForTesting(t, testCapabilityOwnerHierarchy)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	key := createAndLoadRSAPSSKeyForTesting(t, tpm, primary)
	defer flushContext(t, tpm, key)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		policyRef Nonce
	}{
		{
			desc: "NoPolicyRef",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc:      "WithPolicyRef",
			alg:       HashAlgorithmSHA256,
			policyRef: []byte("bar"),
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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

			if _, _, err := tpm.PolicySigned(key, sessionContext, false, nil, data.policyRef, 0, signature); err != nil {
				t.Fatalf("PolicySigned failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicySigned(key.Name(), data.policyRef)

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
	tpm := openTPMForTesting(t, testCapabilityOwnerHierarchy)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		policyRef Nonce
	}{
		{
			desc: "NoPolicyRef",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc:      "WithPolicyRef",
			alg:       HashAlgorithmSHA256,
			policyRef: []byte("bar"),
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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
			trial.PolicySecret(primary.Name(), data.policyRef)

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
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	digests := make(map[HashAlgorithmId]DigestList)
	for _, d := range []string{"foo", "bar", "xyz"} {
		for _, a := range []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256} {
			if _, exists := digests[a]; !exists {
				digests[a] = make(DigestList, 0)
			}
			h := a.NewHash()
			h.Write([]byte(d))
			digests[a] = append(digests[a], h.Sum(nil))
		}
	}

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		pHashList DigestList
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
			pHashList: DigestList{
				digests[HashAlgorithmSHA256][0],
				digests[HashAlgorithmSHA256][2],
				digests[HashAlgorithmSHA256][1]},
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
			pHashList: DigestList{
				digests[HashAlgorithmSHA1][1],
				digests[HashAlgorithmSHA1][0]},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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
			if err := trial.PolicyOR(data.pHashList); err != nil {
				t.Errorf("PolicyOR failed: %v", err)
			}

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
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	digests := make(map[HashAlgorithmId]Digest)
	for _, a := range []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256} {
		h := a.NewHash()
		h.Write([]byte("foo"))
		digests[a] = h.Sum(nil)
	}

	for _, data := range []struct {
		desc   string
		alg    HashAlgorithmId
		digest Digest
		pcrs   PCRSelectionList
	}{
		{
			desc:   "SHA256",
			alg:    HashAlgorithmSHA256,
			digest: digests[HashAlgorithmSHA256],
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
		},
		{
			desc:   "SHA1",
			alg:    HashAlgorithmSHA1,
			digest: digests[HashAlgorithmSHA1],
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{7, 8}}},
		},
		{
			desc:   "Mixed",
			alg:    HashAlgorithmSHA256,
			digest: digests[HashAlgorithmSHA256],
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{7, 8}},
				{Hash: HashAlgorithmSHA256, Select: []int{2, 4}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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
	tpm := openTPMForTesting(t, testCapabilityOwnerPersist)
	defer closeTPM(t, tpm)

	owner := tpm.OwnerHandleContext()

	nvPub := NVPublic{
		Index:   0x0181ffff,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthRead | AttrNVAuthWrite),
		Size:    64}
	index, err := tpm.NVDefineSpace(owner, nil, &nvPub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, index, owner)

	twentyFiveUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(twentyFiveUint64, 25)

	tenUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(tenUint64, 10)

	fortyUint32 := make(Operand, 4)
	binary.BigEndian.PutUint32(fortyUint32, 40)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		operandB  Operand
		offset    uint16
		operation ArithmeticOp
	}{
		{
			desc:      "SHA256",
			alg:       HashAlgorithmSHA256,
			operandB:  tenUint64,
			offset:    0,
			operation: OpUnsignedLT,
		},
		{
			desc:      "SHA1",
			alg:       HashAlgorithmSHA1,
			operandB:  twentyFiveUint64,
			offset:    0,
			operation: OpUnsignedGE,
		},
		{
			desc:      "Partial",
			alg:       HashAlgorithmSHA1,
			operandB:  fortyUint32,
			offset:    4,
			operation: OpUnsignedGE,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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
			trial.PolicyNV(index.Name(), data.operandB, data.offset, data.operation)

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

func TestTrialPolicyCounterTimer(t *testing.T) {
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	uint64a := make(Operand, 8)
	binary.BigEndian.PutUint64(uint64a, 1603123)

	uint64b := make(Operand, 8)
	binary.BigEndian.PutUint64(uint64b, 6658125610)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		operandB  Operand
		offset    uint16
		operation ArithmeticOp
	}{
		{
			desc:      "SHA256",
			alg:       HashAlgorithmSHA256,
			operandB:  uint64b,
			offset:    8,
			operation: OpUnsignedGT,
		},
		{
			desc:      "SHA1",
			alg:       HashAlgorithmSHA1,
			operandB:  uint64b,
			offset:    8,
			operation: OpUnsignedGE,
		},
		{
			desc:      "Time",
			alg:       HashAlgorithmSHA256,
			operandB:  uint64a,
			offset:    0,
			operation: OpUnsignedGE,
		},
		{
			desc:      "Safe",
			alg:       HashAlgorithmSHA256,
			operandB:  Operand{0x01},
			offset:    24,
			operation: OpEq,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyCounterTimer(sessionContext, data.operandB, data.offset, data.operation, nil); err != nil {
				t.Fatalf("PolicyCounterTimer failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyCounterTimer(data.operandB, data.offset, data.operation)

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
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
		code CommandCode
	}{
		{
			desc: "Unseal",
			alg:  HashAlgorithmSHA256,
			code: CommandUnseal,
		},
		{
			desc: "NVChangeAuth",
			alg:  HashAlgorithmSHA256,
			code: CommandNVChangeAuth,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
			code: CommandUnseal,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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

func TestTrialPolicyCpHash(t *testing.T) {
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			h := data.alg.NewHash()
			h.Write([]byte("12345"))
			cpHashA := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyCpHash(sessionContext, cpHashA); err != nil {
				t.Fatalf("PolicyCpHash failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyCpHash(cpHashA)

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

func TestTrialPolicyNameHash(t *testing.T) {
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			h := data.alg.NewHash()
			h.Write([]byte("12345"))
			nameHash := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyNameHash(sessionContext, nameHash); err != nil {
				t.Fatalf("PolicyNameHash failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyNameHash(nameHash)

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

func TestTrialPolicyDuplicationSelect(t *testing.T) {
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc          string
		alg           HashAlgorithmId
		includeObject bool
	}{
		{
			desc:          "SHA256",
			alg:           HashAlgorithmSHA256,
			includeObject: true,
		},
		{
			desc:          "NoIncludeObject",
			alg:           HashAlgorithmSHA256,
			includeObject: false,
		},
		{
			desc:          "SHA1",
			alg:           HashAlgorithmSHA1,
			includeObject: true,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			h := data.alg.NewHash()
			h.Write([]byte("12345"))
			objectName := h.Sum(nil)

			h = data.alg.NewHash()
			h.Write([]byte("67890"))
			newParentName := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyDuplicationSelect(sessionContext, objectName, newParentName, data.includeObject); err != nil {
				t.Fatalf("PolicyDuplicationSelect failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyDuplicationSelect(objectName, newParentName, data.includeObject)

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

func TestTrialPolicyAuthorize(t *testing.T) {
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	var keySignSHA1 Name
	var keySignSHA256 Name

	h := HashAlgorithmSHA1.NewHash()
	h.Write([]byte("foo"))
	keySignSHA1, _ = MarshalToBytes(HashAlgorithmSHA1, RawBytes(h.Sum(nil)))

	h = HashAlgorithmSHA256.NewHash()
	h.Write([]byte("foo"))
	keySignSHA256, _ = MarshalToBytes(HashAlgorithmSHA256, RawBytes(h.Sum(nil)))

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		policyRef Nonce
		keySign   Name
	}{
		{
			desc:    "SHA256",
			alg:     HashAlgorithmSHA256,
			keySign: keySignSHA256,
		},
		{
			desc:    "SHA1",
			alg:     HashAlgorithmSHA1,
			keySign: keySignSHA1,
		},
		{
			desc:      "WithPolicyRef",
			alg:       HashAlgorithmSHA256,
			policyRef: Nonce("bar"),
			keySign:   keySignSHA256,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyAuthorize(sessionContext, make(Digest, data.alg.Size()), data.policyRef, data.keySign, nil); err != nil {
				t.Fatalf("PolicyAuthorize failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyAuthorize(data.policyRef, data.keySign)

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
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
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

func TestTrialPolicyNvWritten(t *testing.T) {
	tpm := openTPMForTesting(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc       string
		alg        HashAlgorithmId
		writtenSet bool
	}{
		{
			desc:       "SHA256/1",
			alg:        HashAlgorithmSHA256,
			writtenSet: true,
		},
		{
			desc:       "SHA1",
			alg:        HashAlgorithmSHA1,
			writtenSet: false,
		},
		{
			desc:       "SHA256/2",
			alg:        HashAlgorithmSHA256,
			writtenSet: false,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyNvWritten(sessionContext, data.writtenSet); err != nil {
				t.Fatalf("PolicyNvWritten failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyNvWritten(data.writtenSet)

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
