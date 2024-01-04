// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"hash"
	"reflect"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func TestHMACSequence(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, 0)
	defer closeTPM()

	key := make(SensitiveData, 32)
	rand.Read(key)

	seed := make([]byte, 32)

	h := crypto.SHA256.New()
	h.Write(seed)
	h.Write(key)
	unique := Digest(h.Sum(nil))

	loadKey := func(t *testing.T, params KeyedHashParams, auth Auth) ResourceContext {
		public := Public{
			Type:    ObjectTypeKeyedHash,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign | AttrNoDA,
			Params:  MakePublicParamsUnion(params),
			Unique:  MakePublicIDUnion(unique)}
		if params.Scheme.Scheme == KeyedHashSchemeNull {
			public.Attrs |= AttrDecrypt
		}

		authValue := make(Auth, public.NameAlg.Size())
		copy(authValue, auth)
		sensitive := Sensitive{
			Type:      ObjectTypeKeyedHash,
			AuthValue: authValue,
			SeedValue: seed,
			Sensitive: MakeSensitiveCompositeUnion(key)}
		rc, err := tpm.LoadExternal(&sensitive, &public, HandleNull)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}
		return rc
	}

	start := func(t *testing.T, keyContext ResourceContext, auth Auth, hashAlg HashAlgorithmId, session SessionContext) ResourceContext {
		defer flushContext(t, tpm, keyContext)
		seq, err := tpm.HMACStart(keyContext, auth, hashAlg, session)
		if err != nil {
			t.Fatalf("HMACStart failed: %v", err)
		}
		return seq
	}

	run := func(t *testing.T, seq ResourceContext, data [][]byte, alg HashAlgorithmId, session SessionContext) {
		defer verifyContextFlushed(t, tpm, seq)

		h := hmac.New(func() hash.Hash { return alg.NewHash() }, key)

		for _, d := range data[:len(data)-1] {
			if err := tpm.SequenceUpdate(seq, d, session); err != nil {
				t.Fatalf("SequenceUpdate failed: %v", err)
			}
			h.Write(d)
		}

		result, validation, err := tpm.SequenceComplete(seq, data[len(data)-1], HandleNull, session)
		if err != nil {
			t.Fatalf("SequenceComplete failed: %v", err)
		}
		h.Write(data[len(data)-1])
		if validation != nil {
			t.Errorf("validation should be nil")
		}
		if !bytes.Equal(result, h.Sum(nil)) {
			t.Errorf("Unexpected result")
		}
	}

	t.Run("WithSignOnlyKey/1", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeHMAC, Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})}}, nil)
		seq := start(t, keyContext, nil, HashAlgorithmSHA256, nil)
		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, HashAlgorithmSHA256, nil)
	})

	t.Run("WithSignOnlyKey/2", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeHMAC, Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})}}, nil)
		seq := start(t, keyContext, nil, HashAlgorithmNull, nil)
		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz2")}, HashAlgorithmSHA256, nil)
	})

	t.Run("WithSignAndDecryptKey", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}, nil)
		seq := start(t, keyContext, nil, HashAlgorithmSHA256, nil)
		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, HashAlgorithmSHA256, nil)
	})

	t.Run("UsePasswordFoHMACKey", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeHMAC, Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})}}, testAuth)
		seq := start(t, keyContext, nil, HashAlgorithmSHA256, nil)
		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, HashAlgorithmSHA256, nil)
	})

	t.Run("UseSessionForHMACKey", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeHMAC, Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})}}, testAuth)

		session, err := tpm.StartAuthSession(nil, keyContext, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, session)

		seq := start(t, keyContext, nil, HashAlgorithmSHA256, session)
		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, HashAlgorithmSHA256, nil)
	})

	t.Run("UsePasswordForSeq/1", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeHMAC, Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})}}, nil)
		seq := start(t, keyContext, testAuth, HashAlgorithmNull, nil)
		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, HashAlgorithmSHA256, nil)
	})

	t.Run("UsePasswordForSeq/2", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeHMAC, Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})}}, nil)
		seq := start(t, keyContext, testAuth, HashAlgorithmNull, nil)
		seq.SetAuthValue(testAuth)
		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, HashAlgorithmSHA256, nil)
	})

	t.Run("UseSessionForSeq", func(t *testing.T) {
		keyContext := loadKey(t, KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeHMAC, Details: MakeSchemeKeyedHashUnion(SchemeHMAC{HashAlg: HashAlgorithmSHA256})}}, nil)
		seq := start(t, keyContext, testAuth, HashAlgorithmNull, nil)

		session, err := tpm.StartAuthSession(nil, seq, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, session)

		run(t, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, HashAlgorithmSHA256, session.WithAttrs(AttrContinueSession))
	})
}

func TestHashSequence(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, 0)
	defer closeTPM()

	start := func(t *testing.T, auth Auth, hashAlg HashAlgorithmId) ResourceContext {
		seq, err := tpm.HashSequenceStart(auth, hashAlg)
		if err != nil {
			t.Fatalf("HashSequenceStart failed: %v", err)
		}
		return seq
	}

	run := func(t *testing.T, seq ResourceContext, data [][]byte, hierarchy Handle, alg HashAlgorithmId, session SessionContext) {
		defer verifyContextFlushed(t, tpm, seq)

		ticketIsSafe := len(data[0]) >= binary.Size(TPMGenerated(0)) && TPMGenerated(binary.BigEndian.Uint32(data[0])) != TPMGeneratedValue
		h := alg.NewHash()

		for _, d := range data[:len(data)-1] {
			if err := tpm.SequenceUpdate(seq, d, session); err != nil {
				t.Fatalf("SequenceUpdate failed: %v", err)
			}
			h.Write(d)
		}

		result, validation, err := tpm.SequenceComplete(seq, data[len(data)-1], hierarchy, session)
		if err != nil {
			t.Fatalf("SequenceComplete failed: %v", err)
		}
		h.Write(data[len(data)-1])
		if ticketIsSafe && hierarchy != HandleNull {
			if validation == nil {
				t.Fatalf("nil validation")
			}
			if validation.Tag != TagHashcheck {
				t.Errorf("Unexpected tag")
			}
			if validation.Hierarchy != hierarchy {
				t.Errorf("Unexpected hierarchy")
			}
		} else if validation != nil {
			t.Errorf("validation should be nil")
		}
		if !bytes.Equal(result, h.Sum(nil)) {
			t.Errorf("Unexpected result")
		}
	}

	t.Run("NoPassword", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA256)
		run(t, seq, [][]byte{[]byte("foobar"), []byte("bar"), []byte("baz")}, HandleOwner, HashAlgorithmSHA256, nil)
	})

	t.Run("SHA1", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA1)
		run(t, seq, [][]byte{[]byte("foobar"), []byte("bar"), []byte("baz")}, HandleOwner, HashAlgorithmSHA1, nil)
	})

	t.Run("NoTicket/1", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA256)
		run(t, seq, [][]byte{[]byte("foobar"), []byte("bar"), []byte("baz")}, HandleNull, HashAlgorithmSHA256, nil)
	})

	t.Run("NoTicket/2", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA256)
		run(t, seq, [][]byte{[]byte("\xff\x54\x43\x47foo"), []byte("bar"), []byte("baz")}, HandleOwner, HashAlgorithmSHA256, nil)
	})

	t.Run("UsePassword/1", func(t *testing.T) {
		seq := start(t, testAuth, HashAlgorithmSHA256)
		run(t, seq, [][]byte{[]byte("foobar"), []byte("bar"), []byte("baz")}, HandleOwner, HashAlgorithmSHA256, nil)
	})

	t.Run("UsePassword/2", func(t *testing.T) {
		seq := start(t, testAuth, HashAlgorithmSHA256)
		seq.SetAuthValue(testAuth)
		run(t, seq, [][]byte{[]byte("foobar"), []byte("bar"), []byte("baz")}, HandleOwner, HashAlgorithmSHA256, nil)
	})

	t.Run("UseSession", func(t *testing.T) {
		seq := start(t, testAuth, HashAlgorithmSHA256)

		session, err := tpm.StartAuthSession(nil, seq, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, session)

		run(t, seq, [][]byte{[]byte("foobar"), []byte("bar"), []byte("baz")}, HandleOwner, HashAlgorithmSHA256, session.WithAttrs(AttrContinueSession))
	})
}

func TestEventSequence(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeaturePCR|testutil.TPMFeatureNV)
	defer closeTPM()

	start := func(t *testing.T, auth Auth) ResourceContext {
		seq, err := tpm.HashSequenceStart(auth, HashAlgorithmNull)
		if err != nil {
			t.Fatalf("HashSequenceStart failed: %v", err)
		}
		return seq
	}

	run := func(t *testing.T, pcr int, seq ResourceContext, data [][]byte, session SessionContext) {
		defer verifyContextFlushed(t, tpm, seq)

		var pcrValues PCRValues
		if pcr > -1 {
			var err error
			_, pcrValues, err = tpm.PCRRead(PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{pcr}}, {Hash: HashAlgorithmSHA1, Select: []int{pcr}}})
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}
		}

		for _, d := range data[:len(data)-1] {
			if err := tpm.SequenceUpdate(seq, d, session); err != nil {
				t.Fatalf("SequenceUpdate failed: %v", err)
			}
		}

		var pcrContext ResourceContext
		if pcr > -1 {
			pcrContext = tpm.PCRHandleContext(pcr)
		}
		results, err := tpm.EventSequenceComplete(pcrContext, seq, data[len(data)-1], nil, session)
		if err != nil {
			t.Fatalf("EventSequenceComplete failed: %v", err)
		}

		expectedPcrValues := make(PCRValues)
		checked := false
		for _, r := range results {
			if !r.HashAlg.Available() {
				continue
			}
			checked = true
			h := r.HashAlg.NewHash()
			for _, d := range data {
				h.Write(d)
			}
			d := h.Sum(nil)
			if !bytes.Equal(r.Digest(), d) {
				t.Errorf("Unexpected digest")
			}

			if pcr < 0 {
				continue
			}

			if v, ok := pcrValues[r.HashAlg]; ok {
				h := r.HashAlg.NewHash()
				h.Write(v[pcr])
				h.Write(d)
				expectedPcrValues[r.HashAlg] = make(map[int]Digest)
				expectedPcrValues[r.HashAlg][pcr] = h.Sum(nil)
			}
		}
		if !checked {
			t.Errorf("Unable to check the results")
		}

		if pcr < 0 {
			return
		}
		_, updatedPcrValues, err := tpm.PCRRead(PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{pcr}}, {Hash: HashAlgorithmSHA1, Select: []int{pcr}}})
		if err != nil {
			t.Fatalf("PCRRead failed: %v", err)
		}
		if !reflect.DeepEqual(updatedPcrValues, expectedPcrValues) {
			t.Errorf("Unexpected PCR values")
		}
	}

	t.Run("NoPassword", func(t *testing.T) {
		seq := start(t, nil)
		run(t, -1, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, nil)
	})

	t.Run("WithPCR", func(t *testing.T) {
		seq := start(t, nil)
		run(t, 12, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz2")}, nil)
	})

	t.Run("UsePassword/1", func(t *testing.T) {
		seq := start(t, testAuth)
		run(t, -1, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, nil)
	})

	t.Run("UsePassword/2", func(t *testing.T) {
		seq := start(t, testAuth)
		seq.SetAuthValue(testAuth)
		run(t, -1, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, nil)
	})

	t.Run("UseSession", func(t *testing.T) {
		seq := start(t, testAuth)

		session, err := tpm.StartAuthSession(nil, seq, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, session)

		run(t, -1, seq, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, session.WithAttrs(AttrContinueSession))
	})
}

func TestHashSequenceExecute(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, 0)
	defer closeTPM()

	b := make([]byte, 2500)
	rand.Read(b[4:])

	start := func(t *testing.T, auth Auth, hashAlg HashAlgorithmId) ResourceContext {
		seq, err := tpm.HashSequenceStart(auth, hashAlg)
		if err != nil {
			t.Fatalf("HashSequenceStart failed: %v", err)
		}
		return seq
	}

	run := func(t *testing.T, seq ResourceContext, data []byte, hierarchy Handle, alg HashAlgorithmId, session SessionContext) {
		defer verifyContextFlushed(t, tpm, seq)

		ticketIsSafe := len(data) >= binary.Size(TPMGenerated(0)) && TPMGenerated(binary.BigEndian.Uint32(data)) != TPMGeneratedValue

		result, validation, err := tpm.SequenceExecute(seq, data, hierarchy, session)
		if err != nil {
			t.Fatalf("SequenceExecute failed: %v", err)
		}
		if ticketIsSafe && hierarchy != HandleNull {
			if validation == nil {
				t.Fatalf("nil validation")
			}
			if validation.Tag != TagHashcheck {
				t.Errorf("Unexpected tag")
			}
			if validation.Hierarchy != hierarchy {
				t.Errorf("Unexpected hierarchy")
			}
		} else if validation != nil {
			t.Errorf("validation should be nil")
		}
		h := alg.NewHash()
		h.Write(data)
		if !bytes.Equal(result, h.Sum(nil)) {
			t.Errorf("Unexpected result")
		}
	}

	t.Run("NoPassword", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA256)
		run(t, seq, b, HandleOwner, HashAlgorithmSHA256, nil)
	})

	t.Run("SHA1", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA1)
		run(t, seq, b, HandleOwner, HashAlgorithmSHA1, nil)
	})

	t.Run("NoTicket/1", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA256)
		run(t, seq, b, HandleNull, HashAlgorithmSHA256, nil)
	})

	t.Run("NoTicket/2", func(t *testing.T) {
		seq := start(t, nil, HashAlgorithmSHA256)
		run(t, seq, append([]byte("\xff\x54\x43\x47foo"), b...), HandleOwner, HashAlgorithmSHA256, nil)
	})

	t.Run("UsePassword", func(t *testing.T) {
		seq := start(t, testAuth, HashAlgorithmSHA256)
		run(t, seq, b, HandleOwner, HashAlgorithmSHA256, nil)
	})

	t.Run("UseSession", func(t *testing.T) {
		seq := start(t, testAuth, HashAlgorithmSHA256)

		session, err := tpm.StartAuthSession(nil, seq, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, session)

		run(t, seq, b, HandleOwner, HashAlgorithmSHA256, session.WithAttrs(AttrContinueSession))
	})
}

func TestEventSequenceExecute(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeaturePCR|testutil.TPMFeatureNV)
	defer closeTPM()

	data := make([]byte, 2500)
	rand.Read(data)

	start := func(t *testing.T, auth Auth) ResourceContext {
		seq, err := tpm.HashSequenceStart(auth, HashAlgorithmNull)
		if err != nil {
			t.Fatalf("HashSequenceStart failed: %v", err)
		}
		return seq
	}

	run := func(t *testing.T, pcr int, seq ResourceContext, session SessionContext) {
		defer verifyContextFlushed(t, tpm, seq)

		var pcrValues PCRValues
		if pcr > -1 {
			var err error
			_, pcrValues, err = tpm.PCRRead(PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{pcr}}, {Hash: HashAlgorithmSHA1, Select: []int{pcr}}})
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}
		}

		var pcrContext ResourceContext
		if pcr > -1 {
			pcrContext = tpm.PCRHandleContext(pcr)
		}
		results, err := tpm.EventSequenceExecute(pcrContext, seq, data, nil, session)
		if err != nil {
			t.Fatalf("EventSequenceExecute failed: %v", err)
		}

		expectedPcrValues := make(PCRValues)
		checked := false
		for _, r := range results {
			if !r.HashAlg.Available() {
				continue
			}
			checked = true
			h := r.HashAlg.NewHash()
			h.Write(data)
			d := h.Sum(nil)
			if !bytes.Equal(r.Digest(), d) {
				t.Errorf("Unexpected digest")
			}

			if pcr < 0 {
				continue
			}

			if v, ok := pcrValues[r.HashAlg]; ok {
				h := r.HashAlg.NewHash()
				h.Write(v[pcr])
				h.Write(d)
				expectedPcrValues[r.HashAlg] = make(map[int]Digest)
				expectedPcrValues[r.HashAlg][pcr] = h.Sum(nil)
			}
		}
		if !checked {
			t.Errorf("Unable to check the results")
		}

		if pcr < 0 {
			return
		}
		_, updatedPcrValues, err := tpm.PCRRead(PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{pcr}}, {Hash: HashAlgorithmSHA1, Select: []int{pcr}}})
		if err != nil {
			t.Fatalf("PCRRead failed: %v", err)
		}
		if !reflect.DeepEqual(updatedPcrValues, expectedPcrValues) {
			t.Errorf("Unexpected PCR values")
		}
	}

	t.Run("NoPassword", func(t *testing.T) {
		seq := start(t, nil)
		run(t, -1, seq, nil)
	})

	t.Run("WithPCR", func(t *testing.T) {
		seq := start(t, nil)
		run(t, 12, seq, nil)
	})

	t.Run("UsePassword", func(t *testing.T) {
		seq := start(t, testAuth)
		run(t, -1, seq, nil)
	})

	t.Run("UseSession", func(t *testing.T) {
		seq := start(t, testAuth)

		session, err := tpm.StartAuthSession(nil, seq, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, session)

		run(t, -1, seq, session.WithAttrs(AttrContinueSession))
	})
}
