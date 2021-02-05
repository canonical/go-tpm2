// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package internal

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"hash"

	"github.com/canonical/go-sp800.108-kdf"
)

func getHashConstructor(hashAlg crypto.Hash) func() hash.Hash {
	return func() hash.Hash {
		return hashAlg.New()
	}
}

func internalKDFa(hashAlg crypto.Hash, key, label, contextU, contextV []byte, sizeInBits int, counterInOut *int, once bool) []byte {
	digestSize := hashAlg.Size()
	if once && sizeInBits&7 > 0 {
		panic("sizeInBits must be a multiple of 8 when called with once == true")
	}

	counter := 0
	if counterInOut != nil {
		counter = *counterInOut
	}
	var nbytes int
	if once {
		nbytes = digestSize
	} else {
		nbytes = (sizeInBits + 7) / 8
	}

	buf := new(bytes.Buffer)

	for ; nbytes > 0; nbytes -= digestSize {
		counter++
		if nbytes < digestSize {
			digestSize = nbytes
		}

		h := hmac.New(getHashConstructor(hashAlg), key)

		binary.Write(h, binary.BigEndian, uint32(counter))
		h.Write(label)
		h.Write([]byte{0})
		h.Write(contextU)
		h.Write(contextV)
		binary.Write(h, binary.BigEndian, uint32(sizeInBits))

		buf.Write(h.Sum(nil)[0:digestSize])
	}

	outKey := buf.Bytes()

	if sizeInBits%8 != 0 {
		outKey[0] &= ((1 << uint(sizeInBits%8)) - 1)
	}
	if counterInOut != nil {
		*counterInOut = counter
	}
	return outKey
}

func KDFa(hashAlg crypto.Hash, key, label, contextU, contextV []byte, sizeInBits int) []byte {
	context := make([]byte, len(contextU)+len(contextV))
	copy(context, contextU)
	copy(context[len(contextU):], contextV)
	return kdf.CounterModeKey(kdf.NewHMACPRF(hashAlg), key, label, context, uint32(sizeInBits))
}

func KDFe(hashAlg crypto.Hash, z, label, partyUInfo, partyVInfo []byte, sizeInBits int) []byte {
	digestSize := hashAlg.Size()

	counter := 1
	var res bytes.Buffer

	for bytes := (sizeInBits + 7) / 8; bytes > 8; bytes -= digestSize {
		if bytes < digestSize {
			digestSize = bytes
		}

		h := hashAlg.New()

		binary.Write(h, binary.BigEndian, uint32(counter))
		h.Write(z)
		h.Write(label)
		h.Write([]byte{0})
		h.Write(partyUInfo)
		h.Write(partyVInfo)

		res.Write(h.Sum(nil)[0:digestSize])
	}

	outKey := res.Bytes()

	if sizeInBits%8 != 0 {
		outKey[0] &= ((1 << uint(sizeInBits%8)) - 1)
	}
	return outKey
}

func XORObfuscation(hashAlg crypto.Hash, key []byte, contextU, contextV, data []byte) {
	digestSize := hashAlg.Size()

	counter := 0
	datasize := len(data)
	remaining := datasize

	for ; remaining > 0; remaining -= digestSize {
		mask := internalKDFa(hashAlg, key, []byte("XOR"), contextU, contextV, datasize*8, &counter, true)
		lim := remaining
		if digestSize < remaining {
			lim = digestSize
		}
		for i := 0; i < lim; i++ {
			data[datasize-remaining+i] ^= mask[i]
		}
	}
}
