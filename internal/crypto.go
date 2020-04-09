// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package internal

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
)

type SymmetricMode uint16

const (
	SymmetricModeNull SymmetricMode = 0x0010 // TPM_ALG_NULL
	SymmetricModeCTR  SymmetricMode = 0x0040 // TPM_ALG_CTR
	SymmetricModeOFB  SymmetricMode = 0x0041 // TPM_ALG_OFB
	SymmetricModeCBC  SymmetricMode = 0x0042 // TPM_ALG_CBC
	SymmetricModeCFB  SymmetricMode = 0x0043 // TPM_ALG_CFB
	SymmetricModeECB  SymmetricMode = 0x0044 // TPM_ALG_ECB
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
	return internalKDFa(hashAlg, key, label, contextU, contextV, sizeInBits, nil, false)
}

func KDFe(hashAlg crypto.Hash, z, label, partyUInfo, partyVInfo []byte, sizeInBits int) []byte {
	digestSize := hashAlg.Size()

	counter := 0
	buf := new(bytes.Buffer)

	for bytes := (sizeInBits + 7) / 8; bytes > 0; bytes -= digestSize {
		if bytes < digestSize {
			digestSize = bytes
		}
		counter++

		h := hashAlg.New()

		binary.Write(h, binary.BigEndian, uint32(counter))
		h.Write(z)
		h.Write(label)
		h.Write([]byte{0})
		h.Write(partyUInfo)
		h.Write(partyVInfo)

		buf.Write(h.Sum(nil)[0:digestSize])
	}

	outKey := buf.Bytes()

	if sizeInBits%8 != 0 {
		outKey[0] &= ((1 << uint(sizeInBits%8)) - 1)
	}
	return outKey
}

func EncryptSymmetricAES(key []byte, mode SymmetricMode, data, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cannot construct new block cipher: %v", err)
	}

	if mode != SymmetricModeCFB {
		return fmt.Errorf("unsupported block cipher mode %v", mode)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(data, data)
	return nil
}

func DecryptSymmetricAES(key []byte, mode SymmetricMode, data, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cannot construct new block cipher: %v", err)
	}

	if mode != SymmetricModeCFB {
		return fmt.Errorf("unsupported block cipher mode %v", mode)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return nil
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
