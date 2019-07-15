package tpm2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

var digestSizes = map[AlgorithmId]uint{
	AlgorithmSHA1:   20,
	AlgorithmSHA256: 32,
	AlgorithmSHA384: 48,
	AlgorithmSHA512: 64,
}

func hashAlgToGoConstructor(hashAlg AlgorithmId) func () hash.Hash {
	switch hashAlg {
	case AlgorithmSHA1:
		return sha1.New
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA384:
		return sha512.New384
	case AlgorithmSHA512:
		return sha512.New
	default:
		panic("unsupported algorithm")
	}
}

func cryptComputeCpHash(hashAlg AlgorithmId, commandCode CommandCode, commandHandles []Name,
	cpBytes []byte) []byte {
	hash := hashAlgToGoConstructor(hashAlg)()

	b, _ := MarshalToBytes(commandCode)
	hash.Write(b)
	for _, name := range commandHandles {
		hash.Write([]byte(name))
	}
	hash.Write(cpBytes)

	return hash.Sum(nil)[:]
}

func cryptComputeRpHash(hashAlg AlgorithmId, responseCode ResponseCode, commandCode CommandCode,
	rpBytes []byte) []byte {
	hash := hashAlgToGoConstructor(hashAlg)()

	b, _ := MarshalToBytes(responseCode)
	hash.Write(b)
	b, _ = MarshalToBytes(commandCode)
	hash.Write(b)
	hash.Write(rpBytes)

	return hash.Sum(nil)[:]
}

func cryptComputeSessionHMAC(context *sessionContext, authValue, pHash []byte, attrs sessionAttrs,
	command bool) []byte {
	key := make([]byte, len(context.sessionKey) + len(authValue))
	copy(key, context.sessionKey)
	copy(key[len(context.sessionKey):], authValue)

	hmac := hmac.New(hashAlgToGoConstructor(context.hashAlg), key)
	hmac.Write(pHash)
	if command {
		hmac.Write(context.nonceCaller)
		hmac.Write(context.nonceTPM)
	} else {
		hmac.Write(context.nonceTPM)
		hmac.Write(context.nonceCaller)
	}
	hmac.Write([]byte{uint8(attrs)})

	return hmac.Sum(nil)[:]
}

func cryptComputeSessionCommandHMAC(context *sessionContext, authValue, cpHash []byte,
	attrs sessionAttrs) []byte {
	return cryptComputeSessionHMAC(context, authValue, cpHash, attrs, true)
}

func cryptComputeSessionResponseHMAC(context *sessionContext, authValue, rpHash []byte,
	attrs sessionAttrs) []byte {
	return cryptComputeSessionHMAC(context, authValue, rpHash, attrs, false)
}

func cryptKDFa(hashAlg AlgorithmId, key, label, contextU, contextV []byte, sizeInBits uint) ([]byte, error) {
	digestSize, knownDigest := digestSizes[hashAlg]
	if !knownDigest {
		return nil, fmt.Errorf("unknown hashAlg: %v", hashAlg)
	}

	var counter uint32 = 0
	buf := new(bytes.Buffer)

	for bytes := (sizeInBits + 7) / 8; bytes > 0; bytes -= digestSize {
		counter++
		if bytes < digestSize {
			digestSize = bytes
		}

		h := hmac.New(hashAlgToGoConstructor(hashAlg), key)

		counterRaw := make([]byte, 4)
		binary.BigEndian.PutUint32(counterRaw, counter)
		h.Write(counterRaw)

		h.Write(label)
		h.Write([]byte{0})
		h.Write(contextU)
		h.Write(contextV)

		sizeInBitsRaw := make([]byte, 4)
		binary.BigEndian.PutUint32(sizeInBitsRaw, uint32(sizeInBits))
		h.Write(sizeInBitsRaw)

		buf.Write(h.Sum(nil)[0:digestSize])
	}

	outKey := buf.Bytes()

	if sizeInBits % 8 != 0 {
		outKey[0] &= ((1 << (sizeInBits % 8)) - 1)
	}
	return outKey, nil
}
