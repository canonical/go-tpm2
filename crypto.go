// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
)

var (
	defaultRSAExponent = 65537

	knownDigests = map[AlgorithmId]crypto.Hash{
		AlgorithmSHA1:   crypto.SHA1,
		AlgorithmSHA256: crypto.SHA256,
		AlgorithmSHA384: crypto.SHA384,
		AlgorithmSHA512: crypto.SHA512}
)

func cryptGetHash(alg AlgorithmId) crypto.Hash {
	h, ok := knownDigests[alg]
	if !ok {
		panic(fmt.Sprintf("unknown hash algorithm %v", alg))
	}
	return h
}

func cryptGetHashConstructor(alg AlgorithmId) func() hash.Hash {
	h, ok := knownDigests[alg]
	if !ok {
		panic(fmt.Sprintf("unknown hash algorithm %v", alg))
	}
	return func() hash.Hash {
		return h.New()
	}
}

func cryptConstructHash(alg AlgorithmId) hash.Hash {
	return cryptGetHashConstructor(alg)()
}

func cryptIsKnownDigest(alg AlgorithmId) bool {
	_, isKnown := knownDigests[alg]
	return isKnown
}

func cryptGetDigestSize(alg AlgorithmId) uint {
	h, ok := knownDigests[alg]
	if !ok {
		panic(fmt.Sprintf("nknown hash algorithm %v", alg))
	}
	return uint(h.Size())
}

func eccCurveToGoCurve(curve ECCCurve) elliptic.Curve {
	switch curve {
	case ECCCurveNIST_P224:
		return elliptic.P224()
	case ECCCurveNIST_P256:
		return elliptic.P256()
	case ECCCurveNIST_P384:
		return elliptic.P384()
	case ECCCurveNIST_P521:
		return elliptic.P521()
	}
	return nil
}

func cryptComputeCpHash(hashAlg AlgorithmId, commandCode CommandCode, commandHandles []Name,
	cpBytes []byte) []byte {
	hash := cryptConstructHash(hashAlg)

	binary.Write(hash, binary.BigEndian, commandCode)
	for _, name := range commandHandles {
		hash.Write([]byte(name))
	}
	hash.Write(cpBytes)

	return hash.Sum(nil)
}

func cryptComputeRpHash(hashAlg AlgorithmId, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte) []byte {
	hash := cryptConstructHash(hashAlg)

	binary.Write(hash, binary.BigEndian, responseCode)
	binary.Write(hash, binary.BigEndian, commandCode)
	hash.Write(rpBytes)

	return hash.Sum(nil)
}

func computeSessionHMAC(alg AlgorithmId, key, pHash []byte, nonceNewer, nonceOlder, nonceDecrypt, nonceEncrypt Nonce,
	attrs sessionAttrs) []byte {
	hmac := hmac.New(cryptGetHashConstructor(alg), key)

	hmac.Write(pHash)
	hmac.Write(nonceNewer)
	hmac.Write(nonceOlder)
	hmac.Write(nonceDecrypt)
	hmac.Write(nonceEncrypt)
	hmac.Write([]byte{uint8(attrs)})

	return hmac.Sum(nil)
}

func cryptComputeSessionCommandHMAC(context *sessionContext, key, cpHash []byte, nonceDecrypt, nonceEncrypt Nonce,
	attrs sessionAttrs) []byte {
	return computeSessionHMAC(context.hashAlg, key, cpHash, context.nonceCaller, context.nonceTPM, nonceDecrypt, nonceEncrypt, attrs)
}

func cryptComputeSessionResponseHMAC(context *sessionContext, key, rpHash []byte, attrs sessionAttrs) []byte {
	return computeSessionHMAC(context.hashAlg, key, rpHash, context.nonceTPM, context.nonceCaller, nil, nil, attrs)
}

func cryptKDFa(hashAlg AlgorithmId, key, label, contextU, contextV []byte, sizeInBits uint, counterInOut *uint32, once bool) []byte {
	digestSize := cryptGetDigestSize(hashAlg)
	if once && sizeInBits&7 > 0 {
		panic("sizeInBits must be a multiple of 8 when called with once == true")
	}

	var counter uint32 = 0
	if counterInOut != nil {
		counter = *counterInOut
	}
	var nbytes uint
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

		h := hmac.New(cryptGetHashConstructor(hashAlg), key)

		binary.Write(h, binary.BigEndian, counter)
		h.Write(label)
		h.Write([]byte{0})
		h.Write(contextU)
		h.Write(contextV)
		binary.Write(h, binary.BigEndian, uint32(sizeInBits))

		buf.Write(h.Sum(nil)[0:digestSize])
	}

	outKey := buf.Bytes()

	if sizeInBits%8 != 0 {
		outKey[0] &= ((1 << (sizeInBits % 8)) - 1)
	}
	if counterInOut != nil {
		*counterInOut = counter
	}
	return outKey
}

func cryptKDFe(hashAlg AlgorithmId, z, label, partyUInfo, partyVInfo []byte, sizeInBits uint) []byte {
	digestSize := cryptGetDigestSize(hashAlg)

	var counter uint32 = 0
	buf := new(bytes.Buffer)

	for bytes := (sizeInBits + 7) / 8; bytes > 0; bytes -= digestSize {
		if bytes < digestSize {
			digestSize = bytes
		}
		counter++

		h := cryptConstructHash(hashAlg)

		binary.Write(h, binary.BigEndian, counter)
		h.Write(z)
		h.Write(label)
		h.Write([]byte{0})
		h.Write(partyUInfo)
		h.Write(partyVInfo)

		buf.Write(h.Sum(nil)[0:digestSize])
	}

	outKey := buf.Bytes()

	if sizeInBits%8 != 0 {
		outKey[0] &= ((1 << (sizeInBits % 8)) - 1)
	}
	return outKey
}

func cryptComputeNonce(nonce []byte) error {
	_, err := rand.Read(nonce)
	return err
}

func cryptEncryptRSA(public *Public, paddingOverride AlgorithmId, data, label []byte) ([]byte, error) {
	if public.Type != AlgorithmRSA {
		panic(fmt.Sprintf("Unsupported key type %v", public.Type))
	}

	exp := int(public.Params.RSADetail().Exponent)
	if exp == 0 {
		exp = defaultRSAExponent
	}
	pubKey := &rsa.PublicKey{N: new(big.Int).SetBytes(public.Unique.RSA()), E: exp}

	padding := public.Params.RSADetail().Scheme.Scheme
	if paddingOverride != AlgorithmNull {
		padding = paddingOverride
	}

	switch padding {
	case AlgorithmOAEP:
		schemeHashAlg := public.NameAlg
		if paddingOverride == AlgorithmNull {
			schemeHashAlg = public.Params.RSADetail().Scheme.Details.OAEP().HashAlg
		}
		if schemeHashAlg == AlgorithmNull {
			schemeHashAlg = public.NameAlg
		}
		if !cryptIsKnownDigest(schemeHashAlg) {
			return nil, fmt.Errorf("unknown scheme hash algorithm: %v", schemeHashAlg)
		}
		hash := cryptConstructHash(schemeHashAlg)
		labelCopy := make([]byte, len(label)+1)
		copy(labelCopy, label)
		return rsa.EncryptOAEP(hash, rand.Reader, pubKey, data, labelCopy)
	case AlgorithmRSAES:
		return rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	}
	return nil, fmt.Errorf("unsupported RSA scheme: %v", padding)
}

func cryptGetECDHPoint(public *Public) (ECCParameter, *ECCPoint, error) {
	if public.Type != AlgorithmECC {
		panic(fmt.Sprintf("Unsupported key type %v", public.Type))
	}

	curve := eccCurveToGoCurve(public.Params.ECCDetail().CurveID)
	if curve == nil {
		return nil, nil, fmt.Errorf("unsupported curve: %v", public.Params.ECCDetail().CurveID)
	}

	ephPriv, ephX, ephY, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ephemeral ECC key: %v", err)
	}

	if !curve.IsOnCurve(ephX, ephY) {
		return nil, nil, fmt.Errorf("ephemeral public key is not on curve")
	}

	tpmX := new(big.Int).SetBytes(public.Unique.ECC().X)
	tpmY := new(big.Int).SetBytes(public.Unique.ECC().Y)

	mulX, _ := curve.ScalarMult(tpmX, tpmY, ephPriv)

	return ECCParameter(mulX.Bytes()), &ECCPoint{X: ECCParameter(ephX.Bytes()), Y: ECCParameter(ephY.Bytes())}, nil
}

func cryptComputeEncryptedSalt(public *Public) (EncryptedSecret, []byte, error) {
	if !cryptIsKnownDigest(public.NameAlg) {
		return nil, nil, fmt.Errorf("cannot determine size of unknown nameAlg %v", public.NameAlg)
	}
	digestSize := cryptGetDigestSize(public.NameAlg)

	switch public.Type {
	case AlgorithmRSA:
		salt := make([]byte, digestSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, fmt.Errorf("cannot read random bytes for salt: %v", err)
		}
		encryptedSalt, err := cryptEncryptRSA(public, AlgorithmOAEP, salt, []byte("SECRET"))
		return encryptedSalt, salt, err
	case AlgorithmECC:
		z, q, err := cryptGetECDHPoint(public)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute secret: %v", err)
		}
		encryptedSalt, err := MarshalToBytes(q)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ephemeral public key: %v", err)
		}
		salt := cryptKDFe(public.NameAlg, []byte(z), []byte("SECRET"), []byte(q.X), []byte(public.Unique.ECC().X), digestSize*8)
		return EncryptedSecret(encryptedSalt), salt, nil
	}

	return nil, nil, fmt.Errorf("unsupported key type %v", public.Type)
}

func cryptXORObfuscation(hashAlg AlgorithmId, key []byte, contextU, contextV Nonce, data []byte) error {
	if !cryptIsKnownDigest(hashAlg) {
		return fmt.Errorf("cannot determine digest size for unknown algorithm %v", hashAlg)
	}
	digestSize := cryptGetDigestSize(hashAlg)

	var counter uint32 = 0
	datasize := uint(len(data))
	remaining := int(datasize)

	for ; remaining > 0; remaining -= int(digestSize) {
		mask := cryptKDFa(hashAlg, key, []byte("XOR"), contextU, contextV, datasize*8, &counter, true)
		lim := remaining
		if int(digestSize) < remaining {
			lim = int(digestSize)
		}
		for i := 0; i < lim; i++ {
			data[int(datasize)-remaining+i] ^= mask[i]
		}
	}

	return nil
}

func cryptEncryptSymmetricAES(key []byte, mode AlgorithmId, data, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cannot construct new block cipher: %v", err)
	}

	if mode != AlgorithmCFB {
		return fmt.Errorf("unsupported block cipher mode %v", mode)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(data, data)
	return nil
}

func cryptDecryptSymmetricAES(key []byte, mode AlgorithmId, data, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cannot construct new block cipher: %v", err)
	}

	if mode != AlgorithmCFB {
		return fmt.Errorf("unsupported block cipher mode %v", mode)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return nil
}
