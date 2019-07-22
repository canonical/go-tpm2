package tpm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
)

var (
	defaultRSAExponent = 65537

	knownDigests = map[AlgorithmId]struct {
		constructor func() hash.Hash
		size        int
	}{
		AlgorithmSHA1:   {constructor: sha1.New, size: sha1.Size},
		AlgorithmSHA256: {constructor: sha256.New, size: sha256.Size},
		AlgorithmSHA384: {constructor: sha512.New384, size: sha512.Size384},
		AlgorithmSHA512: {constructor: sha512.New, size: sha512.Size}}
)

func cryptHashAlgToGoConstructor(hashAlg AlgorithmId) func() hash.Hash {
	knownDigest, isKnown := knownDigests[hashAlg]
	if !isKnown {
		return nil
	}
	return knownDigest.constructor
}

func cryptIsKnownDigest(alg AlgorithmId) bool {
	_, isKnown := knownDigests[alg]
	return isKnown
}

func cryptGetDigestSize(alg AlgorithmId) (uint, error) {
	known, isKnown := knownDigests[alg]
	if !isKnown {
		return 0, fmt.Errorf("unknown digest algorithm: %v", alg)
	}
	return uint(known.size), nil
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
	hash := cryptHashAlgToGoConstructor(hashAlg)()

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
	hash := cryptHashAlgToGoConstructor(hashAlg)()

	b, _ := MarshalToBytes(responseCode)
	hash.Write(b)
	b, _ = MarshalToBytes(commandCode)
	hash.Write(b)
	hash.Write(rpBytes)

	return hash.Sum(nil)[:]
}

func cryptComputeSessionHMAC(context *sessionContext, authValue, pHash []byte, attrs sessionAttrs,
	command bool) []byte {
	key := make([]byte, len(context.sessionKey)+len(authValue))
	copy(key, context.sessionKey)
	copy(key[len(context.sessionKey):], authValue)

	hmac := hmac.New(cryptHashAlgToGoConstructor(context.hashAlg), key)
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
	digestSize, err := cryptGetDigestSize(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("cannot determine digest size: %v", err)
	}

	var counter uint32 = 0
	buf := new(bytes.Buffer)

	for bytes := (sizeInBits + 7) / 8; bytes > 0; bytes -= digestSize {
		counter++
		if bytes < digestSize {
			digestSize = bytes
		}

		h := hmac.New(cryptHashAlgToGoConstructor(hashAlg), key)

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
	return outKey, nil
}

func cryptKDFe(hashAlg AlgorithmId, z, label, partyUInfo, partyVInfo []byte, sizeInBits uint) ([]byte, error) {
	digestSize, err := cryptGetDigestSize(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("cannot determine digest size: %v", err)
	}

	var counter uint32 = 0
	buf := new(bytes.Buffer)

	for bytes := (sizeInBits + 7) / 8; bytes > 0; bytes -= digestSize {
		if bytes < digestSize {
			digestSize = bytes
		}
		counter++

		h := cryptHashAlgToGoConstructor(hashAlg)()

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
	return outKey, nil
}

func cryptComputeNonce(nonce []byte) error {
	_, err := rand.Read(nonce)
	return err
}

func cryptEncryptRSA(public *Public, padding AlgorithmId, data, label []byte) ([]byte, error) {
	if public.Type != AlgorithmRSA {
		return nil, fmt.Errorf("unsupported key type %v", public.Type)
	}

	exp := int(public.Params.RSADetail.Exponent)
	if exp == 0 {
		exp = defaultRSAExponent
	}
	pubKey := &rsa.PublicKey{N: new(big.Int).SetBytes(public.Unique.RSA), E: exp}

	if padding == AlgorithmNull {
		padding = public.Params.RSADetail.Scheme.Scheme
	}

	switch padding {
	case AlgorithmOAEP:
		schemeHashAlg := public.NameAlg
		if padding == AlgorithmNull {
			schemeHashAlg = public.Params.RSADetail.Scheme.Details.OAEP.HashAlg
		}
		if schemeHashAlg == AlgorithmNull {
			schemeHashAlg = public.NameAlg
		}
		if !cryptIsKnownDigest(schemeHashAlg) {
			return nil, fmt.Errorf("unknown scheme hash algorithm: %v", schemeHashAlg)
		}
		hash := cryptHashAlgToGoConstructor(schemeHashAlg)()
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
		return nil, nil, fmt.Errorf("unsupported key type %v", public.Type)
	}

	curve := eccCurveToGoCurve(public.Params.ECCDetail.CurveID)
	if curve == nil {
		return nil, nil, fmt.Errorf("unsupported curve: %v", public.Params.ECCDetail.CurveID)
	}

	ephPriv, ephX, ephY, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ephemeral ECC key: %v", err)
	}

	if !curve.IsOnCurve(ephX, ephY) {
		return nil, nil, fmt.Errorf("ephemeral public key is not on curve")
	}

	tpmX := new(big.Int).SetBytes(public.Unique.ECC.X)
	tpmY := new(big.Int).SetBytes(public.Unique.ECC.Y)

	mulX, _ := curve.ScalarMult(tpmX, tpmY, ephPriv)

	return ECCParameter(mulX.Bytes()),
		&ECCPoint{X: ECCParameter(ephX.Bytes()), Y: ECCParameter(ephY.Bytes())},
		nil
}

func cryptComputeEncryptedSalt(public *Public) (EncryptedSecret, []byte, error) {
	digestSize, err := cryptGetDigestSize(public.NameAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot determine size of nameAlg: %v", err)
	}

	salt := make([]byte, digestSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("cannot read random bytes for salt: %v", err)
	}

	switch public.Type {
	case AlgorithmRSA:
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
		salt, err := cryptKDFe(public.NameAlg,
			[]byte(z),
			[]byte("SECRET"),
			[]byte(q.X),
			[]byte(public.Unique.ECC.X),
			digestSize*8)
		if err != nil {
			return nil, nil, fmt.Errorf("failed KDFe: %v", err)
		}
		return EncryptedSecret(encryptedSalt), salt, nil
	}

	return nil, nil, fmt.Errorf("unsupported key type %v", public.Type)
}
