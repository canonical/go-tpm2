// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/canonical/go-tpm2/internal"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

type NewCipherFunc func([]byte) (cipher.Block, error)

type symmetricCipher struct {
	fn        NewCipherFunc
	blockSize int
}

var (
	symmetricAlgs = map[SymAlgorithmId]*symmetricCipher{
		SymAlgorithmAES: &symmetricCipher{aes.NewCipher, aes.BlockSize},
	}
)

// RegisterCipher allows a go block cipher implementation to be registered for the
// specified algorithm, so binaries don't need to link against every implementation.
func RegisterCipher(alg SymAlgorithmId, fn NewCipherFunc, blockSize int) {
	symmetricAlgs[alg] = &symmetricCipher{fn, blockSize}
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

func cryptComputeCpHash(hashAlg HashAlgorithmId, commandCode CommandCode, commandHandles []Name,
	cpBytes []byte) []byte {
	hash := hashAlg.NewHash()

	binary.Write(hash, binary.BigEndian, commandCode)
	for _, name := range commandHandles {
		hash.Write([]byte(name))
	}
	hash.Write(cpBytes)

	return hash.Sum(nil)
}

func cryptComputeRpHash(hashAlg HashAlgorithmId, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte) []byte {
	hash := hashAlg.NewHash()

	binary.Write(hash, binary.BigEndian, responseCode)
	binary.Write(hash, binary.BigEndian, commandCode)
	hash.Write(rpBytes)

	return hash.Sum(nil)
}

func cryptComputeNonce(nonce []byte) error {
	_, err := rand.Read(nonce)
	return err
}

func cryptSymmetricEncrypt(alg SymAlgorithmId, key, iv, data []byte) error {
	switch alg {
	case SymAlgorithmXOR, SymAlgorithmNull:
		return errors.New("unsupported symmetric algorithm")
	default:
		c, err := alg.NewCipher(key)
		if err != nil {
			return xerrors.Errorf("cannot create cipher: %w", err)
		}
		// The TPM uses CFB cipher mode for all secret sharing
		s := cipher.NewCFBEncrypter(c, iv)
		s.XORKeyStream(data, data)
		return nil
	}
}

func cryptSymmetricDecrypt(alg SymAlgorithmId, key, iv, data []byte) error {
	switch alg {
	case SymAlgorithmXOR, SymAlgorithmNull:
		return errors.New("unsupported symmetric algorithm")
	default:
		c, err := alg.NewCipher(key)
		if err != nil {
			return xerrors.Errorf("cannot create cipher: %w", err)
		}
		// The TPM uses CFB cipher mode for all secret sharing
		s := cipher.NewCFBDecrypter(c, iv)
		s.XORKeyStream(data, data)
		return nil
	}
}

func cryptEncryptRSA(public *Public, paddingOverride RSASchemeId, data, label []byte) ([]byte, error) {
	if public.Type != ObjectTypeRSA {
		panic(fmt.Sprintf("Unsupported key type %v", public.Type))
	}

	exp := int(public.Params.RSADetail.Exponent)
	if exp == 0 {
		exp = DefaultRSAExponent
	}
	pubKey := &rsa.PublicKey{N: new(big.Int).SetBytes(public.Unique.RSA), E: exp}

	padding := public.Params.RSADetail.Scheme.Scheme
	if paddingOverride != RSASchemeNull {
		padding = paddingOverride
	}

	switch padding {
	case RSASchemeOAEP:
		schemeHashAlg := public.NameAlg
		if paddingOverride == RSASchemeNull {
			schemeHashAlg = public.Params.RSADetail.Scheme.Details.OAEP.HashAlg
		}
		if schemeHashAlg == HashAlgorithmNull {
			schemeHashAlg = public.NameAlg
		}
		if !schemeHashAlg.Available() {
			return nil, fmt.Errorf("unknown scheme hash algorithm or algorithm not linked in to binary: %v", schemeHashAlg)
		}
		hash := schemeHashAlg.NewHash()
		labelCopy := make([]byte, len(label)+1)
		copy(labelCopy, label)
		return rsa.EncryptOAEP(hash, rand.Reader, pubKey, data, labelCopy)
	case RSASchemeRSAES:
		return rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	}
	return nil, fmt.Errorf("unsupported RSA scheme: %v", padding)
}

func cryptGetECDHPoint(public *Public) (ECCParameter, *ECCPoint, error) {
	if public.Type != ObjectTypeECC {
		panic(fmt.Sprintf("Unsupported key type %v", public.Type))
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

	return mulX.Bytes(), &ECCPoint{X: ephX.Bytes(), Y: ephY.Bytes()}, nil
}

func cryptComputeEncryptedSalt(public *Public) (EncryptedSecret, []byte, error) {
	if !public.NameAlg.Supported() {
		return nil, nil, fmt.Errorf("cannot determine size of unknown nameAlg %v", public.NameAlg)
	}
	digestSize := public.NameAlg.Size()

	switch public.Type {
	case ObjectTypeRSA:
		salt := make([]byte, digestSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, fmt.Errorf("cannot read random bytes for salt: %v", err)
		}
		encryptedSalt, err := cryptEncryptRSA(public, RSASchemeOAEP, salt, []byte("SECRET"))
		return encryptedSalt, salt, err
	case ObjectTypeECC:
		z, q, err := cryptGetECDHPoint(public)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute secret: %v", err)
		}
		encryptedSalt, err := mu.MarshalToBytes(q)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ephemeral public key: %v", err)
		}
		salt := internal.KDFe(public.NameAlg.GetHash(), []byte(z), []byte("SECRET"), []byte(q.X), []byte(public.Unique.ECC.X), digestSize*8)
		return encryptedSalt, salt, nil
	}

	return nil, nil, fmt.Errorf("unsupported key type %v", public.Type)
}
