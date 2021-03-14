// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
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
	eccCurves = map[ECCCurve]elliptic.Curve{
		ECCCurveNIST_P224: elliptic.P224(),
		ECCCurveNIST_P256: elliptic.P256(),
		ECCCurveNIST_P384: elliptic.P384(),
		ECCCurveNIST_P521: elliptic.P521(),
	}

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

func zeroExtendBytes(x *big.Int, l int) (out []byte) {
	out = make([]byte, l)
	tmp := x.Bytes()
	copy(out[len(out)-len(tmp):], tmp)
	return
}

func cryptSecretDecrypt(priv crypto.PrivateKey, hashAlg HashAlgorithmId, label []byte, secret EncryptedSecret) ([]byte, error) {
	if !hashAlg.Supported() {
		return nil, fmt.Errorf("cannot determine size of unknown hashAlg %v", hashAlg)
	}

	switch p := priv.(type) {
	case *rsa.PrivateKey:
		h := hashAlg.NewHash()
		label0 := make([]byte, len(label)+1)
		copy(label0, label)
		return rsa.DecryptOAEP(h, rand.Reader, p, secret, label0)
	case *ecdsa.PrivateKey:
		var ephPoint ECCPoint
		if _, err := mu.UnmarshalFromBytes(secret, &ephPoint); err != nil {
			return nil, xerrors.Errorf("cannot unmarshal ephemeral point: %w", err)
		}
		ephX := new(big.Int).SetBytes(ephPoint.X)
		ephY := new(big.Int).SetBytes(ephPoint.Y)

		if !p.Curve.IsOnCurve(ephX, ephY) {
			return nil, errors.New("ephemeral point is not on curve")
		}

		sz := p.Curve.Params().BitSize / 8

		mulX, _ := p.Curve.ScalarMult(ephX, ephY, p.D.Bytes())
		return internal.KDFe(hashAlg.GetHash(), zeroExtendBytes(mulX, sz), label,
			ephPoint.X, zeroExtendBytes(p.X, sz), hashAlg.Size()*8), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

func cryptSecretEncrypt(public *Public, label []byte) (EncryptedSecret, []byte, error) {
	if !public.NameAlg.Supported() {
		return nil, nil, fmt.Errorf("cannot determine size of unknown nameAlg %v", public.NameAlg)
	}
	digestSize := public.NameAlg.Size()

	switch public.Type {
	case ObjectTypeRSA:
		if public.Params.RSADetail.Scheme.Scheme != RSASchemeNull &&
			public.Params.RSADetail.Scheme.Scheme != RSASchemeOAEP {
			return nil, nil, errors.New("unsupported RSA scheme")
		}
		pub := public.Public().(*rsa.PublicKey)

		secret := make([]byte, digestSize)
		if _, err := rand.Read(secret); err != nil {
			return nil, nil, fmt.Errorf("cannot read random bytes for secret: %v", err)
		}

		h := public.NameAlg.NewHash()
		label0 := make([]byte, len(label)+1)
		copy(label0, label)
		encryptedSecret, err := rsa.EncryptOAEP(h, rand.Reader, pub, secret, label0)
		return encryptedSecret, secret, err
	case ObjectTypeECC:
		pub := public.Public().(*ecdsa.PublicKey)
		if pub.Curve == nil {
			return nil, nil, fmt.Errorf("unsupported curve: %v", public.Params.ECCDetail.CurveID.GoCurve())
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, nil, fmt.Errorf("public key is not on curve")
		}

		ephPriv, ephX, ephY, err := elliptic.GenerateKey(pub.Curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate ephemeral ECC key: %v", err)
		}

		sz := pub.Curve.Params().BitSize / 8

		encryptedSecret, err := mu.MarshalToBytes(&ECCPoint{
			X: zeroExtendBytes(ephX, sz),
			Y: zeroExtendBytes(ephY, sz)})
		if err != nil {
			panic(fmt.Sprintf("failed to marshal secret: %v", err))
		}

		mulX, _ := pub.Curve.ScalarMult(pub.X, pub.Y, ephPriv)
		secret := internal.KDFe(public.NameAlg.GetHash(),
			zeroExtendBytes(mulX, sz), label, zeroExtendBytes(ephX, sz),
			zeroExtendBytes(pub.X, sz), digestSize*8)
		return encryptedSecret, secret, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key type %v", public.Type)
	}
}
