// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/crypto"
	"github.com/canonical/go-tpm2/mu"
)

// UnwrapOuter removes an outer wrapper from the supplied sensitive data blob. The
// supplied name is associated with the data.
//
// It checks the integrity HMAC is valid using the specified digest algorithm and
// a key derived from the supplied seed and returns an error if the check fails.
//
// It then decrypts the data blob using the specified symmetric algorithm and a
// key derived from the supplied seed and name.
func UnwrapOuter(hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, name tpm2.Name, seed []byte, useIV bool, data []byte) ([]byte, error) {
	if !hashAlg.Available() {
		return nil, errors.New("digest algorithm is not available")
	}
	if symmetricAlg == nil || !symmetricAlg.Algorithm.IsValidBlockCipher() {
		return nil, errors.New("symmetric algorithm is not a valid block cipher")
	}

	r := bytes.NewReader(data)

	var integrity []byte
	if _, err := mu.UnmarshalFromReader(r, &integrity); err != nil {
		return nil, fmt.Errorf("cannot unmarshal integrity digest: %w", err)
	}

	data, _ = ioutil.ReadAll(r)

	hmacKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, hashAlg.Size()*8)
	h := hmac.New(func() hash.Hash { return hashAlg.NewHash() }, hmacKey)
	h.Write(data)
	h.Write(name)

	if !bytes.Equal(h.Sum(nil), integrity) {
		return nil, errors.New("integrity digest is invalid")
	}

	r = bytes.NewReader(data)

	iv := make([]byte, symmetricAlg.Algorithm.BlockSize())
	if useIV {
		if _, err := mu.UnmarshalFromReader(r, &iv); err != nil {
			return nil, fmt.Errorf("cannot unmarshal IV: %w", err)
		}
		if len(iv) != symmetricAlg.Algorithm.BlockSize() {
			return nil, errors.New("IV has the wrong size")
		}
	}

	data, _ = ioutil.ReadAll(r)

	symKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(symmetricAlg.KeyBits.Sym))

	if err := crypto.SymmetricDecrypt(symmetricAlg.Algorithm, symKey, iv, data); err != nil {
		return nil, fmt.Errorf("cannot decrypt: %w", err)
	}

	return data, nil
}

// ProduceOuterWrap adds an outer wrapper to the supplied data. The supplied name
// is associated with the data.
//
// It encrypts the data using the specified symmetric algorithm and a key derived
// from the supplied seed and name.
//
// It then prepends an integrity HMAC of the encrypted data and the supplied
// name using the specified digest algorithm and a key derived from the supplied
// seed.
func ProduceOuterWrap(hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, name tpm2.Name, seed []byte, useIV bool, data []byte) ([]byte, error) {
	if !hashAlg.Available() {
		return nil, errors.New("digest algorithm is not available")
	}
	if symmetricAlg == nil || !symmetricAlg.Algorithm.IsValidBlockCipher() {
		return nil, errors.New("symmetric algorithm is not a valid block cipher")
	}

	iv := make([]byte, symmetricAlg.Algorithm.BlockSize())
	if useIV {
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("cannot generate IV: %w", err)
		}
	}

	symKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(symmetricAlg.KeyBits.Sym))

	if err := crypto.SymmetricEncrypt(symmetricAlg.Algorithm, symKey, iv, data); err != nil {
		return nil, fmt.Errorf("cannot encrypt: %w", err)
	}

	if useIV {
		data = mu.MustMarshalToBytes(iv, mu.RawBytes(data))
	}

	hmacKey := crypto.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, hashAlg.Size()*8)
	h := hmac.New(func() hash.Hash { return hashAlg.NewHash() }, hmacKey)
	h.Write(data)
	h.Write(name)

	integrity := h.Sum(nil)

	return mu.MustMarshalToBytes(integrity, mu.RawBytes(data)), nil
}

func duplicateToSensitive(duplicate tpm2.Private, name tpm2.Name, outerHashAlg tpm2.HashAlgorithmId, outerSymmetricAlg *tpm2.SymDefObject, outerSeed []byte, innerSymmetricAlg *tpm2.SymDefObject, innerSymmetricKey tpm2.Data) (sensitive *tpm2.Sensitive, err error) {
	if len(outerSeed) > 0 {
		// Remove outer wrapper
		duplicate, err = UnwrapOuter(outerHashAlg, outerSymmetricAlg, name, outerSeed, false, duplicate)
		if err != nil {
			return nil, fmt.Errorf("cannot unwrap outer wrapper: %w", err)
		}
	}

	if innerSymmetricAlg != nil && innerSymmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
		// Remove inner wrapper
		if name.Algorithm() == tpm2.HashAlgorithmNull {
			return nil, errors.New("invalid name")
		}
		if !name.Algorithm().Available() {
			return nil, errors.New("name algorithm is not available")
		}
		if !innerSymmetricAlg.Algorithm.IsValidBlockCipher() {
			return nil, errors.New("inner symmetric algorithm is not a valid block cipher")
		}

		if err := crypto.SymmetricDecrypt(innerSymmetricAlg.Algorithm, innerSymmetricKey, make([]byte, innerSymmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, fmt.Errorf("cannot decrypt inner wrapper: %w", err)
		}

		r := bytes.NewReader(duplicate)

		var innerIntegrity []byte
		if _, err := mu.UnmarshalFromReader(r, &innerIntegrity); err != nil {
			return nil, fmt.Errorf("cannot unmarshal inner integrity digest: %w", err)
		}

		duplicate, _ = ioutil.ReadAll(r)

		h := name.Algorithm().NewHash()
		h.Write(duplicate)
		h.Write(name)

		if !bytes.Equal(h.Sum(nil), innerIntegrity) {
			return nil, errors.New("inner integrity digest is invalid")
		}
	}

	if _, err := mu.UnmarshalFromBytes(duplicate, mu.Sized(&sensitive)); err != nil {
		return nil, fmt.Errorf("cannot unmarhsal sensitive: %w", err)
	}

	return sensitive, nil
}

func sensitiveToDuplicate(sensitive *tpm2.Sensitive, name tpm2.Name, outerHashAlg tpm2.HashAlgorithmId, outerSymmetricAlg *tpm2.SymDefObject, outerSeed []byte, innerSymmetricAlg *tpm2.SymDefObject, innerSymmetricKey tpm2.Data) (innerSymmetricKeyOut tpm2.Data, duplicate tpm2.Private, err error) {
	applyInnerWrapper := false
	if innerSymmetricAlg != nil && innerSymmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
		applyInnerWrapper = true
	}

	applyOuterWrapper := false
	if len(outerSeed) > 0 {
		applyOuterWrapper = true
	}

	duplicate, err = mu.MarshalToBytes(mu.Sized(sensitive))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal sensitive: %w", err)
	}

	if applyInnerWrapper {
		if name.Algorithm() == tpm2.HashAlgorithmNull {
			return nil, nil, errors.New("invalid name")
		}
		if !name.Algorithm().Available() {
			return nil, nil, errors.New("name algorithm is not available")
		}
		if !innerSymmetricAlg.Algorithm.IsValidBlockCipher() {
			return nil, nil, errors.New("inner symmetric algorithm is not a valid block cipher")
		}

		// Apply inner wrapper
		h := name.Algorithm().NewHash()
		h.Write(duplicate)
		h.Write(name)

		innerIntegrity := h.Sum(nil)

		duplicate = mu.MustMarshalToBytes(innerIntegrity, mu.RawBytes(duplicate))

		if len(innerSymmetricKey) == 0 {
			innerSymmetricKeyOut = make([]byte, innerSymmetricAlg.KeyBits.Sym/8)
			if _, err := rand.Read(innerSymmetricKeyOut); err != nil {
				return nil, nil, fmt.Errorf("cannot obtain symmetric key for inner wrapper: %w", err)
			}
			innerSymmetricKey = innerSymmetricKeyOut
		} else if len(innerSymmetricKey) != int(innerSymmetricAlg.KeyBits.Sym/8) {
			return nil, nil, errors.New("the supplied symmetric key for inner wrapper has the wrong length")
		}

		if err := crypto.SymmetricEncrypt(innerSymmetricAlg.Algorithm, innerSymmetricKey, make([]byte, innerSymmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, nil, fmt.Errorf("cannot apply inner wrapper: %w", err)
		}
	}

	if applyOuterWrapper {
		// Apply outer wrapper
		duplicate, err = ProduceOuterWrap(outerHashAlg, outerSymmetricAlg, name, outerSeed, false, duplicate)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot apply outer wrapper: %w", err)
		}
	}

	return innerSymmetricKeyOut, duplicate, nil
}
