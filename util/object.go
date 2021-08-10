// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"hash"
	"io/ioutil"

	"golang.org/x/xerrors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/internal"
	"github.com/canonical/go-tpm2/mu"
)

func UnwrapOuter(hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, name tpm2.Name, seed, data []byte) ([]byte, error) {
	r := bytes.NewReader(data)

	var integrity []byte
	if _, err := mu.UnmarshalFromReader(r, &integrity); err != nil {
		return nil, xerrors.Errorf("cannot unpack integrity digest: %w", err)
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot unpack wrapper: %w", err)
	}

	hmacKey := internal.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, hashAlg.Size()*8)
	h := hmac.New(func() hash.Hash { return hashAlg.NewHash() }, hmacKey)
	h.Write(data)
	h.Write(name)

	if !bytes.Equal(h.Sum(nil), integrity) {
		return nil, errors.New("integrity digest is invalid")
	}

	symKey := internal.KDFa(hashAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(symmetricAlg.KeyBits.Sym))

	if err := tpm2.CryptSymmetricDecrypt(tpm2.SymAlgorithmId(symmetricAlg.Algorithm), symKey, make([]byte, symmetricAlg.Algorithm.BlockSize()), data); err != nil {
		return nil, xerrors.Errorf("cannot remove wrapper: %w", err)
	}

	return data, nil
}

func ProduceOuterWrap(protector *tpm2.Public, name tpm2.Name, seed, data []byte) ([]byte, error) {
	symmetric := protector.Params.AsymDetail().Symmetric

	symKey := internal.KDFa(protector.NameAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(symmetric.KeyBits.Sym))

	if err := tpm2.CryptSymmetricEncrypt(tpm2.SymAlgorithmId(symmetric.Algorithm), symKey, make([]byte, symmetric.Algorithm.BlockSize()), data); err != nil {
		return nil, xerrors.Errorf("cannot apply wrapper: %w", err)
	}

	hmacKey := internal.KDFa(protector.NameAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, protector.NameAlg.Size()*8)
	h := hmac.New(func() hash.Hash { return protector.NameAlg.NewHash() }, hmacKey)
	h.Write(data)
	h.Write(name)

	integrity := h.Sum(nil)

	return mu.MustMarshalToBytes(integrity, mu.RawBytes(data)), nil
}

func DuplicateToSensitive(duplicate tpm2.Private, name tpm2.Name, parent crypto.PrivateKey, parentNameAlg tpm2.HashAlgorithmId, parentSymmetricAlg *tpm2.SymDefObject, seed []byte, symmetricAlg *tpm2.SymDefObject, innerSymKey tpm2.Data) (*tpm2.Sensitive, error) {
	if len(seed) > 0 {
		// Remove outer wrapper
		var err error
		duplicate, err = UnwrapOuter(parentNameAlg, parentSymmetricAlg, name, seed, duplicate)
		if err != nil {
			return nil, xerrors.Errorf("cannot unwrap outer wrapper: %w", err)
		}
	}

	if symmetricAlg != nil && symmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
		// Remove inner wrapper
		if err := tpm2.CryptSymmetricDecrypt(tpm2.SymAlgorithmId(symmetricAlg.Algorithm), innerSymKey, make([]byte, symmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, xerrors.Errorf("cannot remove inner wrapper: %w", err)
		}

		r := bytes.NewReader(duplicate)

		var innerIntegrity []byte
		if _, err := mu.UnmarshalFromReader(r, &innerIntegrity); err != nil {
			return nil, xerrors.Errorf("cannot unpack inner integrity digest: %w", err)
		}

		var err error
		duplicate, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, xerrors.Errorf("cannot unpack inner wrapper: %w", err)
		}

		h := name.Algorithm().NewHash()
		h.Write(duplicate)
		h.Write(name)

		if !bytes.Equal(h.Sum(nil), innerIntegrity) {
			return nil, errors.New("inner integrity digest is invalid")
		}
	}

	var sensitive struct {
		Ptr *tpm2.Sensitive `tpm2:"sized"`
	}
	if _, err := mu.UnmarshalFromBytes(duplicate, &sensitive); err != nil {
		return nil, xerrors.Errorf("cannot unmarhsal sensitive: %w", err)
	}

	return sensitive.Ptr, nil
}

func SensitiveToDuplicate(sensitive *tpm2.Sensitive, name tpm2.Name, parent *tpm2.Public, seed []byte, symmetricAlg *tpm2.SymDefObject, innerSymKey tpm2.Data) (innerSymKeyOut tpm2.Data, duplicate tpm2.Private, err error) {
	applyInnerWrapper := false
	if symmetricAlg != nil && symmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
		applyInnerWrapper = true
	}

	applyOuterWrapper := false
	if len(seed) > 0 {
		applyOuterWrapper = true
	}

	sensitiveSized := struct {
		Ptr *tpm2.Sensitive `tpm2:"sized"`
	}{sensitive}
	duplicate, err = mu.MarshalToBytes(sensitiveSized)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot marshal sensitive: %w", err)
	}

	if applyInnerWrapper {
		// Apply inner wrapper
		h := name.Algorithm().NewHash()
		h.Write(duplicate)
		h.Write(name)

		innerIntegrity := h.Sum(nil)

		duplicate = mu.MustMarshalToBytes(innerIntegrity, mu.RawBytes(duplicate))

		if len(innerSymKey) == 0 {
			innerSymKey = make([]byte, symmetricAlg.KeyBits.Sym/8)
			if _, err := rand.Read(innerSymKey); err != nil {
				return nil, nil, xerrors.Errorf("cannot read random bytes for key for inner wrapper: %w", err)
			}
			innerSymKeyOut = innerSymKey
		}

		if err := tpm2.CryptSymmetricEncrypt(tpm2.SymAlgorithmId(symmetricAlg.Algorithm), innerSymKey, make([]byte, symmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, nil, xerrors.Errorf("cannot apply inner wrapper: %w", err)
		}
	}

	if applyOuterWrapper {
		// Apply outer wrapper
		var err error
		duplicate, err = ProduceOuterWrap(parent, name, seed, duplicate)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot produce outer wrapper: %w", err)
		}
	}

	return innerSymKeyOut, duplicate, nil
}
