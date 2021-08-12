// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto"
	"crypto/cipher"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"hash"
)

// This file contains types defined in section 9 (Interface Types) in
// part 2 of the library spec. Interface types are used by the TPM
// implementation to check that a value is appropriate for the context
// during unmarshalling. This package has limited support for some
// algorithm interfaces by defining context specific algorithm types
// based on the AlgorithmId type. Note that no interface types with
// TPM_HANDLE as the underlying type are supported, as this package
// doesn't use handles in most APIs.

// HashAlgorithmId corresponds to the TPMI_ALG_HASH type
type HashAlgorithmId AlgorithmId

// GetHash returns the equivalent crypto.Hash value for this algorithm if one
// exists, and 0 if one does not exist.
func (a HashAlgorithmId) GetHash() crypto.Hash {
	switch a {
	case HashAlgorithmSHA1:
		return crypto.SHA1
	case HashAlgorithmSHA256:
		return crypto.SHA256
	case HashAlgorithmSHA384:
		return crypto.SHA384
	case HashAlgorithmSHA512:
		return crypto.SHA512
	case HashAlgorithmSHA3_256:
		return crypto.SHA3_256
	case HashAlgorithmSHA3_384:
		return crypto.SHA3_384
	case HashAlgorithmSHA3_512:
		return crypto.SHA3_512
	default:
		return 0
	}
}

// IsValid determines if the digest algorithm is valid. This should be
// checked by code that deserializes an algorithm before calling Size
// if it does not want to panic.
func (a HashAlgorithmId) IsValid() bool {
	switch a {
	case HashAlgorithmSHA1:
	case HashAlgorithmSHA256:
	case HashAlgorithmSHA384:
	case HashAlgorithmSHA512:
	case HashAlgorithmSM3_256:
	case HashAlgorithmSHA3_256:
	case HashAlgorithmSHA3_384:
	case HashAlgorithmSHA3_512:
	default:
		return false
	}

	return true
}

// Available determines if the TPM digest algorithm has an equivalent go crypto.Hash
// that is linked into the current binary.
func (a HashAlgorithmId) Available() bool {
	return a.GetHash().Available()
}

// NewHash constructs a new hash.Hash implementation for this algorithm. It will panic if
// HashAlgorithmId.Available returns false.
func (a HashAlgorithmId) NewHash() hash.Hash {
	return a.GetHash().New()
}

// Size returns the size of the algorithm. It will panic if IsValid returns false.
func (a HashAlgorithmId) Size() int {
	switch a {
	case HashAlgorithmSHA1:
		return 20
	case HashAlgorithmSHA256:
		return 32
	case HashAlgorithmSHA384:
		return 48
	case HashAlgorithmSHA512:
		return 64
	case HashAlgorithmSM3_256:
		return 32
	case HashAlgorithmSHA3_256:
		return 32
	case HashAlgorithmSHA3_384:
		return 48
	case HashAlgorithmSHA3_512:
		return 64
	default:
		panic("unknown hash algorithm")
	}
}

// SymAlgorithmId corresponds to the TPMI_ALG_SYM type
type SymAlgorithmId AlgorithmId

// IsValidBlockCipher determines if this algorithm is a valid block cipher.
// This should be checked by code that deserializes an algorithm before calling
// BlockSize if it does not want to panic.
func (a SymAlgorithmId) IsValidBlockCipher() bool {
	switch a {
	case SymAlgorithmTDES:
	case SymAlgorithmAES:
	case SymAlgorithmSM4:
	case SymAlgorithmCamellia:
	default:
		return false
	}
	return true
}

// Available indicates whether the TPM symmetric cipher has a registered go implementation.
func (a SymAlgorithmId) Available() bool {
	_, ok := symmetricAlgs[a]
	return ok
}

// BlockSize indicates the block size of the symmetric cipher. This will panic if
// IsValidBlockCipher returns false.
func (a SymAlgorithmId) BlockSize() int {
	switch a {
	case SymAlgorithmTDES:
		return 8
	case SymAlgorithmAES:
		return 16
	case SymAlgorithmSM4:
		return 16
	case SymAlgorithmCamellia:
		return 16
	default:
		panic("invalid symmetric algorithm")
	}
}

// NewCipher constructs a new symmetric cipher with the supplied key, if there is a go
// implementation registered.
func (a SymAlgorithmId) NewCipher(key []byte) (cipher.Block, error) {
	fn, ok := symmetricAlgs[a]
	if !ok {
		return nil, errors.New("unavailable cipher")
	}
	return fn(key)
}

// SymObjectAlgorithmId corresponds to the TPMI_ALG_SYM_OBJECT type
type SymObjectAlgorithmId AlgorithmId

// IsValidBlockCipher determines if this algorithm is a valid block cipher.
// This should be checked by code that deserializes an algorithm before calling
// BlockSize if it does not want to panic.
func (a SymObjectAlgorithmId) IsValidBlockCipher() bool {
	return SymAlgorithmId(a).IsValidBlockCipher()
}

// Available indicates whether the TPM symmetric cipher has a registered go implementation.
func (a SymObjectAlgorithmId) Available() bool {
	return SymAlgorithmId(a).Available()
}

// BlockSize indicates the block size of the symmetric cipher. This will panic if
// IsValidBlockCipher returns false.
func (a SymObjectAlgorithmId) BlockSize() int {
	return SymAlgorithmId(a).BlockSize()
}

// NewCipher constructs a new symmetric cipher with the supplied key, if there is a go
// implementation registered.
func (a SymObjectAlgorithmId) NewCipher(key []byte) (cipher.Block, error) {
	return SymAlgorithmId(a).NewCipher(key)
}

// SymModeId corresponds to the TPMI_ALG_SYM_MODE type
type SymModeId AlgorithmId

// KDFAlgorithmId corresppnds to the TPMI_ALG_KDF type
type KDFAlgorithmId AlgorithmId

// SigSchemeId corresponds to the TPMI_ALG_SIG_SCHEME type
type SigSchemeId AlgorithmId
