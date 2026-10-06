package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	versionV1   = 1
	versionV2   = 2
	version     = versionV1
	saltLen     = 16
	nonceLen    = 12
	keyLen      = 32
	headerLen   = 1 + saltLen + nonceLen
	v2HeaderLen = 1 + 8 + saltLen + nonceLen
	argonTime   = 3
	argonMem    = 64 * 1024
	argonPar    = 4
)

var ErrWrongPassword = errors.New("wrong password or corrupted file")

// Encrypt writes authenticated v2. An omitted generation is zero for legacy
// source compatibility with callers that only construct fixture blobs.
func Encrypt(plaintext []byte, password string, generations ...uint64) ([]byte, error) {
	var generation uint64
	if len(generations) > 0 {
		generation = generations[0]
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMem, argonPar, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	header := make([]byte, v2HeaderLen)
	header[0] = versionV2
	binary.BigEndian.PutUint64(header[1:9], generation)
	copy(header[9:9+saltLen], salt)
	copy(header[9+saltLen:], nonce)
	ciphertext := gcm.Seal(nil, nonce, plaintext, header[:9])
	return append(header, ciphertext...), nil
}

func Decrypt(data []byte, password string) ([]byte, error) {
	if len(data) < headerLen+16 {
		return nil, ErrWrongPassword
	}
	var salt, nonce, aad []byte
	start := headerLen
	switch data[0] {
	case versionV1:
		salt = data[1 : 1+saltLen]
		nonce = data[1+saltLen : headerLen]
	case versionV2:
		if len(data) < v2HeaderLen+16 {
			return nil, ErrWrongPassword
		}
		salt = data[9 : 9+saltLen]
		nonce = data[9+saltLen : v2HeaderLen]
		aad = data[:9]
		start = v2HeaderLen
	default:
		return nil, fmt.Errorf("unsupported version: %d", data[0])
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMem, argonPar, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, data[start:], aad)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return plaintext, nil
}

// Generation reads only the format header and needs no password.
func Generation(data []byte) (uint64, bool) {
	if len(data) < 1 {
		return 0, false
	}
	switch data[0] {
	case versionV1:
		return 0, len(data) >= headerLen+16
	case versionV2:
		if len(data) < v2HeaderLen+16 {
			return 0, false
		}
		return binary.BigEndian.Uint64(data[1:9]), true
	default:
		return 0, false
	}
}

func ValidBlob(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	switch data[0] {
	case versionV1:
		return len(data) >= headerLen+16
	case versionV2:
		return len(data) >= v2HeaderLen+16
	default:
		return false
	}
}
