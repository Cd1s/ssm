package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	version   = 1
	saltLen   = 16
	nonceLen  = 12
	keyLen    = 32
	headerLen = 1 + saltLen + nonceLen
	argonTime = 3
	argonMem  = 64 * 1024
	argonPar  = 4
)

var ErrWrongPassword = errors.New("wrong password or corrupted file")

func Encrypt(plaintext []byte, password string) ([]byte, error) {
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

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, headerLen+len(ciphertext))
	out = append(out, byte(version))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

func Decrypt(data []byte, password string) ([]byte, error) {
	if len(data) < headerLen+16 {
		return nil, ErrWrongPassword
	}

	if data[0] != byte(version) {
		return nil, fmt.Errorf("unsupported version: %d", data[0])
	}

	salt := data[1 : 1+saltLen]
	nonce := data[1+saltLen : headerLen]
	ciphertext := data[headerLen:]

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMem, argonPar, keyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}

	return plaintext, nil
}

// ValidBlob reports whether data has the shape of an encrypted vault (known
// version byte and at least a header plus an authentication tag). It does not
// and cannot authenticate the contents; it keeps an obviously malformed
// download from replacing the only local copy.
func ValidBlob(data []byte) bool {
	return len(data) >= headerLen+16 && data[0] == byte(version)
}
