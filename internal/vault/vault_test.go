package vault

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
)

const testPassword = "test-passphrase-not-secret"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		plaintext []byte
	}{
		{name: "empty", plaintext: nil},
		{name: "short", plaintext: []byte("vault round-trip")},
		{name: "large", plaintext: bytes.Repeat([]byte("vault payload\n"), 256*1024)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := Encrypt(tc.plaintext, testPassword)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			plaintext, err := Decrypt(ciphertext, testPassword)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(plaintext, tc.plaintext) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(plaintext), len(tc.plaintext))
			}
		})
	}
}

func TestDecryptWrongPasswordDoesNotRevealData(t *testing.T) {
	plaintext := []byte("vault plaintext must stay private")
	ciphertext, err := Encrypt(plaintext, testPassword)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrongPassword := testPassword + "-wrong"
	decrypted, err := Decrypt(ciphertext, wrongPassword)
	if err == nil {
		t.Fatal("Decrypt with wrong password succeeded")
	}
	if decrypted != nil {
		t.Fatalf("Decrypt returned plaintext with an error: %q", decrypted)
	}
	if message := err.Error(); strings.Contains(message, testPassword) ||
		strings.Contains(message, wrongPassword) || strings.Contains(message, string(plaintext)) {
		t.Fatalf("error reveals password or plaintext: %q", message)
	}
}

func TestDecryptRejectsCorruption(t *testing.T) {
	plaintext := []byte("corruption must never decrypt successfully")
	ciphertext, err := Encrypt(plaintext, testPassword)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	mutated := func(offset int) []byte {
		data := append([]byte(nil), ciphertext...)
		data[offset] ^= 0xff
		return data
	}
	cases := []struct {
		name string
		data []byte
	}{
		{name: "version", data: mutated(0)},
		{name: "salt", data: mutated(1)},
		{name: "nonce", data: mutated(1 + saltLen)},
		{name: "ciphertext", data: mutated(headerLen + 1)},
		{name: "authentication tag", data: mutated(len(ciphertext) - 1)},
	}
	for _, length := range []int{0, 1, headerLen - 1, headerLen, headerLen + 15, len(ciphertext) - 1} {
		cases = append(cases, struct {
			name string
			data []byte
		}{name: "truncate-" + strconv.Itoa(length), data: ciphertext[:length]})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decrypted, err := Decrypt(tc.data, testPassword)
			if err == nil {
				t.Fatalf("Decrypt accepted corrupted data and returned %d bytes", len(decrypted))
			}
		})
	}
}

func TestEncryptIsRandomized(t *testing.T) {
	plaintext := []byte("same plaintext, fresh salt and nonce")
	first, err := Encrypt(plaintext, testPassword)
	if err != nil {
		t.Fatalf("first Encrypt: %v", err)
	}
	second, err := Encrypt(plaintext, testPassword)
	if err != nil {
		t.Fatalf("second Encrypt: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("Encrypt returned identical ciphertext twice")
	}
}

func TestDecryptKnownFormat(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/vault-v1.enc")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	const want = "known vault format sample\n"
	plaintext, err := Decrypt(ciphertext, testPassword)
	if err != nil {
		t.Fatalf("Decrypt fixed sample: %v", err)
	}
	if string(plaintext) != want {
		t.Fatalf("fixed sample plaintext = %q, want %q", plaintext, want)
	}
}
