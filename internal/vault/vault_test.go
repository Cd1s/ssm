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

func TestValidBlob(t *testing.T) {
	minimum := make([]byte, headerLen+16)
	minimum[0] = byte(version)
	wrongVersion := append([]byte(nil), minimum...)
	wrongVersion[0]++
	tooShortValidVersion := make([]byte, headerLen+15)
	tooShortValidVersion[0] = byte(version)
	tooShortWrongVersion := make([]byte, headerLen+15)
	minimumVersionZero := make([]byte, headerLen+16)
	minimumPlusOne := make([]byte, headerLen+17)
	minimumPlusOne[0] = byte(version)
	encrypted, err := Encrypt([]byte("valid blob"), testPassword)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	corruptedEncrypted := append([]byte(nil), encrypted...)
	corruptedEncrypted[0]++

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "nil", data: nil, want: false},
		{name: "empty", data: []byte{}, want: false},
		{name: "too short", data: tooShortValidVersion, want: false},
		{name: "too short, wrong version", data: tooShortWrongVersion, want: false},
		{name: "minimum length, version zero", data: minimumVersionZero, want: false},
		{name: "minimum valid shape", data: minimum, want: true},
		{name: "minimum length plus one, valid version", data: minimumPlusOne, want: true},
		{name: "minimum wrong version", data: wrongVersion, want: false},
		{name: "encrypted output", data: encrypted, want: true},
		{name: "encrypted output wrong version", data: corruptedEncrypted, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidBlob(tc.data); got != tc.want {
				t.Fatalf("ValidBlob = %v, want %v", got, tc.want)
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
		t.Error("Encrypt returned identical ciphertext twice")
	}
	if bytes.Equal(first[1:1+saltLen], second[1:1+saltLen]) {
		t.Error("Encrypt reused salt across calls")
	}
	if bytes.Equal(first[1+saltLen:headerLen], second[1+saltLen:headerLen]) {
		t.Error("Encrypt reused nonce across calls")
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
