package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// defaultHostKeyAlgorithms is anchored to golang.org/x/crypto v0.56.0
// (ssh/common.go defaultHostKeyAlgos). Re-check it whenever x/crypto is
// upgraded. It mirrors the host-key algorithm preference that
// golang.org/x/crypto/ssh applies when ClientConfig.HostKeyAlgorithms is empty.
// It is only used to fill in the algorithms behind the known_hosts key types.
var defaultHostKeyAlgorithms = []string{
	gossh.CertAlgoRSASHA256v01,
	gossh.CertAlgoRSASHA512v01,
	gossh.CertAlgoRSAv01,
	gossh.InsecureCertAlgoDSAv01, //nolint:staticcheck // mirrors x/crypto defaultHostKeyAlgos
	gossh.CertAlgoECDSA256v01,
	gossh.CertAlgoECDSA384v01,
	gossh.CertAlgoECDSA521v01,
	gossh.CertAlgoED25519v01,
	gossh.KeyAlgoECDSA256,
	gossh.KeyAlgoECDSA384,
	gossh.KeyAlgoECDSA521,
	gossh.KeyAlgoRSASHA256,
	gossh.KeyAlgoRSASHA512,
	gossh.KeyAlgoRSA,
	gossh.InsecureKeyAlgoDSA, //nolint:staticcheck // mirrors x/crypto defaultHostKeyAlgos
	gossh.KeyAlgoED25519,
}

// signatureAlgorithmsForKeyType maps a known_hosts key type to the host-key
// algorithms that can authenticate a key of that type.
func signatureAlgorithmsForKeyType(keyType string) []string {
	switch keyType {
	case gossh.KeyAlgoRSA:
		return []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA}
	case gossh.KeyAlgoECDSA256, gossh.KeyAlgoECDSA384, gossh.KeyAlgoECDSA521,
		gossh.KeyAlgoED25519, gossh.InsecureKeyAlgoDSA: //nolint:staticcheck // known_hosts may still hold DSA keys
		return []string{keyType}
	}
	return nil
}

var hostKeyProbe = sync.OnceValues(func() (gossh.PublicKey, error) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return gossh.NewPublicKey(public)
})

// splitCertAuthorities separates the entries x/crypto returned in a
// KeyError.Want into plain host keys and reports whether any of them comes from
// a @cert-authority line. A CA key is not a host key type: it is only
// meaningful for certificate verification, so it must not steer algorithm
// order or key-type comparison. The marker is read back from the known_hosts
// line; when that is not possible the entry is conservatively treated as a CA.
func splitCertAuthorities(path string, want []knownhosts.KnownKey) (plain []knownhosts.KnownKey, hasAuthority bool) {
	var lines [][]byte
	loaded := false
	for _, known := range want {
		isAuthority := true
		if !loaded {
			if data, err := os.ReadFile(path); err == nil { //nolint:gosec // configured known_hosts path
				lines = bytes.Split(data, []byte("\n"))
			}
			loaded = true
		}
		if known.Filename == path && known.Line >= 1 && known.Line <= len(lines) {
			text := bytes.TrimLeft(lines[known.Line-1], " \t")
			isAuthority = bytes.HasPrefix(text, []byte("@cert-authority")) &&
				(len(text) == len("@cert-authority") || text[len("@cert-authority")] == ' ' || text[len("@cert-authority")] == '\t')
		}
		if isAuthority {
			hasAuthority = true
			continue
		}
		plain = append(plain, known)
	}
	return plain, hasAuthority
}

// knownHostKeyTypes lists the plain host key types known_hosts records for
// address, in file order, and whether a @cert-authority entry also matches. It
// asks the knownhosts database with a throw-away key that can never match, so
// the resulting KeyError carries every entry for the host, including hashed
// and [host]:port forms.
func knownHostKeyTypes(path, address string) (types []string, hasAuthority bool) {
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, false
	}
	probe, err := hostKeyProbe()
	if err != nil {
		return nil, false
	}
	err = callback(address, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, probe)
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return nil, false
	}
	plain, hasAuthority := splitCertAuthorities(path, keyErr.Want)
	seen := map[string]bool{}
	for _, known := range plain {
		keyType := known.Key.Type()
		if !seen[keyType] {
			seen[keyType] = true
			types = append(types, keyType)
		}
	}
	return types, hasAuthority
}

// hostKeyAlgorithmsFor returns the host-key algorithm preference for address:
// the algorithms of the key types already present in known_hosts first (as
// OpenSSH does), then the remaining defaults. It returns nil, meaning the
// library default, when known_hosts holds no usable entry for the address or
// any @cert-authority entry matches it.
func hostKeyAlgorithmsFor(path, address string) []string {
	types, hasAuthority := knownHostKeyTypes(path, address)
	if hasAuthority {
		// A matching @cert-authority entry means the server may present a host
		// certificate: keep the library default, which prefers certificates.
		return nil
	}
	var preferred []string
	seen := map[string]bool{}
	for _, keyType := range types {
		for _, algorithm := range signatureAlgorithmsForKeyType(keyType) {
			if !seen[algorithm] {
				seen[algorithm] = true
				preferred = append(preferred, algorithm)
			}
		}
	}
	if len(preferred) == 0 {
		return nil
	}
	for _, algorithm := range defaultHostKeyAlgorithms {
		if !seen[algorithm] {
			seen[algorithm] = true
			preferred = append(preferred, algorithm)
		}
	}
	return preferred
}

// observedKeyType returns the plain key type of an observed host key; for a
// host certificate that is the type of the certified key.
func observedKeyType(key gossh.PublicKey) string {
	if certificate, ok := key.(*gossh.Certificate); ok && certificate.Key != nil {
		return certificate.Key.Type()
	}
	return key.Type()
}

// wantHasKeyType reports whether known_hosts holds an entry of the observed
// key type for the host.
func wantHasKeyType(want []knownhosts.KnownKey, key gossh.PublicKey) bool {
	observed := observedKeyType(key)
	for _, known := range want {
		if known.Key.Type() == observed {
			return true
		}
	}
	return false
}
