package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// defaultHostKeyAlgorithms mirrors the host-key algorithm preference that
// golang.org/x/crypto/ssh applies when ClientConfig.HostKeyAlgorithms is empty.
// It is only used to fill in the algorithms behind the known_hosts key types.
var defaultHostKeyAlgorithms = []string{
	gossh.CertAlgoRSASHA256v01,
	gossh.CertAlgoRSASHA512v01,
	gossh.CertAlgoRSAv01,
	gossh.InsecureCertAlgoDSAv01,
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
	gossh.InsecureKeyAlgoDSA,
	gossh.KeyAlgoED25519,
}

// signatureAlgorithmsForKeyType maps a known_hosts key type to the host-key
// algorithms that can authenticate a key of that type.
func signatureAlgorithmsForKeyType(keyType string) []string {
	switch keyType {
	case gossh.KeyAlgoRSA:
		return []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA}
	case gossh.KeyAlgoECDSA256, gossh.KeyAlgoECDSA384, gossh.KeyAlgoECDSA521,
		gossh.KeyAlgoED25519, gossh.InsecureKeyAlgoDSA:
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

// knownHostKeyTypes lists the key types known_hosts records for address, in
// file order. It asks the knownhosts database with a throw-away key that can
// never match, so the resulting KeyError carries every entry for the host,
// including hashed and [host]:port forms.
func knownHostKeyTypes(path, address string) []string {
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil
	}
	probe, err := hostKeyProbe()
	if err != nil {
		return nil
	}
	err = callback(address, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, probe)
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return nil
	}
	var types []string
	seen := map[string]bool{}
	for _, known := range keyErr.Want {
		keyType := known.Key.Type()
		if !seen[keyType] {
			seen[keyType] = true
			types = append(types, keyType)
		}
	}
	return types
}

// hostKeyAlgorithmsFor returns the host-key algorithm preference for address:
// the algorithms of the key types already present in known_hosts first (as
// OpenSSH does), then the remaining defaults. It returns nil, meaning the
// library default, when known_hosts holds no usable entry for the address.
func hostKeyAlgorithmsFor(path, address string) []string {
	var preferred []string
	seen := map[string]bool{}
	for _, keyType := range knownHostKeyTypes(path, address) {
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
