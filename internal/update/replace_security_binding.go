package update

import "hash"

func writeWindowsSecurityContractRMControl(
	digest hash.Hash,
	present bool,
	value byte,
) {
	var encoded [2]byte
	if present {
		encoded[0] = 1
		encoded[1] = value
	}
	_, _ = digest.Write(encoded[:])
}
