package update

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestWindowsSecurityContractRMControlCanonicalEncoding(t *testing.T) {
	tests := []struct {
		name    string
		present bool
		value   byte
		want    string
	}{
		{
			name: "absent",
			want: "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
		},
		{
			name:    "present zero",
			present: true,
			want:    "47dc540c94ceb704a23875c11273e16bb0b8a87aed84de911f2133568115f254",
		},
		{
			name:    "present value 42",
			present: true,
			value:   42,
			want:    "12a0f65cb25738c3251f2ddfab7129fb80de0f7f05e3e105ccac2f2b71076e9d",
		},
		{
			name:    "present value 43",
			present: true,
			value:   43,
			want:    "62a5ebd13c6089d8409a4584c107183b8c5214cb5b0a624d77d6558fbdebc9cc",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			digest := sha256.New()
			writeWindowsSecurityContractRMControl(digest, test.present, test.value)
			if got := fmt.Sprintf("%x", digest.Sum(nil)); got != test.want {
				t.Fatalf("canonical RM-control digest = %s, want %s", got, test.want)
			}
		})
	}
}
