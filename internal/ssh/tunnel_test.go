package ssh

import (
	"context"
	"testing"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func TestParseLocalForward(t *testing.T) {
	valid := []string{"15037:127.0.0.1:5037", "127.0.0.1:15037:target:5037", "[::1]:15037:[::1]:5037"}
	for _, in := range valid {
		if _, err := ParseLocalForward(in); err != nil {
			t.Errorf("ParseLocalForward(%q): %v", in, err)
		}
	}
	invalid := []string{"", "15037", ":target:5037", "127.0.0.1:0:target:1", "127.0.0.1:65536:target:1", "127.0.0.1:1::1", "127.0.0.1:1:target:65536", "a:b:c:d:e"}
	for _, in := range invalid {
		if _, err := ParseLocalForward(in); err == nil {
			t.Errorf("ParseLocalForward(%q) unexpectedly succeeded", in)
		}
	}
}

func TestRunTunnelRejectsRemoteBindBeforeDial(t *testing.T) {
	spec := TunnelSpec{Kind: "dynamic", Bind: "192.0.2.1", Port: 12345}
	_, err := RunTunnel(context.Background(), config.Connection{}, nil, []TunnelSpec{spec}, TunnelOptions{})
	if err == nil {
		t.Fatal("remote bind unexpectedly accepted")
	}
	failure, ok := machinecontract.FailureFromError(err)
	if !ok || failure.Error != "tunnel_remote_bind_refused" {
		t.Fatalf("error = %v, failure = %+v", err, failure)
	}
}

func TestParseDynamicForward(t *testing.T) {
	for _, in := range []string{"15037", "127.0.0.1:15037", "[::1]:15037"} {
		if _, err := ParseDynamicForward(in); err != nil {
			t.Errorf("ParseDynamicForward(%q): %v", in, err)
		}
	}
	for _, in := range []string{"", "0", "65536", "host:1:2"} {
		if _, err := ParseDynamicForward(in); err == nil {
			t.Errorf("ParseDynamicForward(%q) unexpectedly succeeded", in)
		}
	}
}
