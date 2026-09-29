package ssh

import (
	"errors"
	"strings"
	"testing"

	"ssm/internal/machinecontract"
)

func TestAnnotateLeftoverTempNamesThePath(t *testing.T) {
	base := transferError(machinecontract.TransferTimedOut, 3, errors.New("sftp: connection lost"))
	got := annotateLeftoverTemp(base, "/srv/app.bin.ssm-upload.abc123")
	var transferErr *TransferError
	if !errors.As(got, &transferErr) {
		t.Fatalf("error type = %T", got)
	}
	failure := transferErr.ContractFailure()
	for _, text := range []string{failure.Message, got.Error()} {
		if !strings.Contains(text, "/srv/app.bin.ssm-upload.abc123") || !strings.Contains(text, "may remain") {
			t.Fatalf("leftover path not reported: %q", text)
		}
	}
	if failure.Error != "transfer_timeout" || transferErr.BytesSent != 3 {
		t.Fatalf("failure identity changed: %+v", failure)
	}
	plain := errors.New("not a transfer error")
	if annotateLeftoverTemp(plain, "x") != plain {
		t.Fatal("non-transfer errors must pass through")
	}
}
