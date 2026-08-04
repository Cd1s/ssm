package update

import "testing"

func TestWindowsVariableLengthFileInformationIncludesStructureStorage(t *testing.T) {
	t.Parallel()

	const (
		structureSize = 24
		fileNameBytes = 198
	)
	want := structureSize + fileNameBytes
	if got := windowsVariableLengthFileInformationSize(
		structureSize,
		fileNameBytes,
	); got != want {
		t.Fatalf(
			"variable-length Windows file-information buffer size = %d, want %d (full structure plus FileName bytes)",
			got,
			want,
		)
	}
}
