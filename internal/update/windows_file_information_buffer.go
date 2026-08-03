package update

// windowsVariableLengthFileInformationSize retains the complete aligned fixed
// structure before adding the variable FileName bytes. Using the FileName
// offset instead discards required trailing structure storage on Windows.
func windowsVariableLengthFileInformationSize(
	structureSize,
	fileNameByteLength int,
) int {
	return structureSize + fileNameByteLength
}
