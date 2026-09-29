//go:build !windows

package machinecontract

func isPlatformConnectionBreak(error) bool { return false }
