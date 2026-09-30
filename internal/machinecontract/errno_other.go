//go:build !windows

package machinecontract

func isPlatformConnectionBreak(error) bool { return false }

func platformDialErrnoKind(error) Kind { return "" }
