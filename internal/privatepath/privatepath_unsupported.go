//go:build !unix && !windows

package privatepath

import "fmt"

func RestrictDirectory(string) error {
	return fmt.Errorf("private directory enforcement is unsupported on this platform")
}

func VerifyDirectory(string) error {
	return fmt.Errorf("private directory verification is unsupported on this platform")
}

func RestrictFile(string) error {
	return fmt.Errorf("private file enforcement is unsupported on this platform")
}

func VerifyFile(string) error {
	return fmt.Errorf("private file verification is unsupported on this platform")
}
