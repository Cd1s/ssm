//go:build darwin || freebsd || openbsd

package update

import (
	"fmt"
	"os"
)

func unixReplacementDescriptorPath(file *os.File) string {
	return fmt.Sprintf("/dev/fd/%d", file.Fd())
}
