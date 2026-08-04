//go:build linux

package update

import (
	"fmt"
	"os"
)

func unixReplacementDescriptorPath(file *os.File) string {
	return fmt.Sprintf("/proc/self/fd/%d", file.Fd())
}
