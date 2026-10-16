//go:build unix

package idp

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func openKeyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

func checkKeyFileMode(path string, m fs.FileMode) error {
	if !m.IsRegular() || m.Perm()&0o077 != 0 {
		return fmt.Errorf("idp key file %s must be a regular file with no group/world access (mode %s)", path, m)
	}
	return nil
}
