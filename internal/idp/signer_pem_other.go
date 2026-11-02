//go:build !unix

package idp

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

func openKeyFile(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil, errors.New("symlinks are not allowed")
	}
	return os.Open(path)
}

func checkKeyFileMode(path string, m fs.FileMode) error {
	if !m.IsRegular() {
		return fmt.Errorf("idp key file %s must be a regular file", path)
	}
	return nil
}
