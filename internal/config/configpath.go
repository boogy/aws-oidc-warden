package config

import (
	"os"
)

// UseConfigFile points LoadConfig at p: a directory via CONFIG_PATH, a file via CONFIG_FILE. An empty p is a no-op.
func UseConfigFile(p string) error {
	if p == "" {
		return nil
	}
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return os.Setenv("CONFIG_PATH", p)
	}
	return os.Setenv("CONFIG_FILE", p)
}
