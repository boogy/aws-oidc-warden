package config

import (
	"os"
	"path/filepath"
	"strings"
)

// UseConfigFile points LoadConfig at p via CONFIG_PATH and CONFIG_NAME; an empty p is a no-op.
func UseConfigFile(p string) error {
	if p == "" {
		return nil
	}
	dir, name := SplitConfigPath(p)
	if err := os.Setenv("CONFIG_PATH", dir); err != nil {
		return err
	}
	if name != "" {
		return os.Setenv("CONFIG_NAME", name)
	}
	return nil
}

// SplitConfigPath maps a config file path to viper's CONFIG_PATH directory and CONFIG_NAME.
func SplitConfigPath(p string) (dir, name string) {
	if fi, err := os.Stat(p); (err == nil && fi.IsDir()) || filepath.Ext(p) == "" {
		return p, ""
	}
	base := filepath.Base(p)
	return filepath.Dir(p), strings.TrimSuffix(base, filepath.Ext(base))
}
