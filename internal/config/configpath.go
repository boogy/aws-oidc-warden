package config

import (
	"os"
	"path/filepath"
	"strings"
)

// SplitConfigPath maps a config file path to viper's CONFIG_PATH directory and CONFIG_NAME.
func SplitConfigPath(p string) (dir, name string) {
	if fi, err := os.Stat(p); (err == nil && fi.IsDir()) || filepath.Ext(p) == "" {
		return p, ""
	}
	base := filepath.Base(p)
	return filepath.Dir(p), strings.TrimSuffix(base, filepath.Ext(base))
}
