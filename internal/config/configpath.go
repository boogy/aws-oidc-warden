package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

var configExts = []string{"yaml", "yml", "json", "toml"}

// UseConfigFile points LoadConfig at the exact config file p, or at <CONFIG_NAME>.<ext> inside directory p. An empty p is a no-op.
func UseConfigFile(p string) error {
	if p == "" {
		return nil
	}
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		name := utils.GetEnv("CONFIG_NAME", "config")
		var found []string
		for _, ext := range configExts {
			f := filepath.Join(p, name+"."+ext)
			if st, err := os.Stat(f); err == nil && !st.IsDir() {
				found = append(found, f)
			}
		}
		switch len(found) {
		case 0:
			return fmt.Errorf("no %s.{%s} config file in directory %s", name, strings.Join(configExts, ","), p)
		case 1:
			return os.Setenv("CONFIG_FILE", found[0])
		default:
			return fmt.Errorf("ambiguous config in directory %s: %s", p, strings.Join(found, ", "))
		}
	}
	return os.Setenv("CONFIG_FILE", p)
}
