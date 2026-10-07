package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/spf13/viper"
)

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
		for _, ext := range viper.SupportedExts {
			f := filepath.Join(p, name+"."+ext)
			if st, err := os.Stat(f); err == nil && !st.IsDir() {
				return os.Setenv("CONFIG_FILE", f)
			}
		}
		return fmt.Errorf("no %s.<ext> config file in directory %s", name, p)
	}
	return os.Setenv("CONFIG_FILE", p)
}
