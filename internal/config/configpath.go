package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/spf13/viper"
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
		f, err := findConfigFile([]string{p}, name)
		if err != nil {
			return err
		}
		if f == "" {
			return fmt.Errorf("no %s.{%s} config file in directory %s", name, strings.Join(configExts, ","), p)
		}
		return os.Setenv("CONFIG_FILE", f)
	}
	return os.Setenv("CONFIG_FILE", p)
}

// findConfigFile returns <name>.<ext> from the first dir holding one, or "" if none does; a second candidate or an unsupported extension is an error.
func findConfigFile(dirs []string, name string) (string, error) {
	for _, dir := range dirs {
		var found []string
		for _, ext := range viper.SupportedExts {
			f := filepath.Join(dir, name+"."+ext)
			if st, err := os.Stat(f); err == nil && !st.IsDir() {
				found = append(found, f)
			}
		}
		switch {
		case len(found) > 1:
			return "", fmt.Errorf("ambiguous config in directory %s: %s", dir, strings.Join(found, ", "))
		case len(found) == 1:
			if ext := strings.TrimPrefix(filepath.Ext(found[0]), "."); !slices.Contains(configExts, ext) {
				return "", fmt.Errorf("config file %s: unsupported extension %q (want %s)", found[0], ext, strings.Join(configExts, ", "))
			}
			return found[0], nil
		}
	}
	return "", nil
}
