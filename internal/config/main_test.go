package config

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "aow-etc")
	if err != nil {
		panic(err)
	}
	systemConfigDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
