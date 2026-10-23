package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestParseCliFlagsSetsConfigEnv(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	flag.CommandLine = flag.NewFlagSet("x", flag.ContinueOnError)
	cfg := filepath.Join(t.TempDir(), "example-config.yaml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"x", "-config=" + cfg}
	t.Setenv("CONFIG_FILE", "")

	if _, err := parseCliFlags(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("CONFIG_FILE"); got != cfg {
		t.Errorf("CONFIG_FILE = %q, want %q", got, cfg)
	}
}

func TestParseCliFlagsMissingConfig(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	flag.CommandLine = flag.NewFlagSet("x", flag.ContinueOnError)
	os.Args = []string{"x", "-config=" + filepath.Join(t.TempDir(), "typo.yaml")}
	t.Setenv("CONFIG_FILE", "")

	if _, err := parseCliFlags(); err == nil {
		t.Fatal("want error for a missing -config file")
	}
}

func TestParseCliFlagsMappings(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	flag.CommandLine = flag.NewFlagSet("x", flag.ContinueOnError)
	os.Args = []string{"x", "-mappings", "s3://b/k"}
	t.Setenv("AOW_MAPPINGS_FILE", "")

	settings, err := parseCliFlags()
	if err != nil {
		t.Fatal(err)
	}
	if settings.MappingsPath != "s3://b/k" {
		t.Errorf("MappingsPath = %q, want %q", settings.MappingsPath, "s3://b/k")
	}
	if got := os.Getenv("AOW_MAPPINGS_FILE"); got != "s3://b/k" {
		t.Errorf("AOW_MAPPINGS_FILE = %q, want %q", got, "s3://b/k")
	}
}
