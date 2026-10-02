package main

import (
	"flag"
	"os"
	"testing"
)

func TestParseCliFlagsSetsConfigEnv(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	flag.CommandLine = flag.NewFlagSet("x", flag.ContinueOnError)
	os.Args = []string{"x", "-config=./example-config.yaml"}
	t.Setenv("CONFIG_PATH", "")
	t.Setenv("CONFIG_NAME", "")

	if _, err := parseCliFlags(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("CONFIG_PATH"); got != "." {
		t.Errorf("CONFIG_PATH = %q, want %q", got, ".")
	}
	if got := os.Getenv("CONFIG_NAME"); got != "example-config" {
		t.Errorf("CONFIG_NAME = %q, want %q", got, "example-config")
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
