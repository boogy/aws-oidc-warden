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
