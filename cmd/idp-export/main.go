// Command idp-export writes the static IdP discovery and JWKS documents.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
)

func main() {
	ctx := context.Background()
	logger := logevent.Setup(os.Stderr, slog.LevelInfo, "idp-export")

	configPath := flag.String("config", "", "Path to config file or directory")
	outDir := flag.String("out", "", "Output directory (required)")
	flag.Parse()

	fail := func(component string, err error) {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "idp export failed",
			slog.String("component", component), slog.String("error", err.Error()))
		os.Exit(1)
	}

	if *outDir == "" {
		fail("flags", errors.New("-out is required"))
	}
	if err := config.UseConfigFile(*configPath); err != nil {
		fail("flags", err)
	}

	c := &config.Config{}
	if err := c.LoadConfig(); err != nil {
		fail("config", err)
	}

	if err := run(ctx, c, func() idp.KMSAPI { return aws.NewAwsServiceWrapper().KMS() }, *outDir); err != nil {
		fail("export", err)
	}
}

// run writes the discovery and JWKS documents under outDir at the configured IdP paths.
func run(ctx context.Context, cfg *config.Config, kmsAPI func() idp.KMSAPI, outDir string) error {
	if cfg.IdP == nil || !cfg.IdP.Enabled {
		return errors.New("idp is not enabled in config")
	}
	keys, err := idp.NewLoader(*cfg.IdP, kmsAPI, slog.Default())(ctx)
	if err != nil {
		return err
	}
	ks, err := idp.NewKeySet(*cfg.IdP, keys)
	if err != nil {
		return err
	}
	docs := []struct {
		path string
		body []byte
	}{
		{cfg.IdP.Paths.Discovery, ks.Discovery()},
		{cfg.IdP.Paths.JWKS, ks.JWKS()},
	}
	for _, d := range docs {
		p := filepath.Join(outDir, filepath.FromSlash(d.path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, d.body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
	}
	return nil
}
