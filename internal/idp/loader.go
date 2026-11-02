package idp

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// NewLoader builds every configured signer concurrently; any failure fails the whole load.
func NewLoader(cfg config.IdPConfig, kmsAPI func() KMSAPI, log *slog.Logger) Loader {
	return func(ctx context.Context) ([]LoadedKey, error) {
		out := make([]LoadedKey, len(cfg.SigningKeys))
		g, gctx := errgroup.WithContext(ctx)
		for i, k := range cfg.SigningKeys {
			g.Go(func() error {
				var (
					s   Signer
					err error
				)
				if k.File != "" {
					logevent.Warn(gctx, log, logevent.IdPKeyInsecureSource, "file-backed idp key is for development only",
						slog.String("source", k.Source()), slog.Bool("onLambda", utils.OnLambda()))
					s, err = NewPEMSigner(k.File, k.Algorithm)
				} else {
					s, err = NewKMSSigner(gctx, kmsAPI(), k.KMSKeyID, k.Algorithm, cfg.KMSAllowedRegions, cfg.SignTimeout)
				}
				if err != nil {
					return fmt.Errorf("idp key %s: %w", k.Source(), err)
				}
				logevent.Info(gctx, log, logevent.IdPKeyLoaded, "idp key loaded",
					slog.String("kid", s.KeyID()), slog.String("algorithm", s.Algorithm()),
					slog.String("source", k.Source()), slog.String("status", k.Status))
				out[i] = LoadedKey{Signer: s, Status: k.Status}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, err
		}
		return out, nil
	}
}
