package idp

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
)

// NewLoader builds every configured signer; any failure fails the whole load.
func NewLoader(cfg config.IdPConfig, kmsAPI func() KMSAPI, log *slog.Logger) Loader {
	return func(ctx context.Context) ([]LoadedKey, error) {
		out := make([]LoadedKey, 0, len(cfg.SigningKeys))
		for _, k := range cfg.SigningKeys {
			var (
				s   Signer
				err error
			)
			if k.File != "" {
				logevent.Warn(ctx, log, logevent.IdPKeyInsecureSource, "file-backed idp key is for development only",
					slog.String("source", k.Source()), slog.Bool("onLambda", os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != ""))
				s, err = NewPEMSigner(k.File, k.Algorithm)
			} else {
				s, err = NewKMSSigner(ctx, kmsAPI(), k.KMSKeyID, k.Algorithm, cfg.SignTimeout)
			}
			if err != nil {
				return nil, fmt.Errorf("idp key %s: %w", k.Source(), err)
			}
			logevent.Info(ctx, log, logevent.IdPKeyLoaded, "idp key loaded",
				slog.String("kid", s.KeyID()), slog.String("algorithm", s.Algorithm()),
				slog.String("source", k.Source()), slog.String("status", k.Status))
			out = append(out, LoadedKey{Signer: s, Status: k.Status})
		}
		return out, nil
	}
}
