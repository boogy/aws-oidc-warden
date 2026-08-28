package handler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	s3logger "github.com/boogy/aws-oidc-warden/internal/s3logger"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/boogy/aws-oidc-warden/internal/version"
)

// jwksWarmPrefetchTimeout bounds the cold-start JWKS warm prefetch. A slow or
// unreachable issuer must not eat into the Lambda INIT budget — on timeout the
// prefetch is abandoned and the first request pays the fetch as it did before.
const jwksWarmPrefetchTimeout = 3 * time.Second

// jwksWarmer is the subset of the token validator warmJWKSCache needs, so the
// cold-start gating can be tested without standing up a full validator.
type jwksWarmer interface {
	WarmPrefetch(ctx context.Context)
}

// warmJWKSCache prefetches every configured issuer's JWKS during cold start
// (self mode only; delegated modes never consult JWKS). Best-effort: errors
// are logged and swallowed, bounded by jwksWarmPrefetchTimeout. Reports
// whether a prefetch was attempted.
func warmJWKSCache(mode string, v jwksWarmer) bool {
	if mode != "self" || v == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), jwksWarmPrefetchTimeout)
	defer cancel()
	v.WarmPrefetch(ctx)
	return true
}

// Bootstrap contains all the initialized components needed by handlers
type Bootstrap struct {
	Config    *config.Config
	Provider  *config.Provider
	Consumer  aws.AwsConsumerInterface
	Validator validator.TokenValidatorInterface  // kept for external use / tests
	Extractor validator.ClaimsExtractorInterface // used by processor
	Cache     cache.Cache
	S3Logger  *s3logger.S3Logger
	Logger    *slog.Logger
	LogBuffer *bytes.Buffer
}

// NewBootstrap initializes all common components needed by Lambda handlers
func NewBootstrap() (*Bootstrap, error) {
	versionInfo := version.Get()

	logBuffer, logger, err := initializeLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	logger.Info(
		fmt.Sprintf("Starting %s", versionInfo.BinName),
		slog.String("version", versionInfo.Version),
		slog.String("commit", versionInfo.Commit),
		slog.String("date", versionInfo.Date),
	)

	cfg, err := config.NewConfig()
	if err != nil {
		logger.Error("Failed to load configuration", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	jwksCache, err := cache.NewCache(cfg)
	if err != nil {
		logger.Error("Failed to initialize cache", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	consumer := aws.NewAwsConsumer(cfg)

	provider, err := buildConfigProvider(cfg, consumer)
	if err != nil {
		logger.Error("Failed to load remote configuration", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to load remote configuration: %w", err)
	}

	// Wired so hot-reloaded changes (allowed accounts, tag-auth, spoke role)
	// take effect here too, not just on the processor's config reads.
	consumer.SetConfigSource(provider.Get)

	s3log := s3logger.NewS3Logger(provider.Get())
	s3log.SetConfigSource(provider.Get) // rotated log_bucket takes effect on hot reload

	tokenValidator := validator.NewTokenValidator(provider, jwksCache)

	// jwt_validation.mode itself is fixed at cold start (requires redeploy to
	// change); delegated extractors still read live config per Extract() call.
	extractor, err := newClaimsExtractor(provider, tokenValidator)
	if err != nil {
		logger.Error("Failed to create claims extractor", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create claims extractor: %w", err)
	}
	if cfg.JWTValidation.Mode != "self" {
		logger.Warn("JWT validation delegated to upstream",
			slog.String("mode", cfg.JWTValidation.Mode))
	}
	warmJWKSCache(cfg.JWTValidation.Mode, tokenValidator)

	return &Bootstrap{
		Config:    cfg,
		Provider:  provider,
		Consumer:  consumer,
		Validator: tokenValidator,
		Extractor: extractor,
		Cache:     jwksCache,
		S3Logger:  s3log,
		Logger:    logger,
		LogBuffer: logBuffer,
	}, nil
}

// newClaimsExtractor creates the ClaimsExtractorInterface for the configured
// mode. Delegated modes ("apigw"/"alb") trust an upstream that already
// verified the signature and re-validate against the matched issuer's spec
// for defense-in-depth. "apigw" supports multiple issuers (one JWT
// Authorizer per route); "alb" trusts a single OIDC IdP, so multi-issuer
// config is rejected fail-fast there.
func newClaimsExtractor(provider *config.Provider, v validator.TokenValidatorInterface) (validator.ClaimsExtractorInterface, error) {
	cfg := provider.Get()
	mode := cfg.JWTValidation.Mode
	switch mode {
	case "self", "":
		return validator.NewSelfExtractor(v), nil
	case "apigw":
		return validator.NewAPIGWExtractor(provider), nil
	case "alb":
		if _, err := singleDelegatedIssuer(cfg, mode); err != nil {
			return nil, err
		}
		return validator.NewALBExtractor(provider), nil
	default:
		return nil, fmt.Errorf("unknown jwt_validation.mode: %q", mode)
	}
}

// singleDelegatedIssuer returns the sole configured issuer for alb mode
// (fails if more than one is configured; apigw resolves per request instead).
func singleDelegatedIssuer(cfg *config.Config, mode string) (*config.IssuerConfig, error) {
	if len(cfg.Issuers) != 1 {
		return nil, fmt.Errorf("jwt_validation.mode %q supports exactly one configured issuer, got %d", mode, len(cfg.Issuers))
	}
	return &cfg.Issuers[0], nil
}

// buildConfigProvider wires the config provider: with an S3 config source it
// fetches+overlays it (failing fast) and enables hot-reload when
// ConfigReloadInterval > 0; without one, a static provider serves the local
// config unless config_fragments are set, which need a reloadable provider
// (nil fetch) to get merged at all.
func buildConfigProvider(cfg *config.Config, consumer aws.AwsConsumerInterface) (*config.Provider, error) {
	if cfg.S3ConfigBucket == "" || cfg.S3ConfigPath == "" {
		if len(cfg.ConfigFragments) == 0 {
			return config.NewStaticProvider(cfg), nil
		}
		provider := config.NewProvider(cfg, cfg.ConfigReloadInterval, "", nil)
		if err := provider.Refresh(context.Background()); err != nil {
			return nil, err
		}
		return provider, nil
	}

	bucket, key := cfg.S3ConfigBucket, cfg.S3ConfigPath
	fetch := func(ctx context.Context) ([]byte, error) {
		body, err := consumer.GetS3Object(bucket, key)
		if err != nil {
			return nil, err
		}
		defer func() {
			if cerr := body.Close(); cerr != nil {
				slog.Error("Failed to close S3 configuration object", slog.String("error", cerr.Error()))
			}
		}()
		return io.ReadAll(io.LimitReader(body, maxRemoteConfigSize))
	}

	provider := config.NewProvider(cfg, cfg.ConfigReloadInterval, config.FormatFromPath(key), fetch)

	if err := provider.Refresh(context.Background()); err != nil {
		return nil, err
	}

	if cfg.ConfigReloadInterval > 0 {
		slog.Info("Configuration hot-reload enabled",
			slog.Duration("interval", cfg.ConfigReloadInterval),
			slog.String("bucket", bucket),
			slog.String("key", key))
	}

	return provider, nil
}

// maxRemoteConfigSize bounds the bytes read from the S3 config object.
const maxRemoteConfigSize = 1024 * 1024 // 1MB

// Cleanup flushes the S3 logger and writes buffered logs to S3.
func (b *Bootstrap) Cleanup() {
	if err := b.S3Logger.Flush(); err != nil {
		b.Logger.Error("Failed to flush logs to S3", slog.String("error", err.Error()))
	}

	if err := b.S3Logger.WriteLogToS3(*b.LogBuffer); err != nil {
		b.Logger.Error("Failed to write logs to S3", slog.String("error", err.Error()))
	}
}

// initializeLogger sets up the global logger with proper configuration
func initializeLogger() (*bytes.Buffer, *slog.Logger, error) {
	var programLevel = new(slog.LevelVar)
	programLevel.Set(slog.LevelInfo)

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		if level, err := utils.ParseLogLevel(logLevel); err == nil {
			programLevel.Set(level)
		} else {
			slog.Warn("invalid LOG_LEVEL, defaulting to Info", "level", logLevel, "error", err)
		}
	}

	logBuffer := &bytes.Buffer{}

	logHandler := slog.NewJSONHandler(io.MultiWriter(os.Stdout, logBuffer), &slog.HandlerOptions{
		Level: programLevel,
	})

	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	return logBuffer, logger, nil
}

// validateAdapterMode panics at startup when the configured jwt_validation.mode
// is incompatible with the deployed adapter binary. Prevents silent per-request
// failures caused by a mismatched extractor (e.g. mode=apigw deployed as apigateway).
func validateAdapterMode(adapterName, mode string, allowed ...string) {
	if mode == "" {
		mode = "self"
	}
	for _, m := range allowed {
		if mode == m {
			return
		}
	}
	panic(fmt.Sprintf(
		"adapter %q requires jwt_validation.mode in %v, got %q; deploy the correct binary or update the config",
		adapterName, allowed, mode,
	))
}

// NewAwsApiGatewayFromBootstrap creates a new API Gateway handler using bootstrap
func NewAwsApiGatewayFromBootstrap(bootstrap *Bootstrap) *AwsApiGateway {
	validateAdapterMode("apigateway", bootstrap.Config.JWTValidation.Mode, "self")
	return NewAwsApiGateway(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
}

// NewAwsLambdaUrlFromBootstrap creates a new Lambda URL handler using bootstrap
func NewAwsLambdaUrlFromBootstrap(bootstrap *Bootstrap) *AwsLambdaUrl {
	validateAdapterMode("lambdaurl", bootstrap.Config.JWTValidation.Mode, "self")
	return NewAwsLambdaUrl(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
}

// NewAwsApplicationLoadBalancerFromBootstrap creates a new ALB handler using bootstrap
func NewAwsApplicationLoadBalancerFromBootstrap(bootstrap *Bootstrap) *AwsApplicationLoadBalancer {
	validateAdapterMode("alb", bootstrap.Config.JWTValidation.Mode, "alb", "self")
	return NewAwsApplicationLoadBalancer(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
}

// NewAwsApiGatewayV2FromBootstrap creates a new HTTP API v2 handler using bootstrap
func NewAwsApiGatewayV2FromBootstrap(bootstrap *Bootstrap) *AwsApiGatewayV2 {
	validateAdapterMode("apigatewayv2", bootstrap.Config.JWTValidation.Mode, "apigw")
	return NewAwsApiGatewayV2(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
}
