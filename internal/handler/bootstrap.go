package handler

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
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
	Adapter   string
	IdP       *idp.Service
}

// NewBootstrap initializes all common components needed by Lambda handlers.
// adapter names the deploying binary and is stamped on every log line.
func NewBootstrap(adapter string) (*Bootstrap, error) {
	versionInfo := version.Get()
	ctx := context.Background()

	logger := initializeLogger(adapter)

	logevent.Info(ctx, logger, logevent.AppStart, "starting service",
		slog.String("binName", versionInfo.BinName),
		slog.String("commit", versionInfo.Commit),
		slog.String("date", versionInfo.Date),
	)

	cfg, err := config.NewConfig()
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "startup failed",
			slog.String("component", "config"), slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	consumer := aws.NewAwsConsumer(cfg)
	return newBootstrap(adapter, logger, cfg, consumer, aws.IdPKMS)
}

// bootstrapConsumer is the AWS consumer newBootstrap wires into the provider and handlers.
type bootstrapConsumer interface {
	aws.AwsConsumerInterface
	SetConfigSource(func() *config.Config)
}

// newBootstrap wires every component from the already-loaded base config and AWS consumer.
func newBootstrap(adapter string, logger *slog.Logger, cfg *config.Config, consumer bootstrapConsumer, kms func() idp.KMSAPI) (*Bootstrap, error) {
	ctx := context.Background()

	jwksCache, err := cache.NewCache(cfg)
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "startup failed",
			slog.String("component", "cache"), slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	provider, err := BuildConfigProvider(cfg, consumer)
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "startup failed",
			slog.String("component", "remote_config"), slog.String("error", err.Error()))
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
		logevent.Error(ctx, logger, logevent.AppInitFailure, "startup failed",
			slog.String("component", "claims_extractor"), slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create claims extractor: %w", err)
	}
	if cfg.JWTValidation.Mode != "self" {
		logevent.Warn(ctx, logger, logevent.ConfigJWTValidationDelegated, "jwt validation delegated to upstream",
			slog.String("mode", cfg.JWTValidation.Mode))
	}
	warmJWKSCache(cfg.JWTValidation.Mode, tokenValidator)

	idpSvc := NewIdPService(provider, kms, logger)

	return &Bootstrap{
		Config:    cfg,
		Provider:  provider,
		Consumer:  consumer,
		Validator: tokenValidator,
		Extractor: extractor,
		Cache:     jwksCache,
		S3Logger:  s3log,
		Logger:    logger,
		Adapter:   adapter,
		IdP:       idpSvc,
	}, nil
}

// NewIdPService builds the frozen IdP service from the provider's post-Refresh config and warms it.
func NewIdPService(provider *config.Provider, kms func() idp.KMSAPI, log *slog.Logger) *idp.Service {
	cfg := provider.Get().IdP
	if cfg == nil {
		return nil
	}
	provider.FreezeIdP(cfg)
	c := *cfg
	c.SigningKeys = slices.Clone(c.SigningKeys)
	svc := idp.NewService(c, idp.NewLoader(c, kms, log))
	if c.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := svc.Warm(ctx); err != nil {
			logevent.Error(ctx, log, logevent.IdPKeyLoadFailure, "idp keys not loaded at startup; retrying lazily",
				slog.String("error", err.Error()))
		}
	}
	return svc
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

// BuildConfigProvider wires the config provider shared by every front-end. It stays static
// only with no mappings file, S3 overlay or config_fragments; otherwise it refreshes at startup (failing fast).
func BuildConfigProvider(cfg *config.Config, consumer aws.AwsConsumerInterface) (*config.Provider, error) {
	ctx := context.Background()
	opt := config.WithFragmentFetcher(s3FragmentFetcher(consumer, cfg.S3ConfigBucketOwner))
	hasOverlay := cfg.S3ConfigBucket != "" && cfg.S3ConfigPath != ""

	if !hasOverlay {
		if cfg.MappingsFile == "" && len(cfg.ConfigFragments) == 0 {
			return config.NewStaticProvider(cfg), nil
		}
		provider := config.NewProvider(cfg, cfg.ConfigReloadInterval, "", nil, opt)
		if err := provider.Refresh(ctx); err != nil {
			return nil, err
		}
		if cfg.MappingsFile != "" && cfg.ConfigReloadInterval > 0 {
			logevent.Info(ctx, nil, logevent.ConfigHotReloadEnabled, "configuration hot-reload enabled",
				slog.Int64("intervalMs", cfg.ConfigReloadInterval.Milliseconds()),
				slog.String("mappingsFile", cfg.MappingsFile))
		}
		return provider, nil
	}

	bucket, key, owner := cfg.S3ConfigBucket, cfg.S3ConfigPath, cfg.S3ConfigBucketOwner
	var fetch config.FetchFunc
	if owner != "" {
		fetch = func(ctx context.Context) ([]byte, error) {
			data, _, err := consumer.GetS3ObjectIfChanged(ctx, bucket, key, "", owner)
			return data, err
		}
	} else {
		logevent.Warn(ctx, nil, logevent.ConfigS3OwnerUnpinned, "s3 config read is not pinned to a bucket owner",
			slog.String("bucket", bucket))
		fetch = func(ctx context.Context) ([]byte, error) {
			body, err := consumer.GetS3Object(ctx, bucket, key)
			if err != nil {
				return nil, err
			}
			defer func() {
				if cerr := body.Close(); cerr != nil {
					logevent.Warn(ctx, nil, logevent.AppResourceCloseFailure, "failed to close resource",
						slog.String("resource", "s3_config_object"), slog.String("error", cerr.Error()))
				}
			}()
			return utils.ReadAllCapped(body, utils.MaxConfigBytes, fmt.Sprintf("s3://%s/%s", bucket, key))
		}
	}

	provider := config.NewProvider(cfg, cfg.ConfigReloadInterval, config.FormatFromPath(key), fetch, opt)

	if err := provider.Refresh(ctx); err != nil {
		return nil, err
	}

	if cfg.ConfigReloadInterval > 0 {
		logevent.Info(ctx, nil, logevent.ConfigHotReloadEnabled, "configuration hot-reload enabled",
			slog.Int64("intervalMs", cfg.ConfigReloadInterval.Milliseconds()),
			slog.String("bucket", bucket),
			slog.String("key", key))
	}

	return provider, nil
}

// Cleanup flushes buffered audit records and stops the S3 logger's batch timer.
func (b *Bootstrap) Cleanup() {
	ctx := context.Background()
	if err := b.S3Logger.Close(); err != nil {
		logevent.Error(ctx, b.Logger, logevent.AuditFlushFailure, "failed to flush audit records",
			slog.String("error", err.Error()))
	}
	logevent.Info(ctx, b.Logger, logevent.AppStop, "service stopped")
}

// initializeLogger installs the adapter-stamped JSON logger as slog's default.
func initializeLogger(adapter string) *slog.Logger {
	var programLevel = new(slog.LevelVar)
	programLevel.Set(slog.LevelInfo)

	logger := logevent.Setup(os.Stdout, programLevel, adapter)

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		if level, err := utils.ParseLogLevel(logLevel); err == nil {
			programLevel.Set(level)
		} else {
			logevent.Warn(context.Background(), logger, logevent.ConfigEnvInvalid, "invalid LOG_LEVEL, defaulting to info",
				slog.String("key", "LOG_LEVEL"), slog.String("value", logLevel), slog.String("error", err.Error()))
		}
	}

	return logger
}

// validateAdapterMode panics at startup when the configured jwt_validation.mode
// is incompatible with the deployed adapter binary. Prevents silent per-request
// failures caused by a mismatched extractor (e.g. mode=apigw deployed as apigateway).
func validateAdapterMode(bootstrap *Bootstrap, allowed ...string) {
	mode := bootstrap.Config.JWTValidation.Mode
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
		bootstrap.Adapter, allowed, mode,
	))
}

// NewAwsApiGatewayFromBootstrap creates a new API Gateway handler using bootstrap
func NewAwsApiGatewayFromBootstrap(bootstrap *Bootstrap) *AwsApiGateway {
	validateAdapterMode(bootstrap, "self")
	h := NewAwsApiGateway(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
	h.processor.WithIdP(bootstrap.IdP)
	return h
}

// NewAwsLambdaUrlFromBootstrap creates a new Lambda URL handler using bootstrap
func NewAwsLambdaUrlFromBootstrap(bootstrap *Bootstrap) *AwsLambdaUrl {
	validateAdapterMode(bootstrap, "self")
	h := NewAwsLambdaUrl(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
	h.processor.WithIdP(bootstrap.IdP)
	return h
}

// NewAwsApplicationLoadBalancerFromBootstrap creates a new ALB handler using bootstrap
func NewAwsApplicationLoadBalancerFromBootstrap(bootstrap *Bootstrap) *AwsApplicationLoadBalancer {
	validateAdapterMode(bootstrap, "alb", "self")
	h := NewAwsApplicationLoadBalancer(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
	h.processor.WithIdP(bootstrap.IdP)
	return h
}

// NewAwsApiGatewayV2FromBootstrap creates a new HTTP API v2 handler using bootstrap
func NewAwsApiGatewayV2FromBootstrap(bootstrap *Bootstrap) *AwsApiGatewayV2 {
	validateAdapterMode(bootstrap, "apigw")
	h := NewAwsApiGatewayV2(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor, bootstrap.S3Logger)
	h.processor.WithIdP(bootstrap.IdP)
	return h
}
