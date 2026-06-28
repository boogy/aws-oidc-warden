package handler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	s3logger "github.com/boogy/aws-oidc-warden/internal/s3logger"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/boogy/aws-oidc-warden/internal/version"
)

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
	// Get version information
	versionInfo := version.Get()

	// Initialize logger first
	logBuffer, logger, err := initializeLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Log startup information
	logger.Info(
		fmt.Sprintf("Starting %s", versionInfo.BinName),
		slog.String("version", versionInfo.Version),
		slog.String("commit", versionInfo.Commit),
		slog.String("date", versionInfo.Date),
	)

	// Load configuration
	cfg, err := config.NewConfig()
	if err != nil {
		logger.Error("Failed to load configuration", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize cache
	jwksCache, err := cache.NewCache(cfg)
	if err != nil {
		logger.Error("Failed to initialize cache", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Initialize AWS consumer (needed by buildConfigProvider)
	consumer := aws.NewAwsConsumer(cfg)

	// Build the configuration provider. When an S3 config source is set, the
	// provider fetches+overlays it (optionally hot-reloading on an interval);
	// otherwise it statically serves the local config.
	provider, err := buildConfigProvider(cfg, consumer)
	if err != nil {
		logger.Error("Failed to load remote configuration", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to load remote configuration: %w", err)
	}

	// Wire the live config into the consumer so hot-reloaded changes (allowed
	// accounts, tag-auth enable/disable, spoke role/external ID) take effect on
	// its enforcement and credential-routing paths, not just the processor's.
	consumer.SetConfigSource(provider.Get)

	// Initialize S3Logger from the resolved config so log_bucket/log_prefix
	// overrides in the S3 config are honored.
	s3log := s3logger.NewS3Logger(provider.Get())

	// Initialize token validator from the provider so hot-reloaded issuer/audience
	// changes take effect immediately without a Lambda restart.
	tokenValidator := validator.NewTokenValidatorFromProvider(provider, jwksCache)

	// The extractor is fixed at cold start. Changing jwt_validation.mode at runtime
	// requires a Lambda redeployment. Hot-reload via Provider only affects fields
	// read per-request (repo_role_mappings, audiences, etc.).
	extractor, err := newClaimsExtractor(cfg, tokenValidator)
	if err != nil {
		logger.Error("Failed to create claims extractor", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create claims extractor: %w", err)
	}
	if cfg.JWTValidation.Mode != "self" {
		logger.Warn("JWT validation delegated to upstream",
			slog.String("mode", cfg.JWTValidation.Mode))
	}

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

// newClaimsExtractor creates the appropriate ClaimsExtractorInterface based on the configured mode.
func newClaimsExtractor(cfg *config.Config, v validator.TokenValidatorInterface) (validator.ClaimsExtractorInterface, error) {
	mode := cfg.JWTValidation.Mode
	// Resolve audiences: prefer the slice, fall back to singular field.
	audiences := cfg.Audiences
	if len(audiences) == 0 && cfg.Audience != "" {
		audiences = []string{cfg.Audience}
	}
	switch mode {
	case "self", "":
		return validator.NewSelfExtractor(v), nil
	case "apigw":
		// Pass issuer/audiences for defense-in-depth re-validation of pre-validated claims.
		return validator.NewAPIGWExtractor(cfg.Issuer, audiences), nil
	case "alb":
		// Pass issuer/audiences for post-signature claim validation.
		return validator.NewALBExtractor(cfg.JWTValidation.ALBExpectedSigner, cfg.Issuer, audiences), nil
	default:
		return nil, fmt.Errorf("unknown jwt_validation.mode: %q", mode)
	}
}

// buildConfigProvider wires the config provider. With an S3 config source it
// performs an initial fetch+overlay (failing fast on error) and enables
// per-request lazy hot-reload when ConfigReloadInterval > 0. Without a source it
// returns a static provider serving the local config.
func buildConfigProvider(cfg *config.Config, consumer aws.AwsConsumerInterface) (*config.Provider, error) {
	if cfg.S3ConfigBucket == "" || cfg.S3ConfigPath == "" {
		return config.NewStaticProvider(cfg), nil
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

	// Initial load: fail fast if the S3 config can't be fetched/parsed.
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

// Cleanup handles cleanup operations for the bootstrap components
func (b *Bootstrap) Cleanup() {
	// Flush S3 logger
	if err := b.S3Logger.Flush(); err != nil {
		b.Logger.Error("Failed to flush logs to S3", slog.String("error", err.Error()))
	}

	// Write logs to S3
	if err := b.S3Logger.WriteLogToS3(*b.LogBuffer); err != nil {
		b.Logger.Error("Failed to write logs to S3", slog.String("error", err.Error()))
	}
}

// initializeLogger sets up the global logger with proper configuration
func initializeLogger() (*bytes.Buffer, *slog.Logger, error) {
	var programLevel = new(slog.LevelVar) // Default to Info
	programLevel.Set(slog.LevelInfo)

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		if level, err := utils.ParseLogLevel(logLevel); err == nil {
			programLevel.Set(level)
		} else {
			slog.Info("Invalid LOG_LEVEL %q, defaulting to Info: %v", logLevel, err)
		}
	}

	// Create log buffer for S3 logging
	logBuffer := &bytes.Buffer{}

	// Create a handler that writes to both stdout and our buffer
	logHandler := slog.NewJSONHandler(io.MultiWriter(os.Stdout, logBuffer), &slog.HandlerOptions{
		Level: programLevel,
	})

	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	return logBuffer, logger, nil
}

// NewAwsApiGatewayFromBootstrap creates a new API Gateway handler using bootstrap
func NewAwsApiGatewayFromBootstrap(bootstrap *Bootstrap) *AwsApiGateway {
	return NewAwsApiGateway(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor)
}

// NewAwsLambdaUrlFromBootstrap creates a new Lambda URL handler using bootstrap
func NewAwsLambdaUrlFromBootstrap(bootstrap *Bootstrap) *AwsLambdaUrl {
	return NewAwsLambdaUrl(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor)
}

// NewAwsApplicationLoadBalancerFromBootstrap creates a new ALB handler using bootstrap
func NewAwsApplicationLoadBalancerFromBootstrap(bootstrap *Bootstrap) *AwsApplicationLoadBalancer {
	return NewAwsApplicationLoadBalancer(bootstrap.Provider, bootstrap.Consumer, bootstrap.Extractor)
}
