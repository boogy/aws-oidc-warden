package handler

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/boogy/aws-oidc-warden/pkg/aws"
	"github.com/boogy/aws-oidc-warden/pkg/cache"
	"github.com/boogy/aws-oidc-warden/pkg/config"
	s3logger "github.com/boogy/aws-oidc-warden/pkg/s3logger"
	"github.com/boogy/aws-oidc-warden/pkg/utils"
	"github.com/boogy/aws-oidc-warden/pkg/validator"
	"github.com/boogy/aws-oidc-warden/pkg/version"
)

// Bootstrap contains all the initialized components needed by handlers
type Bootstrap struct {
	Config    *config.Config
	Consumer  aws.AwsConsumerInterface
	Validator validator.TokenValidatorInterface
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

	// Initialize S3 logger
	s3log := s3logger.NewS3Logger(cfg)

	// Initialize AWS consumer
	consumer := aws.NewAwsConsumer(cfg)

	// Read S3 configuration if provided
	if cfg.S3ConfigBucket != "" && cfg.S3ConfigPath != "" {
		if err := consumer.ReadS3Configuration(); err != nil {
			logger.Error("Failed to read S3 configuration", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to read S3 configuration: %w", err)
		}
	}

	// Initialize token validator
	tokenValidator := validator.NewTokenValidator(cfg, jwksCache)

	return &Bootstrap{
		Config:    cfg,
		Consumer:  consumer,
		Validator: tokenValidator,
		Cache:     jwksCache,
		S3Logger:  s3log,
		Logger:    logger,
		LogBuffer: logBuffer,
	}, nil
}

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
	return NewAwsApiGateway(bootstrap.Config, bootstrap.Consumer, bootstrap.Validator)
}

// NewAwsLambdaUrlFromBootstrap creates a new Lambda URL handler using bootstrap
func NewAwsLambdaUrlFromBootstrap(bootstrap *Bootstrap) *AwsLambdaUrl {
	return NewAwsLambdaUrl(bootstrap.Config, bootstrap.Consumer, bootstrap.Validator)
}

// NewAwsApplicationLoadBalancerFromBootstrap creates a new ALB handler using bootstrap
func NewAwsApplicationLoadBalancerFromBootstrap(bootstrap *Bootstrap) *AwsApplicationLoadBalancer {
	return NewAwsApplicationLoadBalancer(bootstrap.Config, bootstrap.Consumer, bootstrap.Validator)
}
