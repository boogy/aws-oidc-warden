package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/boogy/aws-oidc-warden/aws"
	"github.com/boogy/aws-oidc-warden/cache"
	"github.com/boogy/aws-oidc-warden/config"
	"github.com/boogy/aws-oidc-warden/handler"
	s3logger "github.com/boogy/aws-oidc-warden/s3Logger"
	"github.com/boogy/aws-oidc-warden/utils"
	"github.com/boogy/aws-oidc-warden/validator"
)

var (
	binName      string = "AWS OIDC Warden"
	buildVersion string = "snapshot"
	buildCommit  string = "unknown"
	buildDate    string = "unknown"

	logBuffer bytes.Buffer // Buffer to store logs and write them to S3
	jwksCache cache.Cache  // Cache for storing JWKS Keys
	log       *slog.Logger // Global logger with consistent attributes
)

func init() {
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

	// Create a handler that writes to both stdout and our buffer
	logHandler := slog.NewJSONHandler(io.MultiWriter(os.Stdout, &logBuffer), &slog.HandlerOptions{
		Level: programLevel,
	})
	log = slog.New(logHandler)

	slog.SetDefault(log)

	slog.Info(
		fmt.Sprintf("Starting %s", binName),
		slog.String("version", buildVersion),
		slog.String("commit", buildCommit),
		slog.String("date", buildDate),
	)
}

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Error("Failed to load configuration", slog.String("error", err.Error()))
		panic(err)
	}

	jwksCache, err = cache.NewCache(cfg)
	if err != nil {
		slog.Error("Failed to initialize cache", slog.String("error", err.Error()))
		panic(err)
	}

	// Write logs to S3 if enabled
	s3log := s3logger.NewS3Logger(cfg)
	defer func() {
		if err := s3log.Flush(); err != nil {
			slog.Error("Failed to flush logs to S3", slog.String("error", err.Error()))
		}
	}()

	// Set up deferred write of logs to S3 at the end of execution
	defer s3log.WriteLogToS3(logBuffer)

	consumer := aws.NewAwsConsumer(cfg)
	if cfg.S3ConfigBucket != "" && cfg.S3ConfigPath != "" { // Read S3 configuration if it's provided
		if err := consumer.ReadS3Configuration(); err != nil {
			slog.Error("Failed to read configuration", slog.String("error", err.Error()))
			return
		}
	}

	validator := validator.NewTokenValidator(cfg, jwksCache)
	handler := handler.NewHandler(cfg, consumer, validator)

	lambda.Start(handler)
}
