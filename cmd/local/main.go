package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/boogy/aws-oidc-warden/internal/version"
	"github.com/google/uuid"
)

// Settings for the local server
type ServerSettings struct {
	Port            int
	ConfigPath      string
	LogLevel        string
	SimulateLatency time.Duration
}

func main() {
	ctx := context.Background()
	settings, cliErr := parseCliFlags()
	logger := setupLogging(settings.LogLevel)
	if cliErr != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "failed to set CONFIG_PATH environment variable",
			slog.String("component", "config"), slog.String("error", cliErr.Error()))
	}

	// Log version information
	versionInfo := version.Get()
	logevent.Info(ctx, logger, logevent.AppStart, "starting AWS OIDC Warden local server",
		slog.String("version", versionInfo.Version),
		slog.String("commit", versionInfo.Commit),
		slog.String("date", versionInfo.Date),
	)

	// Load configuration
	cfg, err := config.NewConfig()
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "failed to load config",
			slog.String("component", "config"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize the cache
	jwksCache, err := cache.NewCache(cfg)
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "failed to initialize cache",
			slog.String("component", "cache"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Config provider shared by the validator and the handler so both read the
	// same snapshot. Without config_fragments it is static (no reload). With
	// fragments, a static provider would silently ignore them (fragments only
	// merge on a provider Refresh), so build a reloadable provider with no
	// primary fetch: fragments merge once here, and — like the Lambda
	// bootstrap — are re-resolved per config_reload_interval when it's > 0.
	var provider *config.Provider
	if len(cfg.ConfigFragments) > 0 {
		provider = config.NewProvider(cfg, cfg.ConfigReloadInterval, "", nil)
		if err := provider.Refresh(ctx); err != nil {
			logevent.Error(ctx, logger, logevent.AppInitFailure, "failed to merge config fragments",
				slog.String("component", "remote_config"), slog.String("error", err.Error()))
			os.Exit(1)
		}
	} else {
		provider = config.NewStaticProvider(cfg)
	}

	// Initialize the token validator and wrap it in a SelfExtractor so the local
	// server always validates JWT signatures itself (no delegated mode).
	tokenValidator := validator.NewTokenValidator(provider, jwksCache)
	extractor := validator.NewSelfExtractor(tokenValidator)

	// Initialize the AWS client
	awsClient := aws.NewAwsConsumer(cfg)

	// Create the handler function. No audit sink for the local dev server.
	handlerFunc := handler.NewAwsApiGateway(provider, awsClient, extractor, nil).Handler

	// Set up HTTP server
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		sourceIP := remoteIP(r.RemoteAddr)
		reqCtx := logevent.WithRequest(r.Context(), logevent.Request{ID: requestID, SourceIP: sourceIP})

		// Simulate network latency if configured
		if settings.SimulateLatency > 0 {
			time.Sleep(settings.SimulateLatency)
		}

		// Only accept POST requests
		if r.Method != http.MethodPost {
			logevent.Warn(reqCtx, logger, logevent.RequestRejected, "request rejected",
				slog.String("reason", "method not allowed"), slog.String("method", r.Method))
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			logevent.Warn(reqCtx, logger, logevent.RequestRejected, "request rejected",
				slog.String("reason", "body read failed"), slog.String("error", err.Error()))
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		defer func() {
			if err := r.Body.Close(); err != nil {
				logevent.Warn(reqCtx, logger, logevent.HTTPWriteFailure, "error closing request body",
					slog.String("error", err.Error()))
			}
		}()

		// Create an API Gateway proxy request event
		apiGatewayEvent := events.APIGatewayProxyRequest{
			Body:                  string(body),
			Path:                  "/verify",
			HTTPMethod:            r.Method,
			Headers:               make(map[string]string),
			QueryStringParameters: make(map[string]string),
			PathParameters:        make(map[string]string),
			RequestContext: events.APIGatewayProxyRequestContext{
				RequestID: requestID,
				Identity:  events.APIGatewayRequestIdentity{SourceIP: sourceIP},
			},
		}

		// Copy headers
		for k, v := range r.Header {
			if len(v) > 0 {
				apiGatewayEvent.Headers[k] = v[0]
			}
		}

		// Copy query parameters
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				apiGatewayEvent.QueryStringParameters[k] = v[0]
			}
		}

		// Call the Lambda handler function
		response, err := handlerFunc(reqCtx, apiGatewayEvent)
		if err != nil {
			logevent.Error(reqCtx, logger, logevent.HTTPResponseFailure, "handler error",
				slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set response headers
		for k, v := range response.Headers {
			w.Header().Set(k, v)
		}

		// Set status code
		w.WriteHeader(response.StatusCode)

		// Write response body
		if _, err := w.Write([]byte(response.Body)); err != nil {
			logevent.Warn(reqCtx, logger, logevent.HTTPWriteFailure, "error writing response",
				slog.String("error", err.Error()))
		}
	})

	// Add a health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		reqCtx := logevent.WithRequest(r.Context(), logevent.Request{ID: uuid.New().String(), SourceIP: remoteIP(r.RemoteAddr)})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			logevent.Warn(reqCtx, logger, logevent.HTTPWriteFailure, "error encoding health check response",
				slog.String("error", err.Error()))
		}
	})

	// Start the server
	addr := fmt.Sprintf(":%d", settings.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: nil, // Use the default mux
	}

	// Handle graceful shutdown
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logevent.Error(ctx, logger, logevent.HTTPServerFailure, "server shutdown error",
				slog.String("error", err.Error()))
		}
	}()

	logevent.Info(ctx, logger, logevent.HTTPServerStart, "starting local development server",
		slog.Int("port", settings.Port),
		slog.String("verifyEndpoint", fmt.Sprintf("http://localhost:%d/verify", settings.Port)),
		slog.String("healthEndpoint", fmt.Sprintf("http://localhost:%d/health", settings.Port)))

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logevent.Error(ctx, logger, logevent.HTTPServerFailure, "server error",
			slog.String("error", err.Error()))
		os.Exit(1)
	}

	logevent.Info(ctx, logger, logevent.AppStop, "server stopped")
}

// remoteIP strips the port from RemoteAddr, returning it unchanged if it has none.
func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// parseCliFlags runs before logging is set up, so it returns errors instead of logging them.
func parseCliFlags() (ServerSettings, error) {
	settings := ServerSettings{}

	flag.IntVar(&settings.Port, "port", 8080, "Port to listen on")
	flag.StringVar(&settings.ConfigPath, "config", "", "Path to config file")
	flag.StringVar(&settings.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.DurationVar(&settings.SimulateLatency, "latency", 0, "Simulate network latency (e.g., 100ms)")

	flag.Parse()

	if settings.ConfigPath != "" {
		if err := os.Setenv("CONFIG_PATH", settings.ConfigPath); err != nil {
			return settings, err
		}
	}

	return settings, nil
}

// setupLogging installs the base JSON logger for the local adapter.
func setupLogging(level string) *slog.Logger {
	logLevel, err := utils.ParseLogLevel(level)
	if err != nil {
		logLevel = slog.LevelInfo
	}
	return logevent.Setup(os.Stdout, logLevel, "local")
}
