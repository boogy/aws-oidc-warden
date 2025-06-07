package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/pkg/aws"
	"github.com/boogy/aws-oidc-warden/pkg/cache"
	"github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/boogy/aws-oidc-warden/pkg/handler"
	"github.com/boogy/aws-oidc-warden/pkg/validator"
	"github.com/boogy/aws-oidc-warden/pkg/version"
)

// Settings for the local server
type ServerSettings struct {
	Port            int
	ConfigPath      string
	LogLevel        string
	SimulateLatency time.Duration
}

func main() {
	settings := parseCliFlags()
	setupLogging(settings.LogLevel)

	// Log version information
	versionInfo := version.Get()
	slog.Info("Starting AWS OIDC Warden Local Server",
		slog.String("version", versionInfo.Version),
		slog.String("commit", versionInfo.Commit),
		slog.String("date", versionInfo.Date),
	)

	// Load configuration
	cfg, err := config.NewConfig()
	if err != nil {
		slog.Error("Failed to load config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize the cache
	jwksCache, err := cache.NewCache(cfg)
	if err != nil {
		slog.Error("Failed to initialize cache", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize the token validator
	validator := validator.NewTokenValidator(cfg, jwksCache)

	// Initialize the AWS client
	awsClient := aws.NewAwsConsumer(cfg)

	// Create the handler function
	handlerFunc := handler.NewAwsApiGateway(cfg, awsClient, validator).Handler

	// Set up HTTP server
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		// Simulate network latency if configured
		if settings.SimulateLatency > 0 {
			time.Sleep(settings.SimulateLatency)
		}

		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		defer func() {
			if err := r.Body.Close(); err != nil {
				slog.Error("Error closing request body", "error", err)
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
		response, err := handlerFunc(r.Context(), apiGatewayEvent)
		if err != nil {
			slog.Error("Handler error", slog.String("error", err.Error()))
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
			slog.Error("Error writing response", "error", err)
		}
	})

	// Add a health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			slog.Error("Error encoding health check response", "error", err)
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

		slog.Info("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			slog.Error("Server shutdown error", slog.String("error", err.Error()))
		}
	}()

	slog.Info("Starting local development server",
		slog.Int("port", settings.Port),
		slog.String("verifyEndpoint", fmt.Sprintf("http://localhost:%d/verify", settings.Port)),
		slog.String("healthEndpoint", fmt.Sprintf("http://localhost:%d/health", settings.Port)))

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("Server error", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("Server stopped")
}

func parseCliFlags() ServerSettings {
	settings := ServerSettings{}

	flag.IntVar(&settings.Port, "port", 8080, "Port to listen on")
	flag.StringVar(&settings.ConfigPath, "config", "", "Path to config file")
	flag.StringVar(&settings.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.DurationVar(&settings.SimulateLatency, "latency", 0, "Simulate network latency (e.g., 100ms)")

	flag.Parse()

	// Set config path as environment variable if provided
	if settings.ConfigPath != "" {
		if err := os.Setenv("CONFIG_PATH", settings.ConfigPath); err != nil {
			slog.Error("Error setting CONFIG_PATH environment variable", "error", err)
		}
	}

	return settings
}

func setupLogging(level string) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)
}
