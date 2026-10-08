package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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

// ServerSettings holds the local server CLI flags.
type ServerSettings struct {
	Host            string
	Port            int
	ConfigPath      string
	MappingsPath    string
	LogLevel        string
	SimulateLatency time.Duration
}

func main() {
	ctx := context.Background()
	settings, cliErr := parseCliFlags()
	logger := setupLogging(settings.LogLevel)
	if cliErr != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "invalid command-line flags",
			slog.String("component", "flags"), slog.String("error", cliErr.Error()))
		os.Exit(1)
	}

	versionInfo := version.Get()
	logevent.Info(ctx, logger, logevent.AppStart, "starting AWS OIDC Warden local server",
		slog.String("version", versionInfo.Version),
		slog.String("commit", versionInfo.Commit),
		slog.String("date", versionInfo.Date),
	)

	cfg, err := config.NewConfig()
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "failed to load config",
			slog.String("component", "config"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	jwksCache, err := cache.NewCache(cfg)
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "failed to initialize cache",
			slog.String("component", "cache"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	awsClient := aws.NewAwsConsumer(cfg)

	// Shared by the validator and the handler so both read the same snapshot.
	provider, err := handler.BuildConfigProvider(cfg, awsClient)
	if err != nil {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "failed to load configuration",
			slog.String("component", "remote_config"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	awsClient.SetConfigSource(provider.Get)

	// The local server always validates JWT signatures itself (no delegated mode).
	tokenValidator := validator.NewTokenValidator(provider, jwksCache)
	extractor := validator.NewSelfExtractor(tokenValidator)

	svc := handler.NewIdPService(provider, handler.DefaultIdPKMS, logger)

	// No audit sink for the local dev server.
	h := handler.NewAwsApiGateway(provider, awsClient, extractor, nil).WithIdP(svc)

	var idpPaths []string
	if svc != nil {
		p := svc.Config().Paths
		idpPaths = []string{p.Discovery, p.JWKS}
	}

	addr := net.JoinHostPort(settings.Host, strconv.Itoa(settings.Port))
	server := newServer(addr, newMux(logger, settings.SimulateLatency, h.Handler, idpPaths...), settings.SimulateLatency)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logevent.Error(ctx, logger, logevent.HTTPServerFailure, "server error",
			slog.String("error", err.Error()))
		os.Exit(1)
	}

	logevent.Info(ctx, logger, logevent.HTTPServerStart, "starting local development server",
		slog.String("host", settings.Host),
		slog.Int("port", settings.Port),
		slog.String("verifyEndpoint", "http://"+addr+"/verify"),
		slog.String("healthEndpoint", "http://"+addr+"/health"))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	if err := serve(ctx, logger, server, ln, stop, shutdownTimeout); err != nil {
		logevent.Error(ctx, logger, logevent.HTTPServerFailure, "server error",
			slog.String("error", err.Error()))
		os.Exit(1)
	}

	logevent.Info(ctx, logger, logevent.AppStop, "server stopped")
}

const (
	readTimeout     = 30 * time.Second
	shutdownTimeout = 5 * time.Second
)

// newServer sizes WriteTimeout to cover the body read, the simulated latency and the handler's own deadline.
func newServer(addr string, h http.Handler, latency time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      readTimeout + latency + handler.DefaultTimeout + 5*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// serve runs server on ln until stop fires, then returns only after Shutdown has finished draining.
func serve(ctx context.Context, logger *slog.Logger, server *http.Server, ln net.Listener, stop <-chan os.Signal, timeout time.Duration) error {
	quit := make(chan struct{})
	defer close(quit)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		select {
		case <-stop:
		case <-quit:
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logevent.Error(ctx, logger, logevent.HTTPServerFailure, "server shutdown error",
				slog.String("error", err.Error()))
		}
	}()

	if err := server.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained
	return nil
}

// newMux serves /verify, the exact IdP document paths and /health; every other path is 404.
func newMux(logger *slog.Logger, latency time.Duration, handlerFunc func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error), idpPaths ...string) *http.ServeMux {
	allowed := map[string]bool{"/verify": true}
	for _, p := range idpPaths {
		allowed[p] = true
	}
	serve := localHandler(logger, latency, handlerFunc)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		serve(w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		reqCtx := logevent.WithRequest(r.Context(), logevent.Request{ID: uuid.New().String(), SourceIP: remoteIP(r.RemoteAddr)})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			logevent.Warn(reqCtx, logger, logevent.HTTPWriteFailure, "error encoding health check response",
				slog.String("error", err.Error()))
		}
	})
	return mux
}

// maxLocalBodyBytes sits one byte above the handler's cap so its own size check still answers.
const maxLocalBodyBytes = handler.MaxBodyBytes + 1

// localHandler adapts the Lambda handler to net/http.
func localHandler(logger *slog.Logger, latency time.Duration, handlerFunc func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		sourceIP := remoteIP(r.RemoteAddr)
		reqCtx := logevent.WithRequest(r.Context(), logevent.Request{ID: requestID, SourceIP: sourceIP})

		if latency > 0 {
			time.Sleep(latency)
		}

		if r.URL.Path == "/verify" && r.Method != http.MethodPost {
			logevent.Warn(reqCtx, logger, logevent.RequestRejected, "request rejected",
				slog.String("reason", "method not allowed"), slog.String("method", r.Method))
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLocalBodyBytes))
		if err != nil {
			logevent.Warn(reqCtx, logger, logevent.RequestRejected, "request rejected",
				slog.String("reason", "body read failed"), slog.String("error", err.Error()))
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}

		response, err := handlerFunc(reqCtx, buildEvent(r, body, requestID, sourceIP))
		if err != nil {
			logevent.Error(reqCtx, logger, logevent.HTTPResponseFailure, "handler error",
				slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		for k, v := range response.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(response.StatusCode)
		if _, err := w.Write([]byte(response.Body)); err != nil {
			logevent.Warn(reqCtx, logger, logevent.HTTPWriteFailure, "error writing response",
				slog.String("error", err.Error()))
		}
	}
}

// buildEvent maps an HTTP request to an API Gateway proxy event.
func buildEvent(r *http.Request, body []byte, requestID, sourceIP string) events.APIGatewayProxyRequest {
	ev := events.APIGatewayProxyRequest{
		Body:                  string(body),
		Path:                  r.URL.Path,
		HTTPMethod:            r.Method,
		Headers:               make(map[string]string),
		QueryStringParameters: make(map[string]string),
		PathParameters:        make(map[string]string),
		RequestContext: events.APIGatewayProxyRequestContext{
			RequestID: requestID,
			Identity:  events.APIGatewayRequestIdentity{SourceIP: sourceIP},
		},
	}
	for k, v := range r.Header {
		if len(v) > 0 {
			ev.Headers[k] = v[0]
		}
	}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			ev.QueryStringParameters[k] = v[0]
		}
	}
	return ev
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

	flag.StringVar(&settings.Host, "host", "127.0.0.1", "Address to listen on (use 0.0.0.0 inside a container)")
	flag.IntVar(&settings.Port, "port", 8080, "Port to listen on")
	flag.StringVar(&settings.ConfigPath, "config", "", "Path to config file or directory")
	flag.StringVar(&settings.MappingsPath, "mappings", "", "Path or s3:// URI of the role-mappings file")
	flag.StringVar(&settings.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.DurationVar(&settings.SimulateLatency, "latency", 0, "Simulate network latency (e.g., 100ms)")

	flag.Parse()

	if _, err := utils.ParseLogLevel(settings.LogLevel); err != nil {
		return settings, err
	}
	if err := config.UseConfigFile(settings.ConfigPath); err != nil {
		return settings, err
	}

	if settings.MappingsPath != "" {
		if err := os.Setenv("AOW_MAPPINGS_FILE", settings.MappingsPath); err != nil {
			return settings, err
		}
	}

	return settings, nil
}

// setupLogging installs the base JSON logger for the local adapter.
func setupLogging(level string) *slog.Logger {
	logLevel, err := utils.ParseLogLevel(level)
	if err != nil {
		logLevel = slog.LevelInfo // parseCliFlags rejects it; info still logs that error
	}
	return logevent.Setup(os.Stdout, logLevel, "local")
}
