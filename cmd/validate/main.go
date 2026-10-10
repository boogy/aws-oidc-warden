// Command validate loads a config with its overlay, mappings file and fragments merged, and exits non-zero if it is invalid.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// overrides maps a configured source URI to a local file read in its place.
type overrides map[string]string

func (o overrides) String() string { return fmt.Sprint(map[string]string(o)) }

func (o overrides) Set(v string) error {
	uri, path, ok := strings.Cut(v, "=")
	if !ok || uri == "" || path == "" {
		return fmt.Errorf("want URI=PATH, got %q", v)
	}
	bucket, key, err := handler.ParseS3URI(uri)
	if err != nil {
		return err
	}
	uri = s3URI(bucket, key)
	if _, dup := o[uri]; dup {
		return fmt.Errorf("%s overridden twice", uri)
	}
	o[uri] = path
	return nil
}

func main() {
	ctx := context.Background()
	logger := logevent.Setup(os.Stderr, slog.LevelInfo, "validate")

	configPath := flag.String("config", "", "Path to the service config file (required)")
	ov := overrides{}
	flag.Var(ov, "override", "s3://URI=PATH: read a local file in place of an S3 source (overlay, mappings_file or config_fragments entry), parsed as the URI's format; write \"=\" in a key as %3D; repeatable")
	offline := flag.Bool("offline", false, "Fail instead of fetching any remote source that has no -override")
	flag.Parse()

	fail := func(component string, err error) {
		logevent.Error(ctx, logger, logevent.AppInitFailure, "config validation failed",
			slog.String("component", component), slog.String("error", err.Error()))
		os.Exit(1)
	}

	if *configPath == "" {
		fail("flags", errors.New("-config is required"))
	}
	if err := config.UseConfigFile(*configPath); err != nil {
		fail("flags", err)
	}

	c := &config.Config{}
	if err := c.LoadConfig(); err != nil {
		fail("config", err)
	}

	var consumer aws.AwsConsumerInterface
	if !*offline {
		consumer = aws.NewAwsConsumer(c)
	}
	cfg, err := run(c, ov, *offline, consumer)
	if err != nil {
		fail("config", err)
	}
	logevent.Info(ctx, logger, logevent.ConfigValidated, "configuration is valid",
		slog.Int("issuerCount", len(cfg.Issuers)),
		slog.Int("fragmentCount", len(cfg.ConfigFragments)),
		slog.Int("totalMappings", len(cfg.RoleMappings)),
		slog.Int("totalGroups", len(cfg.RoleGroups)))
}

// run builds the merged config exactly as the service does at cold start, reading overridden S3 objects from local files.
func run(c *config.Config, ov overrides, offline bool, consumer aws.AwsConsumerInterface) (*config.Config, error) {
	if offline {
		var missing []string
		for _, uri := range remoteSources(c) {
			if _, ok := ov[uri]; !ok {
				missing = append(missing, uri)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("offline: no -override for remote source: %s", strings.Join(missing, ", "))
		}
		consumer = nil
	}

	local := &localSources{AwsConsumerInterface: consumer, files: ov, limit: c.EffectiveMaxConfigBytes(), used: map[string]bool{}}
	provider, err := handler.BuildConfigProvider(c, local)
	if err != nil {
		return nil, err
	}

	var unused []string
	for uri := range ov {
		if !local.used[uri] {
			unused = append(unused, uri)
		}
	}
	if len(unused) > 0 {
		slices.Sort(unused)
		return nil, fmt.Errorf("override matches no configured source: %s", strings.Join(unused, ", "))
	}
	return provider.Get(), nil
}

// localSources is the S3 reader the provider fetches through, serving overridden objects from local files.
type localSources struct {
	aws.AwsConsumerInterface // nil when offline
	files                    overrides
	limit                    int
	used                     map[string]bool
}

func (l *localSources) read(bucket, key string) (data []byte, ok bool, err error) {
	uri := s3URI(bucket, key)
	path, ok := l.files[uri]
	if !ok {
		if l.AwsConsumerInterface == nil {
			return nil, false, fmt.Errorf("offline: no -override for remote source: %s", uri)
		}
		return nil, false, nil
	}
	l.used[uri] = true
	data, err = readCapped(path, l.limit)
	if err != nil {
		return nil, true, fmt.Errorf("override %s: %w", uri, err)
	}
	return data, true, nil
}

func (l *localSources) GetS3ObjectIfChanged(ctx context.Context, bucket, key, prevETag, owner string) ([]byte, string, error) {
	data, ok, err := l.read(bucket, key)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return l.AwsConsumerInterface.GetS3ObjectIfChanged(ctx, bucket, key, prevETag, owner)
	}
	return data, config.ContentDigest(data), nil
}

func (l *localSources) GetS3Object(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	data, ok, err := l.read(bucket, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return l.AwsConsumerInterface.GetS3Object(ctx, bucket, key)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func overlayURI(c *config.Config) string {
	if c.S3ConfigBucket == "" || c.S3ConfigPath == "" {
		return ""
	}
	return s3URI(c.S3ConfigBucket, c.S3ConfigPath)
}

// s3URI is the one form overrides, the offline check and the S3 reader match on; it round-trips through ParseS3URI.
func s3URI(bucket, key string) string {
	// "=" is escaped so a reported URI pasted into -override URI=PATH splits at the right "=".
	return strings.ReplaceAll((&url.URL{Scheme: "s3", Host: bucket, Path: "/" + key}).String(), "=", "%3D")
}

// remoteSources lists the sources the provider would still fetch over the network.
func remoteSources(c *config.Config) []string {
	var out []string
	if uri := overlayURI(c); uri != "" {
		out = append(out, uri)
	}
	for _, uri := range append([]string{c.MappingsFile}, c.ConfigFragments...) {
		if !strings.Contains(uri, "://") {
			continue
		}
		// An unparseable URI is left to the fetcher, which reports why.
		if bucket, key, err := handler.ParseS3URI(uri); err == nil {
			out = append(out, s3URI(bucket, key))
		}
	}
	return out
}

// readCapped reads path under the same max_config_bytes cap the service applies to the S3 overlay.
func readCapped(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return utils.ReadAllCapped(f, int64(limit), path)
}
