// Command validate loads a config with its overlay, mappings file and fragments merged, and exits non-zero if it is invalid.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
)

// overrides maps a configured source URI to a local file read in its place.
type overrides map[string]string

func (o overrides) String() string { return fmt.Sprint(map[string]string(o)) }

func (o overrides) Set(v string) error {
	uri, path, ok := strings.Cut(v, "=")
	if !ok || uri == "" || path == "" {
		return fmt.Errorf("want URI=PATH, got %q", v)
	}
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
	flag.Var(ov, "override", "URI=PATH: read a local file in place of a configured source (S3 overlay, mappings_file or config_fragments entry); repeatable")
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
	if _, err := os.Stat(*configPath); err != nil {
		fail("flags", err)
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

// run applies the overrides to c, then builds the merged config exactly as the service does at cold start.
func run(c *config.Config, ov overrides, offline bool, consumer aws.AwsConsumerInterface) (*config.Config, error) {
	used := map[string]bool{}

	if uri := overlayURI(c); uri != "" {
		if path, ok := ov[uri]; ok {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("overlay override: %w", err)
			}
			if err := c.MergeBytes(data, config.FormatFromPath(path)); err != nil {
				return nil, fmt.Errorf("overlay %s: %w", path, err)
			}
			c.S3ConfigBucket, c.S3ConfigPath = "", ""
			used[uri] = true
		}
	}

	if path, ok := ov[c.MappingsFile]; ok && c.MappingsFile != "" {
		used[c.MappingsFile] = true
		c.MappingsFile = path
	}
	for i, uri := range c.ConfigFragments {
		path, ok := ov[uri]
		if !ok {
			continue
		}
		used[uri] = true
		c.ConfigFragments[i] = path
		for j := range c.ConfigFragmentChecksums {
			if c.ConfigFragmentChecksums[j].URI == uri {
				c.ConfigFragmentChecksums[j].URI = path
			}
		}
	}

	var unused []string
	for uri := range ov {
		if !used[uri] {
			unused = append(unused, uri)
		}
	}
	if len(unused) > 0 {
		slices.Sort(unused)
		return nil, fmt.Errorf("override matches no configured source: %s", strings.Join(unused, ", "))
	}
	if offline {
		if remote := remoteSources(c); len(remote) > 0 {
			return nil, fmt.Errorf("offline: no -override for remote source: %s", strings.Join(remote, ", "))
		}
	}

	provider, err := handler.BuildConfigProvider(c, consumer)
	if err != nil {
		return nil, err
	}
	return provider.Get(), nil
}

func overlayURI(c *config.Config) string {
	if c.S3ConfigBucket == "" || c.S3ConfigPath == "" {
		return ""
	}
	return "s3://" + c.S3ConfigBucket + "/" + strings.TrimPrefix(c.S3ConfigPath, "/")
}

// remoteSources lists the sources the provider would still fetch over the network.
func remoteSources(c *config.Config) []string {
	var out []string
	if uri := overlayURI(c); uri != "" {
		out = append(out, uri)
	}
	for _, uri := range append([]string{c.MappingsFile}, c.ConfigFragments...) {
		if strings.Contains(uri, "://") {
			out = append(out, uri)
		}
	}
	return out
}
