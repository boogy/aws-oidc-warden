package handler

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
)

// ParseS3URI splits s3://bucket/key; the key keeps any "//" intact.
func ParseS3URI(uri string) (bucket, key string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", fmt.Errorf("invalid s3 uri %q: %w", uri, err)
	}
	switch {
	case u.Scheme != "s3" || !strings.HasPrefix(uri, "s3://"):
		return "", "", fmt.Errorf("invalid s3 uri %q: scheme must be s3", uri)
	case u.Host == "" || u.Port() != "" || strings.Contains(u.Host, ":"):
		return "", "", fmt.Errorf("invalid s3 uri %q: bucket missing or has a port", uri)
	case u.User != nil:
		return "", "", fmt.Errorf("invalid s3 uri %q: userinfo not allowed", uri)
	case u.RawQuery != "" || u.Fragment != "" || strings.Contains(uri, "?") || strings.Contains(uri, "#"):
		return "", "", fmt.Errorf("invalid s3 uri %q: query and fragment not allowed", uri)
	}
	key = strings.TrimPrefix(u.Path, "/")
	if key == "" {
		return "", "", fmt.Errorf("invalid s3 uri %q: key missing", uri)
	}
	return u.Host, key, nil
}

type fetchedETag struct{ digest, s3ETag string }

// s3FragmentFetcher reads fragments through the owner-pinned conditional GET and reports a sha256 content digest as the etag.
func s3FragmentFetcher(consumer aws.AwsConsumerInterface) config.FragmentFetchFunc {
	var mu sync.Mutex
	seen := map[string]fetchedETag{}

	return func(ctx context.Context, uri, prevETag, owner string) ([]byte, string, error) {
		if owner == "" {
			return nil, "", fmt.Errorf("s3 fragment %q: s3_config_bucket_owner must be set in the service config", uri)
		}
		bucket, key, err := ParseS3URI(uri)
		if err != nil {
			return nil, "", err
		}

		mu.Lock()
		var prevS3 string
		if e, ok := seen[uri]; ok && prevETag != "" && e.digest == prevETag {
			prevS3 = e.s3ETag
		}
		mu.Unlock()

		data, s3ETag, err := consumer.GetS3ObjectIfChanged(ctx, bucket, key, prevS3, owner)
		if err != nil {
			return nil, "", err
		}
		if prevS3 != "" && data == nil {
			return nil, prevETag, nil
		}

		digest := config.ContentDigest(data)
		mu.Lock()
		seen[uri] = fetchedETag{digest: digest, s3ETag: s3ETag}
		mu.Unlock()
		return data, digest, nil
	}
}
