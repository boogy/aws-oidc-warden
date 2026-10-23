package s3logger

import (
	"strings"
	"testing"
)

func BenchmarkCompressGzip(b *testing.B) {
	rec := []byte(strings.Repeat(`{"decision":"allow","issuer":"https://token.actions.githubusercontent.com","sub":"repo:acme/api:ref:refs/heads/main"}`, 8))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := compressGzip(rec); err != nil {
			b.Fatal(err)
		}
	}
}
