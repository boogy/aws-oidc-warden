package idp

import "testing"

func BenchmarkRenderSubject(b *testing.B) {
	parts := compileSubjectTemplate("{source_issuer}#{source_subject}#{role_arn}")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := renderSubject(parts, testRole, "https://token.actions.githubusercontent.com", "repo:acme/api:ref:refs/heads/main"); err != nil {
			b.Fatal(err)
		}
	}
}
