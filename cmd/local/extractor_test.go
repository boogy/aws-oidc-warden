package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

func TestNewLocalExtractorAcceptsOnlySelfAndFreezesIt(t *testing.T) {
	t.Setenv("AOW_JWT_VALIDATION_MODE", "")
	const issuer = "issuers:\n  - issuer: https://token.actions.githubusercontent.com\n    provider: github\n    audiences: [sts.amazonaws.com]\nrole_session_name: aws-oidc-warden\n"
	const signer = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/a/1"
	tests := []struct {
		mode    string
		wantErr bool
	}{
		{mode: "self"},
		{mode: "apigw", wantErr: true},
		{mode: "alb", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			base := &config.Config{}
			yaml := issuer + "jwt_validation:\n  mode: " + tt.mode + "\n  alb_expected_signer: " + signer + "\n"
			if err := base.MergeBytes([]byte(yaml), "yaml"); err != nil {
				t.Fatal(err)
			}
			overlay := "log_level: info\n"
			p := config.NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) { return []byte(overlay), nil })
			if err := p.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}

			ex, err := newLocalExtractor(p, nil)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "supports only jwt_validation.mode self") {
					t.Fatalf("err = %v, want mode refusal", err)
				}
				return
			}
			if err != nil || ex == nil {
				t.Fatalf("extractor = %v, err = %v", ex, err)
			}
			overlay = "jwt_validation:\n  mode: apigw\n"
			if err := p.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := p.Get().JWTValidation.Mode; got != "self" {
				t.Errorf("mode after reload = %q, want frozen self", got)
			}
		})
	}
}
