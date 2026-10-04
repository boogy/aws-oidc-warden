package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	maxSubjectBytes = 255
	maxTokenBytes   = 20000 // STS WebIdentityToken max length
	maxSigBytes     = 512   // RS256 up to 4096 bits; ES256 uses 64
)

var (
	// ErrInvalidSubject is returned when the role ARN or rendered sub is unusable.
	ErrInvalidSubject = errors.New("idp subject must be printable ASCII of at most 255 bytes ending in a valid role ARN")
	// ErrTokenTooLarge is returned when the estimated token exceeds maxTokenBytes.
	ErrTokenTooLarge = errors.New("idp token exceeds the STS web-identity token size limit")
	// ErrInvalidSourceIdentity is returned when the source identity is not a valid STS value.
	ErrInvalidSourceIdentity = errors.New("idp source identity must match " + utils.STSNameRule)
)

func maxSigLen(alg string) int {
	if alg == "ES256" {
		return 64
	}
	return maxSigBytes
}

func estimateTokenLen(header, payload []byte, alg string) int {
	return b64.EncodedLen(len(header)) + 1 + b64.EncodedLen(len(payload)) + 1 + b64.EncodedLen(maxSigLen(alg))
}

// MintRequest is the authorized input for one token.
type MintRequest struct {
	RoleARN        string
	SourceIssuer   string
	SourceSubject  string
	RequestID      string
	SourceIdentity string
	Tags           []ststypes.Tag
	TransitiveKeys []string
}

// Token is a minted, self-verified JWT plus its identifying metadata.
type Token struct {
	Value     string
	ID        string
	Subject   string
	KeyID     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type awsTags struct {
	PrincipalTags     map[string][]string `json:"principal_tags"`
	TransitiveTagKeys []string            `json:"transitive_tag_keys,omitempty"`
}

// Only claim source: never copy inbound claims.
type mintClaims struct {
	Iss       string   `json:"iss"`
	Sub       string   `json:"sub"`
	Aud       string   `json:"aud"`
	Iat       int64    `json:"iat"`
	Nbf       int64    `json:"nbf"`
	Exp       int64    `json:"exp"`
	Jti       string   `json:"jti"`
	SrcIss    string   `json:"src_iss,omitempty"`
	SrcSub    string   `json:"src_sub,omitempty"`
	RequestID string   `json:"request_id,omitempty"`
	SourceID  string   `json:"https://aws.amazon.com/source_identity,omitempty"`
	Tags      *awsTags `json:"https://aws.amazon.com/tags,omitempty"`
}

func mint(ctx context.Context, cfg config.IdPConfig, ks *KeySet, req MintRequest, now time.Time) (*Token, error) {
	sub, err := renderSubject(cfg.SubjectTemplate, req.RoleARN, req.SourceIssuer, req.SourceSubject)
	if err != nil {
		return nil, err
	}
	aud := cfg.Audience
	if cfg.AudienceMode == config.IdPAudienceRoleARN {
		aud = req.RoleARN
	}
	signer := ks.Active()
	now = now.Truncate(time.Second)
	exp := now.Add(cfg.TokenTTL)
	c := mintClaims{
		Iss: cfg.Issuer, Sub: sub, Aud: aud,
		Iat: now.Unix(), Nbf: now.Unix(), Exp: exp.Unix(),
		Jti:    uuid.NewString(),
		SrcIss: req.SourceIssuer, SrcSub: req.SourceSubject, RequestID: req.RequestID,
	}
	if cfg.IncludeSourceIdentityClaim() && req.SourceIdentity != "" {
		if !utils.ValidSTSName(req.SourceIdentity) {
			return nil, ErrInvalidSourceIdentity
		}
		c.SourceID = req.SourceIdentity
	}
	if len(req.Tags) > 0 {
		t := &awsTags{PrincipalTags: make(map[string][]string, len(req.Tags)), TransitiveTagKeys: req.TransitiveKeys}
		for _, tag := range req.Tags {
			t.PrincipalTags[aws.ToString(tag.Key)] = []string{aws.ToString(tag.Value)}
		}
		c.Tags = t
	}
	header, err := json.Marshal(map[string]string{"alg": signer.Algorithm(), "typ": "JWT", "kid": signer.KeyID()})
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	est := estimateTokenLen(header, payload, signer.Algorithm())
	if est > maxTokenBytes {
		return nil, fmt.Errorf("%w: estimated %d bytes", ErrTokenTooLarge, est)
	}
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sig, err := signer.Sign(ctx, []byte(signingInput))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if err := jwt.GetSigningMethod(signer.Algorithm()).Verify(signingInput, sig, signer.Public()); err != nil {
		return nil, fmt.Errorf("self-verification failed: %w", err)
	}
	return &Token{
		Value: signingInput + "." + b64.EncodeToString(sig), ID: c.Jti, Subject: sub,
		KeyID: signer.KeyID(), IssuedAt: now, ExpiresAt: exp,
	}, nil
}
