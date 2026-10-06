package idp

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

// KMSAPI is the subset of the KMS client the signer needs.
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

var kmsAllowedKeySpecs = map[string][]kmstypes.KeySpec{
	"RS256": {kmstypes.KeySpecRsa2048, kmstypes.KeySpecRsa3072, kmstypes.KeySpecRsa4096},
	"ES256": {kmstypes.KeySpecEccNistP256},
}

type kmsSigner struct {
	api     KMSAPI
	keyID   string
	alg     string
	kid     string
	pub     crypto.PublicKey
	spec    kmstypes.SigningAlgorithmSpec
	timeout time.Duration
}

// NewKMSSigner checks the KMS key's identity and properties and fetches its public half; the private key never leaves KMS.
// A multi-region key is addressed through its replica in the client's region, which must be in allowedRegions.
func NewKMSSigner(ctx context.Context, api KMSAPI, configuredARN, alg string, allowedRegions []string, timeout time.Duration) (Signer, error) {
	mrk := config.IsMultiRegionKMSKey(configuredARN)
	keyID := configuredARN
	if mrk {
		var err error
		if keyID, err = localReplicaARN(api, configuredARN, allowedRegions); err != nil {
			return nil, err
		}
	}
	desc, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("kms DescribeKey %s: %w", keyID, err)
	}
	md := desc.KeyMetadata
	if md == nil {
		return nil, fmt.Errorf("kms key %s: DescribeKey returned no metadata", keyID)
	}
	if !md.Enabled {
		return nil, fmt.Errorf("kms key %s: key must be Enabled", keyID)
	}
	if md.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kms key %s: KeyUsage must be SIGN_VERIFY", keyID)
	}
	if aws.ToBool(md.MultiRegion) != mrk {
		return nil, fmt.Errorf("kms key %s: MultiRegion is %t but the key ID %s a multi-region key ID", keyID, aws.ToBool(md.MultiRegion), map[bool]string{true: "is", false: "is not"}[mrk])
	}
	if aws.ToString(md.Arn) != keyID {
		return nil, fmt.Errorf("kms key %s: DescribeKey Arn %q does not match the key ARN", keyID, aws.ToString(md.Arn))
	}
	if mrk {
		if err := checkReplicaSet(keyID, md.MultiRegionConfiguration, allowedRegions); err != nil {
			return nil, err
		}
	}
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("kms GetPublicKey %s: %w", keyID, err)
	}
	if aws.ToString(out.KeyId) != keyID {
		return nil, fmt.Errorf("kms key %s: GetPublicKey KeyId %q does not match the key ARN", keyID, aws.ToString(out.KeyId))
	}
	if !slices.Contains(kmsAllowedKeySpecs[alg], out.KeySpec) {
		return nil, fmt.Errorf("kms key %s: KeySpec %s not allowed for %s", keyID, out.KeySpec, alg)
	}
	spec := kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	if alg == "ES256" {
		spec = kmstypes.SigningAlgorithmSpecEcdsaSha256
	}
	if !slices.Contains(out.SigningAlgorithms, spec) {
		return nil, fmt.Errorf("kms key %s: SigningAlgorithms does not include %s", keyID, spec)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms key %s: %w", keyID, err)
	}
	if err := checkKeyMatchesAlg(alg, pub); err != nil {
		return nil, fmt.Errorf("kms key %s: %w", keyID, err)
	}
	kid, err := Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	return &kmsSigner{api: api, keyID: keyID, alg: alg, kid: kid, pub: pub, spec: spec, timeout: timeout}, nil
}

func localReplicaARN(api KMSAPI, arn string, allowedRegions []string) (string, error) {
	o, ok := api.(interface{ Options() kms.Options })
	if !ok || o.Options().Region == "" {
		return "", fmt.Errorf("kms key %s: multi-region key needs a KMS client with a region", arn)
	}
	region := o.Options().Region
	if !slices.Contains(allowedRegions, region) {
		return "", fmt.Errorf("kms key %s: client region %s is not in kms_allowed_regions", arn, region)
	}
	parts := strings.Split(arn, ":")
	parts[3] = region
	return strings.Join(parts, ":"), nil
}

func checkReplicaSet(keyID string, c *kmstypes.MultiRegionConfiguration, allowedRegions []string) error {
	if c == nil || c.PrimaryKey == nil {
		return fmt.Errorf("kms key %s: DescribeKey returned no MultiRegionConfiguration primary key", keyID)
	}
	regions := []string{aws.ToString(c.PrimaryKey.Region)}
	for _, r := range c.ReplicaKeys {
		regions = append(regions, aws.ToString(r.Region))
	}
	for _, r := range regions {
		if !slices.Contains(allowedRegions, r) {
			return fmt.Errorf("kms key %s: replica set includes region %s, which is not in kms_allowed_regions", keyID, r)
		}
	}
	return nil
}

func (s *kmsSigner) Algorithm() string        { return s.alg }
func (s *kmsSigner) KeyID() string            { return s.kid }
func (s *kmsSigner) Public() crypto.PublicKey { return s.pub }

func (s *kmsSigner) Sign(ctx context.Context, in []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	digest := sha256.Sum256(in)
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: s.spec,
	})
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	if s.alg == "ES256" {
		return derToJOSE(out.Signature, 32)
	}
	return out.Signature, nil
}

// derToJOSE converts an ASN.1 ECDSA signature to the fixed-width R||S form JWS requires.
func derToJOSE(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, errors.New("invalid ECDSA DER signature")
	}
	if sig.R.BitLen() > size*8 || sig.S.BitLen() > size*8 {
		return nil, errors.New("ECDSA signature component too large")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}
