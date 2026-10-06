package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const testKMSARN = "arn:aws:kms:eu-west-1:111122223333:key/11111111-2222-3333-4444-555555555555"

type fakeKMS struct {
	priv        crypto.Signer
	keyID       string
	usage       kmstypes.KeyUsageType
	spec        kmstypes.KeySpec
	algs        []kmstypes.SigningAlgorithmSpec
	enabled     bool
	multiRegion bool
	describeErr error
	getPubErr   error
	nilMetadata bool
	signErr     error
	blockSign   bool
	calls       int

	mdArn    string
	mrc      *kmstypes.MultiRegionConfiguration
	seenARNs []string
}

type regionKMS struct {
	*fakeKMS
	region string
}

func (r regionKMS) Options() kms.Options { return kms.Options{Region: r.region} }

var (
	ecAlgs  = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256}
	rsaAlgs = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256}
)

func newFakeKMS(priv crypto.Signer, spec kmstypes.KeySpec, algs []kmstypes.SigningAlgorithmSpec) *fakeKMS {
	return &fakeKMS{priv: priv, keyID: testKMSARN, enabled: true, usage: kmstypes.KeyUsageTypeSignVerify, spec: spec, algs: algs}
}

func (f *fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.seenARNs = append(f.seenARNs, aws.ToString(in.KeyId))
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if f.nilMetadata {
		return &kms.DescribeKeyOutput{}, nil
	}
	arn := f.mdArn
	if arn == "" {
		arn = aws.ToString(in.KeyId)
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		Arn:                      aws.String(arn),
		MultiRegionConfiguration: f.mrc,
		Enabled:                  f.enabled,
		KeyUsage:                 f.usage,
		MultiRegion:              aws.Bool(f.multiRegion),
		KeySpec:                  f.spec,
		SigningAlgorithms:        f.algs,
	}}, nil
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.seenARNs = append(f.seenARNs, aws.ToString(in.KeyId))
	if f.getPubErr != nil {
		return nil, f.getPubErr
	}
	der, _ := x509.MarshalPKIXPublicKey(f.priv.Public())
	return &kms.GetPublicKeyOutput{KeyId: aws.String(f.keyID), PublicKey: der, KeyUsage: f.usage, KeySpec: f.spec, SigningAlgorithms: f.algs}, nil
}

func (f *fakeKMS) Sign(ctx context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.calls++
	f.seenARNs = append(f.seenARNs, aws.ToString(in.KeyId))
	if f.blockSign {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.signErr != nil {
		return nil, f.signErr
	}
	if in.MessageType != kmstypes.MessageTypeDigest {
		return nil, errors.New("expected DIGEST")
	}
	sig, err := f.priv.Sign(rand.Reader, in.Message, crypto.SHA256)
	return &kms.SignOutput{Signature: sig}, err
}

func TestKMSSigner(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherARN := "arn:aws:kms:eu-west-1:111122223333:key/99999999-2222-3333-4444-555555555555"
	tests := []struct {
		name    string
		mutate  func(f *fakeKMS)
		rsa     bool
		alg     string
		wantErr string
	}{
		{"es256", nil, false, "ES256", ""},
		{"rs256", nil, true, "RS256", ""},
		{"wrong usage", func(f *fakeKMS) { f.usage = kmstypes.KeyUsageTypeEncryptDecrypt }, false, "ES256", "SIGN_VERIFY"},
		{"wrong key spec", func(f *fakeKMS) { f.spec = kmstypes.KeySpecEccSecgP256k1 }, false, "ES256", "KeySpec"},
		{"rsa spec for es256", nil, true, "ES256", "KeySpec"},
		{"missing signing alg", func(f *fakeKMS) {
			f.algs = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPssSha256}
		}, true, "RS256", "SigningAlgorithms"},
		{"key id mismatch", func(f *fakeKMS) { f.keyID = otherARN }, false, "ES256", "KeyId"},
		{"key id empty", func(f *fakeKMS) { f.keyID = "" }, false, "ES256", "KeyId"},
		{"disabled", func(f *fakeKMS) { f.enabled = false }, false, "ES256", "Enabled"},
		{"multi-region on single-region arn", func(f *fakeKMS) { f.multiRegion = true }, false, "ES256", "MultiRegion"},
		{"describe arn mismatch", func(f *fakeKMS) { f.mdArn = otherARN }, false, "ES256", "Arn"},
		{"describe error", func(f *fakeKMS) { f.describeErr = errors.New("denied") }, false, "ES256", "DescribeKey"},
		{"nil metadata", func(f *fakeKMS) { f.nilMetadata = true }, false, "ES256", "no metadata"},
		{"get public key error", func(f *fakeKMS) { f.getPubErr = errors.New("boom") }, false, "ES256", "GetPublicKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f *fakeKMS
			if tt.rsa {
				f = newFakeKMS(rk, kmstypes.KeySpecRsa2048, rsaAlgs)
			} else {
				f = newFakeKMS(ec, kmstypes.KeySpecEccNistP256, ecAlgs)
			}
			if tt.mutate != nil {
				tt.mutate(f)
			}
			s, err := NewKMSSigner(context.Background(), f, testKMSARN, tt.alg, nil, time.Second)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			in := []byte("h.p")
			sig, err := s.Sign(context.Background(), in)
			require.NoError(t, err)
			if tt.alg == "ES256" {
				require.Len(t, sig, 64)
			}
			require.NoError(t, jwt.GetSigningMethod(tt.alg).Verify(string(in), sig, s.Public()))
		})
	}
}

func TestKMSSignerSignsDigest(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeKMS(ec, kmstypes.KeySpecEccNistP256, ecAlgs)
	s, err := NewKMSSigner(context.Background(), f, testKMSARN, "ES256", nil, time.Second)
	require.NoError(t, err)
	in := []byte("h.p")
	sig, err := s.Sign(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, 1, f.calls)
	require.Len(t, sig, 64)
	require.NoError(t, jwt.GetSigningMethod("ES256").Verify(string(in), sig, s.Public()))
}

func TestKMSSignerPropagatesError(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeKMS(ec, kmstypes.KeySpecEccNistP256, ecAlgs)
	s, err := NewKMSSigner(context.Background(), f, testKMSARN, "ES256", nil, time.Second)
	require.NoError(t, err)
	f.signErr = errors.New("throttled")
	_, err = s.Sign(context.Background(), []byte("x"))
	require.ErrorContains(t, err, "throttled")
}

func TestKMSSignerTimeout(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeKMS(ec, kmstypes.KeySpecEccNistP256, ecAlgs)
	s, err := NewKMSSigner(context.Background(), f, testKMSARN, "ES256", nil, 50*time.Millisecond)
	require.NoError(t, err)
	f.blockSign = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = s.Sign(ctx, []byte("x"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
}

func TestNewKMSSignerBadKeyID(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeKMS(ec, kmstypes.KeySpecEccNistP256, ecAlgs)
	_, err := NewKMSSigner(context.Background(), f, "alias/x", "ES256", nil, time.Second)
	require.ErrorContains(t, err, "does not match")
}

func TestDERToJOSE(t *testing.T) {
	marshal := func(r, s *big.Int) []byte {
		der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		require.NoError(t, err)
		return der
	}
	valid := marshal(big.NewInt(1), big.NewInt(2))
	tests := []struct {
		name    string
		der     []byte
		wantErr bool
	}{
		{"garbage", []byte{0x01, 0x02}, true},
		{"trailing bytes", append(append([]byte{}, valid...), 0x00), true},
		{"oversize component", marshal(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), true},
		{"short R is left-padded", valid, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := derToJOSE(tt.der, 32)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, out, 64)
			require.EqualValues(t, 1, out[31])
			require.EqualValues(t, 2, out[63])
		})
	}
}

const (
	testMRKARN     = "arn:aws:kms:eu-west-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef"
	testMRKARNUSE1 = "arn:aws:kms:us-east-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef"
)

func TestKMSSignerMultiRegion(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	allowed := []string{"eu-west-1", "us-east-1"}
	mrc := func(primary string, replicas ...string) *kmstypes.MultiRegionConfiguration {
		c := &kmstypes.MultiRegionConfiguration{PrimaryKey: &kmstypes.MultiRegionKey{Region: aws.String(primary)}}
		for _, r := range replicas {
			c.ReplicaKeys = append(c.ReplicaKeys, kmstypes.MultiRegionKey{Region: aws.String(r)})
		}
		return c
	}
	tests := []struct {
		name    string
		region  string
		noOpts  bool
		mutate  func(f *fakeKMS)
		allowed []string
		wantErr string
	}{
		{"rewrites to local replica", "us-east-1", false, nil, allowed, ""},
		{"configured region is local", "eu-west-1", false, nil, allowed, ""},
		{"rogue replica region", "us-east-1", false, func(f *fakeKMS) { f.mrc = mrc("eu-west-1", "us-east-1", "ap-south-1") }, allowed, "ap-south-1"},
		{"rogue primary region", "us-east-1", false, func(f *fakeKMS) { f.mrc = mrc("ap-south-1", "us-east-1") }, allowed, "ap-south-1"},
		{"nil multi-region configuration", "us-east-1", false, func(f *fakeKMS) { f.mrc = nil }, allowed, "MultiRegionConfiguration"},
		{"nil primary key", "us-east-1", false, func(f *fakeKMS) { f.mrc = &kmstypes.MultiRegionConfiguration{} }, allowed, "MultiRegionConfiguration"},
		{"local region not allowed", "ap-south-1", false, nil, allowed, "ap-south-1"},
		{"no Options", "", true, nil, allowed, "region"},
		{"empty local region", "", false, nil, allowed, "region"},
		{"multi-region false on mrk arn", "us-east-1", false, func(f *fakeKMS) { f.multiRegion = false }, allowed, "MultiRegion"},
		{"describe arn mismatch", "us-east-1", false, func(f *fakeKMS) { f.mdArn = testMRKARN }, allowed, "Arn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeKMS(ec, kmstypes.KeySpecEccNistP256, ecAlgs)
			f.multiRegion = true
			f.keyID = testMRKARN
			if tt.region == "us-east-1" {
				f.keyID = testMRKARNUSE1
			}
			f.mrc = mrc("eu-west-1", "us-east-1")
			if tt.mutate != nil {
				tt.mutate(f)
			}
			var api KMSAPI = regionKMS{f, tt.region}
			if tt.noOpts {
				api = f
			}
			s, err := NewKMSSigner(context.Background(), api, testMRKARN, "ES256", tt.allowed, time.Second)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			_, err = s.Sign(context.Background(), []byte("h.p"))
			require.NoError(t, err)
			want := testMRKARN
			if tt.region == "us-east-1" {
				want = testMRKARNUSE1
			}
			require.Len(t, f.seenARNs, 3)
			for _, got := range f.seenARNs {
				require.Equal(t, want, got)
			}
		})
	}
}

func TestKMSSignerSingleRegionIgnoresClientRegion(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeKMS(ec, kmstypes.KeySpecEccNistP256, ecAlgs)
	s, err := NewKMSSigner(context.Background(), regionKMS{f, "us-east-1"}, testKMSARN, "ES256", nil, time.Second)
	require.NoError(t, err)
	_, err = s.Sign(context.Background(), []byte("h.p"))
	require.NoError(t, err)
	for _, got := range f.seenARNs {
		require.Equal(t, testKMSARN, got)
	}
}
