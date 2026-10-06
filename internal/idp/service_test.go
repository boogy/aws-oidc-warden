package idp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

func loaderFor(tb testing.TB, calls *atomic.Int32) Loader {
	tb.Helper()
	sg := newTestSigner(tb)
	return func(context.Context) ([]LoadedKey, error) {
		calls.Add(1)
		return []LoadedKey{{Signer: sg, Status: config.IdPKeyActive}}, nil
	}
}

func TestServiceRecoversAfterCooldown(t *testing.T) {
	sg := newTestSigner(t)
	var calls int
	fail := true
	s := NewService(testCfg(), func(context.Context) ([]LoadedKey, error) {
		calls++
		if fail {
			return nil, errors.New("kms down")
		}
		return []LoadedKey{{Signer: sg, Status: config.IdPKeyActive}}, nil
	})
	clock := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return clock }
	ctx := context.Background()

	require.Error(t, s.Warm(ctx))
	require.Equal(t, 1, calls)
	_, err := s.KeySet(ctx)
	require.ErrorIs(t, err, ErrUnavailable)

	clock = clock.Add(loadCooldownMin - time.Second)
	_, err = s.KeySet(ctx)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Equal(t, 1, calls, "no retry inside cooldown")

	fail = false
	clock = clock.Add(2 * loadCooldownMin)
	ks, err := s.KeySet(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	require.Equal(t, sg.KeyID(), ks.Active().KeyID())

	_, err = s.KeySet(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
}

func TestServiceLoadIgnoresCallerCancellation(t *testing.T) {
	sg := newTestSigner(t)
	s := NewService(testCfg(), func(ctx context.Context) ([]LoadedKey, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := ctx.Deadline(); !ok {
			return nil, errors.New("no deadline")
		}
		return []LoadedKey{{Signer: sg, Status: config.IdPKeyActive}}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.KeySet(ctx)
	require.NoError(t, err)
}

func TestServiceLoadsOnce(t *testing.T) {
	t.Run("concurrent", func(t *testing.T) {
		sg := newTestSigner(t)
		var calls atomic.Int32
		release := make(chan struct{})
		s := NewService(testCfg(), func(context.Context) ([]LoadedKey, error) {
			calls.Add(1)
			<-release
			return []LoadedKey{{Signer: sg, Status: config.IdPKeyActive}}, nil
		})
		var started, done sync.WaitGroup
		errs := make([]error, 16)
		for i := range errs {
			started.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				started.Done()
				_, errs[i] = s.KeySet(context.Background())
			}()
		}
		started.Wait()
		time.Sleep(20 * time.Millisecond)
		close(release)
		done.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}
		require.Equal(t, int32(1), calls.Load())
	})

	t.Run("sequential", func(t *testing.T) {
		var calls atomic.Int32
		s := NewService(testCfg(), loaderFor(t, &calls))
		require.NoError(t, s.Warm(context.Background()))
		var wg sync.WaitGroup
		got := make([]*KeySet, 32)
		for i := range got {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got[i], _ = s.KeySet(context.Background())
			}()
		}
		wg.Wait()
		require.Equal(t, int32(1), calls.Load())
		for _, ks := range got {
			require.NotNil(t, ks)
			require.Same(t, got[0], ks)
		}
	})
}

func TestServiceWarmBypassesCooldown(t *testing.T) {
	sg := newTestSigner(t)
	fail := true
	s := NewService(testCfg(), func(context.Context) ([]LoadedKey, error) {
		if fail {
			return nil, errors.New("kms down")
		}
		return []LoadedKey{{Signer: sg, Status: config.IdPKeyActive}}, nil
	})
	_, err := s.KeySet(context.Background())
	require.ErrorIs(t, err, ErrUnavailable)
	fail = false
	require.NoError(t, s.Warm(context.Background()))
	_, err = s.KeySet(context.Background())
	require.NoError(t, err)
}

func TestServiceMintUsesFrozenConfig(t *testing.T) {
	sg := newTestSigner(t)
	cfg := testCfg()
	cfg.TokenTTL = 5 * time.Minute
	cfg.SigningKeys = []config.IdPSigningKey{{File: "/k.pem", Algorithm: "ES256", Status: config.IdPKeyActive}}
	on := true
	cfg.IncludeSourceIdentity = &on

	s := NewService(cfg, func(context.Context) ([]LoadedKey, error) {
		return []LoadedKey{{Signer: sg, Status: config.IdPKeyActive}}, nil
	})
	cfg.SigningKeys[0].File = "/mutated.pem"
	*cfg.IncludeSourceIdentity = false

	got := s.Config()
	require.Equal(t, "/k.pem", got.SigningKeys[0].File)
	require.True(t, *got.IncludeSourceIdentity)

	tok, err := s.Mint(context.Background(), MintRequest{
		RoleARN: testRole, SourceIssuer: "https://token.actions.githubusercontent.com",
		SourceSubject: "org/repo", RequestID: "req-1",
	})
	require.NoError(t, err)
	require.Equal(t, testRole, tok.Subject)
	require.Equal(t, sg.KeyID(), tok.KeyID)
}
