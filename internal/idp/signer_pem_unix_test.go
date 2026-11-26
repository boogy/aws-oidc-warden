//go:build unix

package idp

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPEMSignerRejectsFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.pem")
	require.NoError(t, syscall.Mkfifo(p, 0o600))
	done := make(chan error, 1)
	go func() { _, err := NewPEMSigner(p, "ES256"); done <- err }()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("NewPEMSigner blocked opening a FIFO")
	}
}
