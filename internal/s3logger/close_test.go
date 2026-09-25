package s3logger

import (
	"testing"

	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClose_BatchTimerDoesNotRearm(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "audit-bucket"})
	l.SetS3Client(&bucketCapturingS3{})
	require.NoError(t, l.Close())

	l.onBatchTimer()
	l.initMu.Lock()
	l.startBatchTimerLocked()
	timer := l.batchTimer
	l.initMu.Unlock()

	assert.Nil(t, timer)
}
