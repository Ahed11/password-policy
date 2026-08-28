package issue

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReloadUsesNewPolicy(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), reloadTestBuildResult('a'), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	event := <-pool.events

	require.NoError(t, event.err)
	require.Equal(t, []byte{'a'}, event.item.Password)

	oldPassword := event.item.Password

	pool.events <- event

	err = pool.Reload(reloadTestBuildResult('b'), poolTestGenerateOptions(1))
	require.NoError(t, err)

	assert.Equal(t, []byte{0}, oldPassword)

	item, err := pool.Get(context.Background())
	require.NoError(t, err)

	defer secret.Zero(item.Password)

	assert.Equal(t, []byte{'b'}, item.Password)

	assert.Equal(t, 1, item.Attempts)
}

func TestReloadWipesAllBufferedPasswords(t *testing.T) {
	const size = 3

	pool, err := NewPool(context.Background(), bytes.NewReader(nil), reloadTestBuildResult('a'), poolTestGenerateOptions(1), size)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	events := make([]poolEvent, 0, size)

	passwords := make([][]byte, 0, size)

	for i := 0; i < size; i++ {
		event := <-pool.events

		require.NoError(t, event.err)
		require.Equal(t, []byte{'a'}, event.item.Password)

		events = append(events, event)

		passwords = append(passwords, event.item.Password)
	}

	for _, event := range events {
		pool.events <- event
	}

	err = pool.Reload(reloadTestBuildResult('b'), poolTestGenerateOptions(1))
	require.NoError(t, err)

	for _, password := range passwords {
		assert.Equal(t, []byte{0}, password)
	}

	item, err := pool.Get(context.Background())
	require.NoError(t, err)

	defer secret.Zero(item.Password)

	assert.Equal(t, []byte{'b'}, item.Password)
}

func TestReloadMultipleTimesUsesLatestPolicy(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), reloadTestBuildResult('a'), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	assert.Equal(t, uint64(1), pool.currentVersion())

	err = pool.Reload(reloadTestBuildResult('b'), poolTestGenerateOptions(1))
	require.NoError(t, err)

	assert.Equal(t, uint64(2), pool.currentVersion())

	err = pool.Reload(reloadTestBuildResult('c'), poolTestGenerateOptions(1))
	require.NoError(t, err)

	assert.Equal(t, uint64(3), pool.currentVersion())

	item, err := pool.Get(context.Background())
	require.NoError(t, err)

	defer secret.Zero(item.Password)

	assert.Equal(t, []byte{'c'}, item.Password)
}

func TestReloadInvalidAttempts(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), reloadTestBuildResult('a'), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	event := <-pool.events

	require.NoError(t, event.err)

	pool.events <- event

	invalidOptions := poolTestGenerateOptions(0)

	err = pool.Reload(reloadTestBuildResult('b'), invalidOptions)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "attempts must be greater than zero")

	assert.Equal(t, uint64(1), pool.currentVersion())

	item, getErr := pool.Get(context.Background())
	require.NoError(t, getErr)

	defer secret.Zero(item.Password)

	assert.Equal(t, []byte{'a'}, item.Password)
}

func TestReloadAfterStop(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), reloadTestBuildResult('a'), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	pool.Stop()

	err = pool.Reload(reloadTestBuildResult('b'), poolTestGenerateOptions(1))

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPoolStopped)
}

func TestReloadNilPool(t *testing.T) {
	var pool *Pool

	err := pool.Reload(reloadTestBuildResult('b'), poolTestGenerateOptions(1))

	assert.Error(t, err)
	assert.ErrorContains(t, err, "pool must not be nil")
}

func TestReloadAfterParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())

	pool, err := NewPool(parent, bytes.NewReader(nil), reloadTestBuildResult('a'), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	cancel()

	err = pool.Reload(reloadTestBuildResult('b'), poolTestGenerateOptions(1))

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPoolStopped)
}

func TestReloadDiscardsInFlightOldPolicyItem(t *testing.T) {
	source := newReloadBlockingReader()

	pool, err := NewPool(context.Background(), source, reloadTestTwoCharacterBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(func() {
		select {
		case source.release <- 0:
		default:
		}

		pool.Stop()
	})

	<-source.started

	err = pool.Reload(reloadTestBuildResult('b'), poolTestGenerateOptions(1))
	require.NoError(t, err)

	assert.Equal(t, uint64(2), pool.currentVersion())

	source.release <- 0

	item, err := pool.Get(context.Background())
	require.NoError(t, err)

	defer secret.Zero(item.Password)

	assert.Equal(t, []byte{'b'}, item.Password)
}

func reloadTestBuildResult(char rune) alphabet.BuildResult {
	return alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name: "letters",
				Alphabet: []rune{
					char,
				},
			},
		},
		Union: []rune{
			char,
		},
	}
}

func reloadTestTwoCharacterBuildResult() alphabet.BuildResult {
	return alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name: "letters",
				Alphabet: []rune{
					'a',
					'x',
				},
			},
		},
		Union: []rune{
			'a',
			'x',
		},
	}
}

type reloadBlockingReader struct {
	started chan struct{}
	release chan byte

	startOnce sync.Once
}

func newReloadBlockingReader() *reloadBlockingReader {
	return &reloadBlockingReader{
		started: make(chan struct{}),
		release: make(chan byte, 1),
	}
}

func (r *reloadBlockingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	r.startOnce.Do(
		func() {
			close(r.started)
		},
	)

	value := <-r.release

	p[0] = value

	return 1, nil
}