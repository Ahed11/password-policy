package issue

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPool(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 2)

	require.NoError(t, err)
	require.NotNil(t, pool)

	t.Cleanup(pool.Stop)

	assert.Equal(t, 2, cap(pool.events))
	assert.Equal(t, 2, cap(pool.slots))
}

func TestNewPoolNilContext(t *testing.T) {
	var ctx context.Context

	pool, err := NewPool(ctx, bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "context must not be nil")

	assert.Nil(t, pool)
}

func TestNewPoolNilSource(t *testing.T) {
	pool, err := NewPool(context.Background(), nil, poolTestBuildResult(), poolTestGenerateOptions(1), 1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "random source must not be nil")

	assert.Nil(t, pool)
}

func TestNewPoolInvalidSize(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 0)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "size must be greater than zero")

	assert.Nil(t, pool)
}

func TestNewPoolInvalidAttempts(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(0), 1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "attempts must be greater than zero")

	assert.Nil(t, pool)
}

func TestNewPoolCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	pool, err := NewPool(ctx, bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Nil(t, pool)
}

func TestPoolGet(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	item, err := pool.Get(context.Background())

	require.NoError(t, err)
	defer secret.Zero(item.Password)

	assert.Equal(t, []byte{'a'}, item.Password)

	assert.Equal(t, 1, item.Attempts)
}

func TestPoolRefillsAfterGet(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	first, err := pool.Get(context.Background())
	require.NoError(t, err)

	defer secret.Zero(first.Password)

	second, err := pool.Get(context.Background())
	require.NoError(t, err)

	defer secret.Zero(second.Password)

	assert.Equal(t, []byte{'a'}, first.Password)

	assert.Equal(t, []byte{'a'}, second.Password)

	assert.Equal(t, 1, first.Attempts)
	assert.Equal(t, 1, second.Attempts)
}

func TestPoolRespectsConfiguredSize(t *testing.T) {
	const size = 3

	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), size)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	events := make([]poolEvent, 0, size)

	for i := 0; i < size; i++ {
		event := <-pool.events

		require.NoError(t, event.err)
		require.NotNil(t, event.item.Password)

		events = append(events, event)
	}

	assert.Equal(t, 0, len(pool.slots))

	for _, event := range events {
		secret.Zero(event.item.Password)
	}
}

func TestPoolGetCanceledContext(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	item, err := pool.Get(ctx)

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, PoolItem{}, item)
}

func TestPoolGetNilContext(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	var ctx context.Context

	item, err := pool.Get(ctx)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "context must not be nil")

	assert.Equal(t, PoolItem{}, item)
}

func TestPoolGetNilPool(t *testing.T) {
	var pool *Pool

	item, err := pool.Get(context.Background())

	assert.Error(t, err)
	assert.ErrorContains(t, err, "pool must not be nil")

	assert.Equal(t, PoolItem{}, item)
}

func TestPoolGenerationErrorIsExposed(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestTwoCharacterBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	item, err := pool.Get(context.Background())

	assert.Error(t, err)
	assert.ErrorIs(t, err, io.EOF)

	assert.ErrorContains(t, err, "refill issue pool")

	assert.Equal(t, PoolItem{}, item)
}

func TestPoolStopsAfterGenerationError(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestTwoCharacterBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	_, err = pool.Get(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, io.EOF)

	item, err := pool.Get(context.Background())

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPoolStopped)

	assert.Equal(t, PoolItem{}, item)
}

func TestPoolReportsActualAttempts(t *testing.T) {
	buildResult := poolTestTwoCharacterBuildResult()

	options := generate.Options{
		MinLength: 1,
		MaxLength: 1,
		Attempts:  2,
		ClassMinimums: map[string]int{
			"letters": 1,
		},
		Rules: rules.Options{
			ContextValues: []string{
				"a",
			},
			ContextMinLength: 1,
		},
	}

	source := bytes.NewReader([]byte{0, 128})

	pool, err := NewPool(context.Background(), source, buildResult, options, 1)
	require.NoError(t, err)

	t.Cleanup(pool.Stop)

	item, err := pool.Get(context.Background())

	require.NoError(t, err)
	defer secret.Zero(item.Password)

	assert.Equal(t, []byte{'b'}, item.Password)

	assert.Equal(t, 2, item.Attempts)
}

func TestPoolStop(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	pool.Stop()

	item, err := pool.Get(context.Background())

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPoolStopped)

	assert.Equal(t, PoolItem{}, item)
}

func TestPoolStopDoesNotLeakGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()

	pool, err := NewPool(
		context.Background(),
		bytes.NewReader(nil),
		poolTestBuildResult(),
		poolTestGenerateOptions(1),
		1,
	)
	require.NoError(t, err)

	pool.Stop()

	after := runtime.NumGoroutine()

	for i := 0; i < 10_000 && after > baseline; i++ {
		runtime.Gosched()

		after = runtime.NumGoroutine()
	}

	assert.LessOrEqual(t, after, baseline)
}

func TestPoolStopTwice(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	pool.Stop()
	pool.Stop()
}

func TestPoolStopNilPool(t *testing.T) {
	var pool *Pool

	assert.NotPanics(
		t,
		func() {
			pool.Stop()
		},
	)
}

func TestPoolStopWipesBufferedPassword(t *testing.T) {
	pool, err := NewPool(context.Background(), bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	event := <-pool.events

	require.NoError(t, event.err)
	require.NotNil(t, event.item.Password)

	password := event.item.Password

	assert.Equal(t, []byte{'a'}, password)

	pool.events <- event

	pool.Stop()

	assert.Equal(t, []byte{0}, password)
}

func TestPoolParentCancellationStopsPool(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())

	pool, err := NewPool(parent, bytes.NewReader(nil), poolTestBuildResult(), poolTestGenerateOptions(1), 1)
	require.NoError(t, err)

	cancel()

	item, err := pool.Get(context.Background())

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPoolStopped)

	assert.Equal(t, PoolItem{}, item)

	pool.Stop()
}

func poolTestBuildResult() alphabet.BuildResult {
	return alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a'},
			},
		},
		Union: []rune{'a'},
	}
}

func poolTestTwoCharacterBuildResult() alphabet.BuildResult {
	return alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}
}

func poolTestGenerateOptions(attempts int) generate.Options {
	return generate.Options{
		MinLength: 1,
		MaxLength: 1,
		Attempts:  attempts,
		ClassMinimums: map[string]int{
			"letters": 1,
		},
		Rules: rules.Options{},
	}
}
