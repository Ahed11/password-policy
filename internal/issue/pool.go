package issue

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/secret"
)

var ErrPoolStopped = errors.New("issue_pool_stopped")

type PoolItem struct {
	Password []byte
	Attempts int
}

type poolEvent struct {
	item    PoolItem
	err     error
	version uint64
}

type Pool struct {
	ctx    context.Context
	cancel context.CancelFunc

	events chan poolEvent
	slots  chan struct{}

	configMu sync.RWMutex
	config   poolConfig

	wg sync.WaitGroup

	stopOnce sync.Once
	stopDone chan struct{}
}

func NewPool(parent context.Context, source random.Source, buildResult alphabet.BuildResult, options generate.Options, size int) (*Pool, error) {
	if parent == nil {
		return nil, fmt.Errorf("create issue pool: context must not be nil")
	}

	if source == nil {
		return nil, fmt.Errorf("create issue pool: random source must not be nil")
	}

	if size <= 0 {
		return nil, fmt.Errorf("create issue pool: size must be greater than zero, got %d", size)
	}

	if options.Attempts <= 0 {
		return nil, fmt.Errorf("create issue pool: attempts must be greater than zero, got %d", options.Attempts)
	}

	if err := parent.Err(); err != nil {
		return nil, fmt.Errorf("create issue pool: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)

	pool := &Pool{
		ctx:    ctx,
		cancel: cancel,

		events: make(chan poolEvent, size),

		slots: make(chan struct{}, size),

		config: poolConfig{
			buildResult: buildResult,
			options:     options,
			version:     1,
		},

		stopDone: make(chan struct{}),
	}

	for i := 0; i < size; i++ {
		pool.slots <- struct{}{}
	}

	pool.wg.Add(1)

	go pool.run(source)

	return pool, nil
}

func (p *Pool) Get(ctx context.Context) (PoolItem, error) {
	if p == nil {
		return PoolItem{}, fmt.Errorf("get password from issue pool: pool must not be nil")
	}

	if ctx == nil {
		return PoolItem{}, fmt.Errorf("get password from issue pool: context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return PoolItem{}, fmt.Errorf("get password from issue pool: %w", err)
	}

	if err := p.ctx.Err(); err != nil {
		return PoolItem{}, fmt.Errorf("get password from issue pool: %w", ErrPoolStopped)
	}

	for {
		select {
		case <-ctx.Done():
			return PoolItem{}, fmt.Errorf("get password from issue pool: %w", ctx.Err())

		case <-p.ctx.Done():
			return PoolItem{}, fmt.Errorf("get password from issue pool: %w", ErrPoolStopped)

		case event, ok := <-p.events:
			if !ok {
				return PoolItem{}, fmt.Errorf("get password from issue pool: %w", ErrPoolStopped)
			}

			p.configMu.RLock()

			if event.version != p.config.version {
				p.configMu.RUnlock()

				if event.item.Password != nil {
					secret.Zero(event.item.Password)

					p.slots <- struct{}{}
				}

				continue
			}

			if event.err != nil {
				p.configMu.RUnlock()

				return PoolItem{}, fmt.Errorf("get password from issue pool: %w", event.err)
			}

			p.slots <- struct{}{}

			p.configMu.RUnlock()

			return event.item, nil
		}
	}
}

func (p *Pool) Stop() {
	if p == nil {
		return
	}

	p.stopOnce.Do(
		func() {
			p.cancel()

			p.wg.Wait()

			for event := range p.events {
				if event.item.Password != nil {
					secret.Zero(event.item.Password)
				}
			}

			close(p.stopDone)
		},
	)

	<-p.stopDone
}

func (p *Pool) currentConfig() poolConfig {
	p.configMu.RLock()
	defer p.configMu.RUnlock()

	return p.config
}

func (p *Pool) currentVersion() uint64 {
	p.configMu.RLock()
	defer p.configMu.RUnlock()

	return p.config.version
}

func (p *Pool) run(source random.Source) {
	defer p.wg.Done()
	defer close(p.events)

	for {
		select {
		case <-p.ctx.Done():
			return

		case <-p.slots:
		}

		config := p.currentConfig()

		item, err := generatePoolItem(p.ctx, source, config.buildResult, config.options)
		if err != nil {
			p.slots <- struct{}{}

			if p.ctx.Err() != nil {
				return
			}

			if p.currentVersion() != config.version {
				continue
			}

			p.configMu.RLock()

			if p.config.version != config.version {
				p.configMu.RUnlock()
				continue
			}

			select {
			case <-p.ctx.Done():
				p.configMu.RUnlock()
				return

			case p.events <- poolEvent{
				err:     fmt.Errorf("refill issue pool: %w", err),
				version: config.version,
			}:
				p.configMu.RUnlock()

				return
			}
		}

		p.configMu.RLock()

		if p.config.version != config.version {
			p.configMu.RUnlock()

			secret.Zero(item.Password)

			p.slots <- struct{}{}

			continue
		}

		select {
		case <-p.ctx.Done():
			p.configMu.RUnlock()

			secret.Zero(item.Password)

			p.slots <- struct{}{}

			return

		case p.events <- poolEvent{
			item:    item,
			version: config.version,
		}:
			p.configMu.RUnlock()
		}
	}
}

func generatePoolItem(ctx context.Context, source random.Source, buildResult alphabet.BuildResult, options generate.Options) (PoolItem, error) {
	for attempt := 1; attempt <= options.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return PoolItem{}, err
		}

		result, err := generate.GenerateAttempt(source, buildResult, options)
		if err != nil {
			return PoolItem{}, fmt.Errorf("generate candidate on attempt %d: %w", attempt, err)
		}

		if !result.Accepted {
			continue
		}

		if err := ctx.Err(); err != nil {
			secret.Zero(result.Password)

			return PoolItem{}, err
		}

		return PoolItem{
			Password: result.Password,
			Attempts: attempt,
		}, nil
	}

	return PoolItem{}, fmt.Errorf("%w: exhausted %d attempts", generate.ErrPolicyTooStrict, options.Attempts)
}
