package issue

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/secret"
)

type poolConfig struct {
	buildResult alphabet.BuildResult
	options     generate.Options
	version     uint64
}

func (p *Pool) Reload(buildResult alphabet.BuildResult, options generate.Options) error {
	if p == nil {
		return fmt.Errorf("reload issue pool: pool must not be nil")
	}

	if options.Attempts <= 0 {
		return fmt.Errorf("reload issue pool: attempts must be greater than zero, got %d", options.Attempts)
	}

	if err := p.ctx.Err(); err != nil {
		return fmt.Errorf("reload issue pool: %w", ErrPoolStopped)
	}

	p.configMu.Lock()
	defer p.configMu.Unlock()

	if err := p.ctx.Err(); err != nil {
		return fmt.Errorf("reload issue pool: %w", ErrPoolStopped)
	}

	for {
		select {
		case event, ok := <-p.events:
			if !ok {
				return fmt.Errorf("reload issue pool: %w", ErrPoolStopped)
			}

			if event.item.Password != nil {
				secret.Zero(event.item.Password)

				p.slots <- struct{}{}
			}

		default:
			p.config = poolConfig{
				buildResult: buildResult,
				options:     options,
				version:     p.config.version + 1,
			}

			return nil
		}
	}
}
