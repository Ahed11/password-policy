package strength

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
)

const rejectionSampleCount = 10_000

type rejectionEstimate struct {
	samples  int
	rejected int
	rate     float64
}

func estimateRejectionRate(source random.Source, buildResult alphabet.BuildResult, options generate.Options) (rejectionEstimate, error) {
	return estimateRejectionRateWithSamples(source, buildResult, options, rejectionSampleCount)
}

func estimateRejectionRateWithSamples(source random.Source, buildResult alphabet.BuildResult, options generate.Options, sampleCount int) (rejectionEstimate, error) {
	if sampleCount <= 0 {
		return rejectionEstimate{}, fmt.Errorf("sample count must be greater than zero, got %d", sampleCount)
	}

	estimate := rejectionEstimate{}

	for sample := 1; sample <= sampleCount; sample++ {
		result, err := generate.Sample(source, buildResult, options)
		if err != nil {
			return rejectionEstimate{}, fmt.Errorf("estimate rejection rate sample %d of %d: %w", sample, sampleCount, err)
		}

		violations, checkErr := rules.Check(result.Password, options.Rules)

		secret.Zero(result.Password)

		if checkErr != nil {
			return rejectionEstimate{}, fmt.Errorf("estimate rejection rate sample %d of %d: check rules: %w", sample, sampleCount, checkErr)
		}

		estimate.samples++

		if len(violations) > 0 {
			estimate.rejected++
		}
	}

	estimate.rate = float64(estimate.rejected) / float64(estimate.samples)

	return estimate, nil
}
