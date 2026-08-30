package strength

import (
	"fmt"
	"math"
	"math/big"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/random"
)

// Estimate содержит рассчитанную нижнюю границу энтропии политики и данные использованной выборки.
type Estimate struct {
	Bits          float64
	Outcomes      *big.Int
	Samples       int
	Rejected      int
	RejectionRate float64
}

// EstimateEntropy вычисляет нижнюю границу энтропии политики с учётом оценочной доли отклонённых кандидатов.
func EstimateEntropy(source random.Source, buildResult alphabet.BuildResult, options generate.Options) (Estimate, error) {
	outcomes, err := countOutcomes(buildResult, options.MinLength, options.MaxLength, options.ClassMinimums, options.Rules.RepeatTotal)
	if err != nil {
		return Estimate{}, fmt.Errorf("count password outcomes: %w", err)
	}

	if outcomes.Sign() <= 0 {
		return Estimate{}, fmt.Errorf("password outcome count must be greater than zero")
	}

	outcomeBits, err := log2BigInt(outcomes)
	if err != nil {
		return Estimate{}, fmt.Errorf("calculate outcome entropy: %w", err)
	}

	rejection, err := estimateRejectionRate(source, buildResult, options)
	if err != nil {
		return Estimate{}, fmt.Errorf("estimate prohibition rejection rate: %w", err)
	}

	bits := outcomeBits

	switch {
	case rejection.rate >= 1:
		bits = math.Inf(-1)

	case rejection.rate > 0:
		bits += math.Log2(1 - rejection.rate)
	}

	return Estimate{
		Bits:          bits,
		Outcomes:      new(big.Int).Set(outcomes),
		Samples:       rejection.samples,
		Rejected:      rejection.rejected,
		RejectionRate: rejection.rate,
	}, nil
}

func log2BigInt(value *big.Int) (float64, error) {
	if value == nil || value.Sign() <= 0 {
		return 0, fmt.Errorf("value must be a positive integer")
	}

	const precisionBits = 53

	bitLength := value.BitLen()

	if bitLength <= precisionBits {
		return math.Log2(float64(value.Int64())), nil
	}

	shift := bitLength - precisionBits

	top := new(big.Int).Rsh(new(big.Int).Set(value), uint(shift))

	return math.Log2(float64(top.Int64())) + float64(shift), nil
}
