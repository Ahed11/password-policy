package strength

import (
	"fmt"
	"math/big"

	"github.com/Ahed11/password-policy/internal/alphabet"
)

func countOutcomes(buildResult alphabet.BuildResult, minLength int, maxLength int, classMinimums map[string]int, repeatTotal bool) (*big.Int, error) {
	if minLength <= 0 {
		return nil, fmt.Errorf("minimum length must be greater than zero, got %d", minLength)
	}

	if maxLength < minLength {
		return nil, fmt.Errorf("maximum length %d is less than minimum length %d", maxLength, minLength)
	}

	dp := make([]*big.Int, maxLength+1)
	dp[0] = big.NewInt(1)

	for _, class := range buildResult.Classes {
		minimum, ok := classMinimums[class.Name]
		if !ok {
			return nil, fmt.Errorf("missing minimum for class %q", class.Name)
		}

		if minimum < 0 {
			return nil, fmt.Errorf("minimum for class %q must not be negative, got %d", class.Name, minimum)
		}

		next := make([]*big.Int, maxLength+1)
		alphabetSize := len(class.Alphabet)

		for used, currentWays := range dp {
			if currentWays == nil || currentWays.Sign() == 0 {
				continue
			}

			maxCount := maxLength - used

			if repeatTotal && maxCount > alphabetSize {
				maxCount = alphabetSize
			}

			for count := minimum; count <= maxCount; count++ {
				classWays := countClassWays(alphabetSize, count, repeatTotal)

				if classWays.Sign() == 0 {
					continue
				}

				positions := new(big.Int).Binomial(int64(used+count), int64(count))

				ways := new(big.Int).Mul(currentWays, positions)

				ways.Mul(ways, classWays)

				totalLength := used + count

				if next[totalLength] == nil {
					next[totalLength] = new(big.Int)
				}

				next[totalLength].Add(next[totalLength], ways)
			}
		}

		dp = next
	}

	total := new(big.Int)

	for length := minLength; length <= maxLength; length++ {
		if dp[length] == nil {
			continue
		}

		total.Add(total, dp[length])
	}

	return total, nil
}

func countClassWays(alphabetSize int, count int, repeatTotal bool) *big.Int {
	if count < 0 {
		return new(big.Int)
	}

	if !repeatTotal {
		return new(big.Int).Exp(big.NewInt(int64(alphabetSize)), big.NewInt(int64(count)), nil)
	}

	if count > alphabetSize {
		return new(big.Int)
	}

	if count == 0 {
		return big.NewInt(1)
	}

	return new(big.Int).MulRange(int64(alphabetSize-count+1), int64(alphabetSize))
}
