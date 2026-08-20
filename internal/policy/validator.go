package policy

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

func parsePolicyDuration(input string) (time.Duration, error) {
	if input == "" {
		return 0, fmt.Errorf("empty input")
	}

	i := len(input) - 1

	numPart := input[:i]
	suffix := input[i:]

	value, err := strconv.ParseUint(numPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number (must be non-negative): %w", err)
	}

	var unit time.Duration

	switch suffix {
	case "s":
		unit = time.Second
	case "m":
		unit = time.Minute
	case "h":
		unit = time.Hour
	case "d":
		unit = 24 * time.Hour
	default:
		return 0, fmt.Errorf("unknown suffix: %q", suffix)
	}

	maxValue := uint64(math.MaxInt64 / int64(unit))

	if value > maxValue {
		return 0, fmt.Errorf("duration is too large")
	}

	return time.Duration(value) * unit, nil
}

func ValidatePolicy(config Config) []error {
	var errors []error

	if config.Version != 1 {
		errors = append(errors, fmt.Errorf("version: must be 1, got %d", config.Version))
	}

	var validPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	if config.Policy.Name == "" {
		errors = append(errors, fmt.Errorf("policy.name: required"))
	} else if !validPattern.MatchString(config.Policy.Name) {
		errors = append(errors, fmt.Errorf("policy.name: contains invalid characters"))
	}

	if len(config.Policy.Classes) == 0 {
		errors = append(errors, fmt.Errorf("policy.classes: must not be empty"))
	} else {
		classNames := []string{}
		for _, class := range config.Policy.Classes {
			duplicate := false
			for _, className := range classNames {
				if class.Name == className {
					errors = append(errors, fmt.Errorf("policy.classes: duplicate class name %q", class.Name))
					duplicate = true
					break
				}
			}
			if !duplicate {
				classNames = append(classNames, class.Name)
			}

			if class.Min < 0 {
				errors = append(errors, fmt.Errorf("policy.classes[%q].min: must be greater than or equal to 0", class.Name))
			}
		}
	}

	if config.Policy.Length.Min <= 0 {
		errors = append(errors, fmt.Errorf("policy.length.min: must be greater than 0"))
	}

	if config.Policy.Length.Max <= 0 {
		errors = append(errors, fmt.Errorf("policy.length.max: must be greater than 0"))
	}
	if config.Policy.Length.Max < config.Policy.Length.Min {
		errors = append(errors, fmt.Errorf("policy.length.max: must be greater than or equal to length.min"))
	}

	if config.Policy.Attempts <= 0 {
		errors = append(errors, fmt.Errorf("policy.attempts: must be greater than 0"))
	}

	if _, ttlErr := parsePolicyDuration(config.Issue.History.Ttl); ttlErr != nil {
		errors = append(errors, fmt.Errorf("issue.history.ttl: %w", ttlErr))
	}

	if _, rotateAfterErr := parsePolicyDuration(config.Issue.RotateAfter); rotateAfterErr != nil {
		errors = append(errors, fmt.Errorf("issue.rotate_after: %w", rotateAfterErr))
	}

	return errors
}
