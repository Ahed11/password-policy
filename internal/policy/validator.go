package policy

import (
	"fmt"
	"regexp"
)

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
		}
	}

	if errors != nil {
		return errors
	}

	return nil
}
