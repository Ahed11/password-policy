package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr []string
	}{
		{
			name:    "correct_config",
			modify:  func(c *Config) {},
			wantErr: []string{},
		},
		{
			name: "invalid_version_1",
			modify: func(c *Config) {
				c.Version = 0
			},
			wantErr: []string{
				"version: must be 1, got 0",
			},
		},
		{
			name: "invalid_version_2",
			modify: func(c *Config) {
				c.Version = 2
			},
			wantErr: []string{
				"version: must be 1, got 2",
			},
		},
		{
			name: "empty_name",
			modify: func(c *Config) {
				c.Policy.Name = ""
			},
			wantErr: []string{
				"policy.name: required",
			},
		},
		{
			name: "invalid_character_in_name",
			modify: func(c *Config) {
				c.Policy.Name = "service account"
			},
			wantErr: []string{
				"policy.name: contains invalid characters",
			},
		},
		{
			name: "empty_classes",
			modify: func(c *Config) {
				c.Policy.Classes = nil
			},
			wantErr: []string{
				"policy.classes: must not be empty",
			},
		},
		{
			name: "duplicate_class_names",
			modify: func(c *Config) {
				c.Policy.Classes[0].Name = "digits"
				c.Policy.Classes[1].Name = "lower"
				c.Policy.Classes[2].Name = "digits"
			},
			wantErr: []string{
				"policy.classes: duplicate class name \"digits\"",
			},
		},
		{
			name: "multiple_errors",
			modify: func(c *Config) {
				c.Version = 2
				c.Policy.Name = ""
				c.Policy.Classes = nil
			},
			wantErr: []string{
				"version: must be 1, got 2",
				"policy.name: required",
				"policy.classes: must not be empty",
			},
		},
		{
			name: "length_min_zero",
			modify: func(c *Config) {
				c.Policy.Length.Min = 0
			},
			wantErr: []string{
				"policy.length.min: must be greater than 0",
			},
		},
		{
			name: "length_min_negative",
			modify: func(c *Config) {
				c.Policy.Length.Min = -1
			},
			wantErr: []string{
				"policy.length.min: must be greater than 0",
			},
		},
		{
			name: "length_max_zero",
			modify: func(c *Config) {
				c.Policy.Length.Max = 0
			},
			wantErr: []string{
				"policy.length.max: must be greater than 0",
				"policy.length.max: must be greater than or equal to length.min",
			},
		},
		{
			name: "length_max_negative",
			modify: func(c *Config) {
				c.Policy.Length.Max = -1
			},
			wantErr: []string{
				"policy.length.max: must be greater than 0",
				"policy.length.max: must be greater than or equal to length.min",
			},
		},
		{
			name: "length_min_greater_than_max",
			modify: func(c *Config) {
				c.Policy.Length.Min = 20
				c.Policy.Length.Max = 10
			},
			wantErr: []string{
				"policy.length.max: must be greater than or equal to length.min",
			},
		},
		{
			name: "length_min_equals_max",
			modify: func(c *Config) {
				c.Policy.Length.Min = 12
				c.Policy.Length.Max = 12
			},
			wantErr: []string{},
		},
		{
			name: "attempts_zero",
			modify: func(c *Config) {
				c.Policy.Attempts = 0
			},
			wantErr: []string{
				"policy.attempts: must be greater than 0",
			},
		},
		{
			name: "attempts_negative",
			modify: func(c *Config) {
				c.Policy.Attempts = -1
			},
			wantErr: []string{
				"policy.attempts: must be greater than 0",
			},
		},
		{
			name: "attempts_one",
			modify: func(c *Config) {
				c.Policy.Attempts = 1
			},
			wantErr: []string{},
		},
		{
			name: "class_min_negative",
			modify: func(c *Config) {
				c.Policy.Classes[0].Min = -1
			},
			wantErr: []string{
				"policy.classes[\"digits\"].min: must be greater than or equal to 0",
			},
		},
		{
			name: "class_min_zero",
			modify: func(c *Config) {
				c.Policy.Classes[1].Min = 0
			},
			wantErr: []string{},
		},
		{
			name: "multiple_numeric_errors",
			modify: func(c *Config) {
				c.Policy.Length.Min = 0
				c.Policy.Length.Max = 1
				c.Policy.Attempts = 0
				c.Policy.Classes[1].Min = -1
			},
			wantErr: []string{
				"policy.classes[\"lower\"].min: must be greater than or equal to 0",
				"policy.length.min: must be greater than 0",
				"policy.attempts: must be greater than 0",
			},
		},
		{
			name: "valid_ttl_and_rotate_after",
			modify: func(c *Config) {
				c.Issue.History.Ttl = "180d"
				c.Issue.RotateAfter = "90d"
			},
			wantErr: []string{},
		},
		{
			name: "invalid_ttl",
			modify: func(c *Config) {
				c.Issue.History.Ttl = "10x"
			},
			wantErr: []string{
				"issue.history.ttl: unknown suffix: \"x\"",
			},
		},
		{
			name: "invalid_rotate_after",
			modify: func(c *Config) {
				c.Issue.RotateAfter = "5q"
			},
			wantErr: []string{
				"issue.rotate_after: unknown suffix: \"q\"",
			},
		},
		{
			name: "empty_ttl",
			modify: func(c *Config) {
				c.Issue.History.Ttl = ""
			},
			wantErr: []string{
				"issue.history.ttl: empty input",
			},
		},
		{
			name: "empty_rotate_after",
			modify: func(c *Config) {
				c.Issue.RotateAfter = ""
			},
			wantErr: []string{
				"issue.rotate_after: empty input",
			},
		},
		{
			name: "multiple_duration_errors",
			modify: func(c *Config) {
				c.Issue.History.Ttl = "10x"
				c.Issue.RotateAfter = "5q"
			},
			wantErr: []string{
				"issue.history.ttl: unknown suffix: \"x\"",
				"issue.rotate_after: unknown suffix: \"q\"",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{
				Version: 1,
				Policy: Policy{
					Name: "service-accounts",
					Length: Length{
						Min: 12,
						Max: 12,
					},
					Classes: []Class{
						{
							Name:     "digits",
							Alphabet: "0123456789",
							Min:      2,
						},
						{
							Name:     "lower",
							Alphabet: "abcdefghijklmnopqrstuvwxyz",
							Min:      2,
						},
						{
							Name:     "upper",
							Alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
							Min:      2,
						},
						{
							Name:     "special",
							Alphabet: "!@#$%^&*()-_=+[]{};:,.?",
							Min:      1,
						},
					},
					Attempts: 100,
				},
				Issue: Issue{
					History: History{
						Ttl: "0s",
					},
					RotateAfter: "0s",
				},
			}

			test.modify(&config)

			errors := ValidatePolicy(config)

			var messages = []string{}

			for _, e := range errors {
				if e != nil {
					messages = append(messages, e.Error())
				}
			}

			assert.Equal(t, test.wantErr, messages, "errors received don't match the expected")
		})
	}
}

func TestParsePolicyDuration(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantDuration time.Duration
		wantErr      bool
		errContains  string
	}{
		{
			name:         "valid_duration_1",
			input:        "0s",
			wantDuration: 0 * time.Second,
			wantErr:      false,
			errContains:  "",
		},
		{
			name:         "valid_duration_2",
			input:        "10s",
			wantDuration: 10 * time.Second,
			wantErr:      false,
			errContains:  "",
		},
		{
			name:         "valid_duration_3",
			input:        "15m",
			wantDuration: 15 * time.Minute,
			wantErr:      false,
			errContains:  "",
		},
		{
			name:         "valid_duration_4",
			input:        "24h",
			wantDuration: 24 * time.Hour,
			wantErr:      false,
			errContains:  "",
		},
		{
			name:         "valid_duration_5",
			input:        "1d",
			wantDuration: 24 * time.Hour,
			wantErr:      false,
			errContains:  "",
		},
		{
			name:         "valid_duration_6",
			input:        "180d",
			wantDuration: 180 * 24 * time.Hour,
			wantErr:      false,
			errContains:  "",
		},
		{
			name:        "invalid_duration_1",
			input:       "",
			wantErr:     true,
			errContains: "empty input",
		},
		{
			name:        "invalid_duration_2",
			input:       "-1h",
			wantErr:     true,
			errContains: "invalid number (must be non-negative)",
		},
		{
			name:        "invalid_duration_3",
			input:       "10",
			wantErr:     true,
			errContains: "unknown suffix: \"0\"",
		},
		{
			name:        "invalid_duration_4",
			input:       "10ms",
			wantErr:     true,
			errContains: "invalid number (must be non-negative)",
		},
		{
			name:        "invalid_duration_5",
			input:       "1.5h",
			wantErr:     true,
			errContains: "invalid number (must be non-negative)",
		},
		{
			name:        "invalid_duration_6",
			input:       "1h30m",
			wantErr:     true,
			errContains: "invalid number (must be non-negative)",
		},
		{
			name:        "invalid_duration_7",
			input:       "d",
			wantErr:     true,
			errContains: "invalid number (must be non-negative)",
		},
		{
			name:        "invalid_duration_8",
			input:       "abc",
			wantErr:     true,
			errContains: "invalid number (must be non-negative)",
		},
		{
			name:        "overflow_value",
			input:       "9999999999999d",
			wantErr:     true,
			errContains: "duration is too large",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			period, err := parsePolicyDuration(test.input)

			if test.wantErr {
				assert.Error(t, err)

				if test.errContains != "" {
					assert.ErrorContains(t, err, test.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantDuration, period)
			}
		})
	}
}
