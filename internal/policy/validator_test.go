package policy

import (
	"testing"
	
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{
				Version: 1,
				Policy: Policy{
					Name: "service-accounts",
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
							Name: "upper",
							Alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
							Min: 2,
						},
						{
							Name: "special",
							Alphabet: "!@#$%^&*()-_=+[]{};:,.?",
							Min: 1,
						},
					},
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
