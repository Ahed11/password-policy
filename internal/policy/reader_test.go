package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodePolicyData(t *testing.T) {
	tests := []struct{
		name string
		policy []byte
		wantContains []string
	}{
		{
			name: "duplicate_key_on_higher_level",
			policy: []byte(`
version: 1
policy:
    name: first
    name: second`),
			wantContains: []string{
				"line 5",
				"mapping key \"name\" already defined",
			},
		},
		{
			name: "duplicate_key_on_deeper_level",
			policy: []byte(`
version: 1
issue:
    history:
        window: 5
        window: 10`),
		wantContains: []string{
			"line 6",
			"mapping key \"window\" already defined",
		},
		},
		{
			name: "unknown_field_nested",
			policy: []byte(`
version: 1
policy:
    name: test
    length:
        min: 12
        max: 20
        foo: 100`),
		wantContains: []string{
			"\"field foo not found in type policy.Length\"",
		},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodePolicyData(test.policy, FormatYAML)

			if err == nil {
				t.Fatalf("expected error, recieved nil")
			}

			for _, er := range test.wantContains {
				assert.ErrorContains(t, err, er)
			}
		})
	}
}