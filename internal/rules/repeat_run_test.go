package rules

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestCheckRepeatRun(t *testing.T) {
	tests := []struct {
		name      string
		password  []byte
		repeatRun int
		want      []repeatRunViolation
	}{
		{
			name:      "disabled",
			password:  []byte{'a', 'a', 'a'},
			repeatRun: 0,
			want:      nil,
		},
		{
			name:      "empty_password",
			password:  nil,
			repeatRun: 2,
			want:      nil,
		},
		{
			name:      "run_exactly_at_limit",
			password:  []byte{'a', 'a', 'b', 'b', 'c', 'c'},
			repeatRun: 2,
			want:      nil,
		},
		{
			name:      "violation_at_beginning",
			password:  []byte{'a', 'a', 'a', 'b', 'c'},
			repeatRun: 2,
			want: []repeatRunViolation{
				{
					offset: 0,
					length: 3,
				},
			},
		},
		{
			name:      "violation_in_middle",
			password:  []byte{'a', 'b', 'b', 'b', 'c'},
			repeatRun: 2,
			want: []repeatRunViolation{
				{
					offset: 1,
					length: 3,
				},
			},
		},
		{
			name:      "violation_at_end",
			password:  []byte{'a', 'b', 'c', 'c', 'c'},
			repeatRun: 2,
			want: []repeatRunViolation{
				{
					offset: 2,
					length: 3,
				},
			},
		},
		{
			name:      "long_run_reports_full_length",
			password:  []byte{'a', 'a', 'a', 'a', 'b'},
			repeatRun: 2,
			want: []repeatRunViolation{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:      "multiple_violations",
			password:  []byte{'a', 'a', 'a', 'b', 'c', 'c', 'c', 'd', 'd', 'd', 'd', 'd'},
			repeatRun: 2,
			want: []repeatRunViolation{
				{
					offset: 0,
					length: 3,
				},
				{
					offset: 4,
					length: 3,
				},
				{
					offset: 7,
					length: 5,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := checkRepeatRun(test.password, test.repeatRun)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestCheckRepeatRunUnicode(t *testing.T) {
	var password []byte

	for _, r := range []rune{'a', '😀', '😀', '😀', 'b'} {
		password = utf8.AppendRune(password, r)
	}

	got := checkRepeatRun(password, 2)

	assert.Equal(t, []repeatRunViolation{
		{
			offset: 1,
			length: 3,
		},
	}, got)
}
