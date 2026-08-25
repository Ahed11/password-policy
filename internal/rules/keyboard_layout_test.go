package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKeyboardLayout(t *testing.T) {
	tests := []struct {
		name       string
		layoutName string
		want       keyboardLayout
		wantFound  bool
	}{
		{
			name:       "qwerty",
			layoutName: "qwerty",
			want:       qwertyLayout,
			wantFound:  true,
		},
		{
			name:       "jcuken",
			layoutName: "jcuken",
			want:       jcukenLayout,
			wantFound:  true,
		},
		{
			name:       "unknown_layout",
			layoutName: "unknown",
			want:       keyboardLayout{},
			wantFound:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, found := getKeyboardLayout(test.layoutName)

			assert.Equal(t, test.wantFound, found)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestBuiltInKeyboardLayoutsHaveSeparateRows(t *testing.T) {
	assert.Len(t, qwertyLayout.rows, 3)
	assert.Len(t, jcukenLayout.rows, 3)

	for _, row := range qwertyLayout.rows {
		assert.NotEmpty(t, row)
	}

	for _, row := range jcukenLayout.rows {
		assert.NotEmpty(t, row)
	}
}
