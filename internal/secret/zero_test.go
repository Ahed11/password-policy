package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZero(t *testing.T) {
	value := []byte{1, 2, 3, 4}

	Zero(value)

	assert.Equal(t, []byte{0, 0, 0, 0}, value)
}

func TestZeroEmptySlice(t *testing.T) {
	value := []byte{}

	Zero(value)

	assert.Empty(t, value)
}

func TestZeroNilSlice(t *testing.T) {
	var value []byte

	Zero(value)

	assert.Nil(t, value)
}

func TestZeroOverwritesEntireBuffer(t *testing.T) {
	value := []byte{0xff, 0x01, 0x80, 0x7f, 0xaa}

	Zero(value)

	for i, b := range value {
		assert.Equalf(t, byte(0), b, "byte at index %d was not zeroed", i)
	}
}
