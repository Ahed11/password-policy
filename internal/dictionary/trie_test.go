package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTrie(t *testing.T) {
	tree := newTrie()

	require.NotNil(t, tree)
	require.NotNil(t, tree.root)
	assert.NotNil(t, tree.root.children)
	assert.Empty(t, tree.root.children)
	assert.False(t, tree.root.terminal)
}

func TestTrieAddSingleWord(t *testing.T) {
	tree := newTrie()

	tree.add("cat")

	c, exists := tree.root.children['c']
	require.True(t, exists)
	assert.False(t, c.terminal)

	a, exists := c.children['a']
	require.True(t, exists)
	assert.False(t, a.terminal)

	end, exists := a.children['t']
	require.True(t, exists)
	assert.True(t, end.terminal)
}

func TestTrieSharedPrefix(t *testing.T) {
	tree := buildTrie([]string{
		"cat",
		"car",
	})

	c, exists := tree.root.children['c']
	require.True(t, exists)

	a, exists := c.children['a']
	require.True(t, exists)

	cat, exists := a.children['t']
	require.True(t, exists)
	assert.True(t, cat.terminal)

	car, exists := a.children['r']
	require.True(t, exists)
	assert.True(t, car.terminal)

	assert.Len(t, tree.root.children, 1)
	assert.Len(t, c.children, 1)
	assert.Len(t, a.children, 2)
}

func TestTrieWordCanBePrefixOfAnotherWord(t *testing.T) {
	tree := buildTrie([]string{
		"car",
		"cart",
	})

	c := tree.root.children['c']
	require.NotNil(t, c)

	a := c.children['a']
	require.NotNil(t, a)

	r := a.children['r']
	require.NotNil(t, r)

	assert.True(t, r.terminal)

	end := r.children['t']
	require.NotNil(t, end)

	assert.True(t, end.terminal)
}

func TestTrieUnicode(t *testing.T) {
	tree := buildTrie([]string{
		"кот",
	})

	k := tree.root.children['к']
	require.NotNil(t, k)

	o := k.children['о']
	require.NotNil(t, o)

	end := o.children['т']
	require.NotNil(t, end)

	assert.True(t, end.terminal)
}

func TestTrieDuplicateWord(t *testing.T) {
	tree := newTrie()

	tree.add("cat")
	tree.add("cat")

	c := tree.root.children['c']
	require.NotNil(t, c)

	a := c.children['a']
	require.NotNil(t, a)

	end := a.children['t']
	require.NotNil(t, end)

	assert.True(t, end.terminal)

	assert.Len(t, tree.root.children, 1)
	assert.Len(t, c.children, 1)
	assert.Len(t, a.children, 1)
	assert.Empty(t, end.children)
}

func TestTrieIgnoresEmptyWord(t *testing.T) {
	tree := newTrie()

	tree.add("")

	assert.Empty(t, tree.root.children)
	assert.False(t, tree.root.terminal)
}
