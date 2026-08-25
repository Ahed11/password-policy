package dictionary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatcherLoadAndFind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary.txt")

	err := os.WriteFile(path, []byte("admin\nroot\npassword\n"), 0600)
	require.NoError(t, err)

	matcher, err := Load(path, 4, false, false)
	require.NoError(t, err)
	require.NotNil(t, matcher)

	got := matcher.Find([]byte{'X', '7', 'a', 'd', 'm', 'i', 'n', '!'})

	assert.Equal(t, []Match{
		{
			Offset: 2,
			Length: 5,
		},
	}, got)
}

func TestMatcherCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary.txt")

	err := os.WriteFile(path, []byte("Admin\n"), 0600)
	require.NoError(t, err)

	matcher, err := Load(path, 4, true, false)
	require.NoError(t, err)

	got := matcher.Find([]byte{'X', 'A', 'D', 'M', 'I', 'N', '7'})

	assert.Equal(t, []Match{
		{
			Offset: 1,
			Length: 5,
		},
	}, got)
}

func TestMatcherLeet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary.txt")

	err := os.WriteFile(path, []byte("password\n"), 0600)
	require.NoError(t, err)

	matcher, err := Load(path, 4, false, true)
	require.NoError(t, err)

	got := matcher.Find([]byte{'X', 'p', '4', '$', '$', 'w', '0', 'r', 'd', '!'})

	assert.Equal(t, []Match{
		{
			Offset: 1,
			Length: 8,
		},
	}, got)
}

func TestMatcherFiltersShortWords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary.txt")

	err := os.WriteFile(path, []byte("cat\nadmin\n"), 0600)
	require.NoError(t, err)

	matcher, err := Load(path, 4, false, false)
	require.NoError(t, err)

	shortMatch := matcher.Find([]byte{'X', 'c', 'a', 't', 'Y'})

	longMatch := matcher.Find([]byte{'X', 'a', 'd', 'm', 'i', 'n', 'Y'})

	assert.Nil(t, shortMatch)

	assert.Equal(t, []Match{
		{
			Offset: 1,
			Length: 5,
		},
	}, longMatch)
}

func TestMatcherNoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary.txt")

	err := os.WriteFile(path, []byte("admin\nroot\n"), 0600)
	require.NoError(t, err)

	matcher, err := Load(path, 4, false, false)
	require.NoError(t, err)

	got := matcher.Find([]byte{'X', '7', 'q', 'w', 'e', '!'})

	assert.Nil(t, got)
}

func TestMatcherEmptyPath(t *testing.T) {
	matcher, err := Load("", 4, true, true)

	require.NoError(t, err)
	require.NotNil(t, matcher)

	got := matcher.Find([]byte{'a', 'd', 'm', 'i', 'n'})

	assert.Nil(t, got)
}

func TestNilMatcherFind(t *testing.T) {
	var matcher *Matcher

	got := matcher.Find([]byte{'a', 'd', 'm', 'i', 'n'})

	assert.Nil(t, got)
}
