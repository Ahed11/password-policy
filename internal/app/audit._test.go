package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditEmptyInput(t *testing.T) {
	prepared := auditTestPrepared()

	result, err := Audit(context.Background(), strings.NewReader(""), prepared, AuditOptions{})

	require.NoError(t, err)

	assert.Equal(t, "test-policy", result.Policy)
	assert.Equal(t, 0, result.Checked)
	assert.Equal(t, 0, result.Passed)
	assert.Equal(t, 0, result.Failed)
	assert.Empty(t, result.Subjects)
	assert.Empty(t, result.LineErrors)
}

func TestAuditPassedAndFailedSubjects(t *testing.T) {
	prepared := auditTestPrepared()

	input := strings.NewReader("{\"subject\":\"svc-01\",\"password\":\"a1\"}\n" + "{\"subject\":\"svc-02\",\"password\":\"ab\"}\n")

	result, err := Audit(context.Background(), input, prepared, AuditOptions{})

	require.NoError(t, err)

	assert.Equal(t, 2, result.Checked)
	assert.Equal(t, 1, result.Passed)
	assert.Equal(t, 1, result.Failed)
	assert.Empty(t, result.LineErrors)

	assert.Equal(t, []AuditSubject{
		{
			Subject: "svc-01",
			Passed:  true,
			Rules:   []string{},
		},
		{
			Subject: "svc-02",
			Passed:  false,
			Rules: []string{
				"class.digits",
			},
		},
	}, result.Subjects)
}

func TestAuditMalformedJSONContinues(t *testing.T) {
	prepared := auditTestPrepared()

	input := strings.NewReader("{\"subject\":\"svc-01\",\"password\":\"a1\"}\n" + "this is not json\n" + "{\"subject\":\"svc-02\",\"password\":\"b2\"}\n")

	result, err := Audit(context.Background(), input, prepared, AuditOptions{Strict: false})

	require.NoError(t, err)

	assert.Equal(t, 2, result.Checked)
	assert.Equal(t, 2, result.Passed)
	assert.Equal(t, 0, result.Failed)

	require.Len(t, result.Subjects, 2)
	assert.Equal(t, "svc-01", result.Subjects[0].Subject)
	assert.Equal(t, "svc-02", result.Subjects[1].Subject)

	require.Len(t, result.LineErrors, 1)

	assert.Equal(t, 2, result.LineErrors[0].Line)
	assert.Contains(t, result.LineErrors[0].Message, "decode JSON")
}

func TestAuditMalformedJSONStrict(t *testing.T) {
	prepared := auditTestPrepared()

	input := strings.NewReader("{\"subject\":\"svc-01\",\"password\":\"a1\"}\n" + "this is not json\n" + "{\"subject\":\"svc-02\",\"password\":\"b2\"}\n")

	result, err := Audit(context.Background(), input, prepared, AuditOptions{Strict: true})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "audit line 2")

	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 1, result.Passed)
	assert.Equal(t, 0, result.Failed)

	require.Len(t, result.Subjects, 1)
	assert.Equal(t, "svc-01", result.Subjects[0].Subject)

	require.Len(t, result.LineErrors, 1)
	assert.Equal(t, 2, result.LineErrors[0].Line)
}

func TestAuditLastLineWithoutNewline(t *testing.T) {
	prepared := auditTestPrepared()

	input := strings.NewReader("{\"subject\":\"svc-01\",\"password\":\"a1\"}")

	result, err := Audit(context.Background(), input, prepared, AuditOptions{})

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 1, result.Passed)
	assert.Equal(t, 0, result.Failed)

	require.Len(t, result.Subjects, 1)

	assert.Equal(t, AuditSubject{
		Subject: "svc-01",
		Passed:  true,
		Rules:   []string{},
	}, result.Subjects[0])
}

func TestAuditMissingSubject(t *testing.T) {
	result, err := Audit(context.Background(), strings.NewReader("{\"password\":\"a1\"}\n"), auditTestPrepared(), AuditOptions{})

	require.NoError(t, err)

	assert.Equal(t, 0, result.Checked)

	require.Len(t, result.LineErrors, 1)
	assert.Equal(t, 1, result.LineErrors[0].Line)
	assert.Contains(t, result.LineErrors[0].Message, "missing subject field")
}

func TestAuditMissingPassword(t *testing.T) {
	result, err := Audit(context.Background(), strings.NewReader("{\"subject\":\"svc-01\"}\n"), auditTestPrepared(), AuditOptions{})

	require.NoError(t, err)

	assert.Equal(t, 0, result.Checked)

	require.Len(t, result.LineErrors, 1)
	assert.Equal(t, 1, result.LineErrors[0].Line)
	assert.Contains(t, result.LineErrors[0].Message, "missing password field")
}

func TestAuditCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Audit(ctx, strings.NewReader("{\"subject\":\"svc-01\",\"password\":\"a1\"}\n"), auditTestPrepared(), AuditOptions{})

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, AuditResult{}, result)
}

func TestAuditDoesNotExposePassword(t *testing.T) {
	const password = "a1"

	result, err := Audit(context.Background(), strings.NewReader("{\"subject\":\"svc-01\",\"password\":\""+password+"\"}\n"), auditTestPrepared(), AuditOptions{})

	require.NoError(t, err)

	data, err := json.Marshal(result)
	require.NoError(t, err)

	assert.NotContains(t, string(data), `"Password"`)

	assert.NotContains(t, string(data), `"password"`)
}

func TestAuditViolatedRulesStableOrder(t *testing.T) {
	evaluation := rules.Evaluation{
		Length: rules.LengthResult{
			Passed: false,
		},
		Classes: []rules.ClassResult{
			{
				Name:   "lower",
				Passed: true,
			},
			{
				Name:   "digits",
				Passed: false,
			},
		},
		Violations: []rules.Violation{
			{
				Rule:   "repeat_run",
				Offset: 0,
				Length: 3,
			},
			{
				Rule:   "repeat_run",
				Offset: 4,
				Length: 3,
			},
			{
				Rule:   "dictionary",
				Offset: 8,
				Length: 5,
			},
		},
	}

	got := auditViolatedRules(evaluation)

	assert.Equal(t, []string{"length", "class.digits", "repeat_run", "dictionary"}, got)
}

func TestDecodeAuditJSONStringEscapes(t *testing.T) {
	got, err := decodeJSONStringBytes([]byte(`"a\n\t\"\\b"`))

	require.NoError(t, err)

	assert.Equal(t, []byte{'a', '\n', '\t', '"', '\\', 'b'}, got)
}

func TestDecodeAuditJSONStringUnicode(t *testing.T) {
	got, err := decodeJSONStringBytes([]byte(`"\u043A\u043E\u0442"`))

	require.NoError(t, err)

	assert.Equal(t, []byte("кот"), got)
}

func TestDecodeAuditJSONStringSurrogatePair(t *testing.T) {
	got, err := decodeJSONStringBytes([]byte(`"\uD83D\uDE00"`))

	require.NoError(t, err)

	assert.Equal(t, []byte("😀"), got)
}

func TestAuditUnicodePassword(t *testing.T) {
	classMinimums := map[string]int{
		"unicode": 2,
	}

	ruleOptions := rules.Options{}

	prepared := Prepared{
		Alphabet: alphabet.BuildResult{
			Classes: []alphabet.Class{
				{
					Name: "unicode",
					Alphabet: []rune{
						'к',
						'о',
						'😀',
					},
				},
			},
			Union: []rune{
				'к',
				'о',
				'😀',
			},
		},
		ClassMinimums: classMinimums,
		Rules:         ruleOptions,
		Generate: generate.Options{
			MinLength:     2,
			MaxLength:     2,
			Attempts:      1,
			ClassMinimums: classMinimums,
			Rules:         ruleOptions,
		},
	}

	input := bytes.NewBufferString("{\"subject\":\"unicode-test\"," + "\"password\":\"\\u043A\\uD83D\\uDE00\"}\n")

	result, err := Audit(context.Background(), input, prepared, AuditOptions{})

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 1, result.Passed)
	assert.Equal(t, 0, result.Failed)

	require.Len(t, result.Subjects, 1)
	assert.True(t, result.Subjects[0].Passed)
}

func auditTestPrepared() Prepared {
	prepared := checkTestPrepared()

	prepared.Config.Policy.Name = "test-policy"

	return prepared
}
