package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
)

type AuditOptions struct {
	Strict bool
}

type AuditSubject struct {
	Subject string
	Passed  bool
	Rules   []string
}

type AuditLineError struct {
	Line    int
	Message string
}

type AuditResult struct {
	Policy     string
	Checked    int
	Passed     int
	Failed     int
	Subjects   []AuditSubject
	LineErrors []AuditLineError
}

func Audit(ctx context.Context, input io.Reader, prepared Prepared, options AuditOptions) (AuditResult, error) {
	if ctx == nil {
		return AuditResult{}, fmt.Errorf("audit passwords: context must not be nil")
	}

	if input == nil {
		return AuditResult{}, fmt.Errorf("audit passwords: input must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return AuditResult{}, fmt.Errorf("audit passwords: %w", err)
	}

	result := AuditResult{
		Policy:     prepared.Config.Policy.Name,
		Subjects:   make([]AuditSubject, 0),
		LineErrors: make([]AuditLineError, 0),
	}

	reader := bufio.NewReader(input)
	lineNumber := 0

	for {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("audit passwords: %w", err)
		}

		line, readErr := reader.ReadBytes('\n')

		if len(line) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		if len(line) == 0 && readErr != nil {
			return result, fmt.Errorf("read audit input after line %d: %w", lineNumber, readErr)
		}

		lineNumber++

		subject, password, decodeErr := decodeAuditRecord(line)

		secret.Zero(line)

		if decodeErr != nil {
			lineError := AuditLineError{
				Line:    lineNumber,
				Message: decodeErr.Error(),
			}

			result.LineErrors = append(result.LineErrors, lineError)

			if options.Strict {
				return result, fmt.Errorf("audit line %d: %w", lineNumber, decodeErr)
			}

			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return result, fmt.Errorf("read audit input after line %d: %w", lineNumber, readErr)
			}

			if errors.Is(readErr, io.EOF) {
				break
			}

			continue
		}

		evaluation, checkErr := Check(ctx, prepared, password)

		secret.Zero(password)

		if checkErr != nil {
			return result, fmt.Errorf("audit line %d: check password: %w", lineNumber, checkErr)
		}

		violatedRules := auditViolatedRules(evaluation)

		result.Checked++

		if evaluation.Passed {
			result.Passed++
		} else {
			result.Failed++
		}

		result.Subjects = append(
			result.Subjects,
			AuditSubject{
				Subject: subject,
				Passed:  evaluation.Passed,
				Rules:   violatedRules,
			},
		)

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}

			return result, fmt.Errorf("read audit input after line %d: %w", lineNumber, readErr)
		}
	}

	return result, nil
}

func auditViolatedRules(evaluation rules.Evaluation) []string {
	result := make([]string, 0)

	if !evaluation.Length.Passed {
		result = append(result, "length")
	}

	for _, class := range evaluation.Classes {
		if class.Passed {
			continue
		}

		result = append(result, "class."+class.Name)
	}

	seen := make(map[string]struct{})

	for _, violation := range evaluation.Violations {
		if _, exists := seen[violation.Rule]; exists {
			continue
		}

		seen[violation.Rule] = struct{}{}

		result = append(result, violation.Rule)
	}

	return result
}

type auditRecord struct {
	Subject  *string       `json:"subject"`
	Password auditPassword `json:"password"`
}

type auditPassword []byte

func (p *auditPassword) UnmarshalJSON(data []byte) error {
	decoded, err := decodeJSONStringBytes(data)
	if err != nil {
		return err
	}

	*p = decoded

	return nil
}

func decodeAuditRecord(line []byte) (string, []byte, error) {
	var record auditRecord

	if err := json.Unmarshal(line, &record); err != nil {
		secret.Zero(record.Password)

		return "", nil, fmt.Errorf("decode JSON: %w", err)
	}

	if record.Subject == nil {
		secret.Zero(record.Password)

		return "", nil, fmt.Errorf("missing subject field")
	}

	if record.Password == nil {
		return "", nil, fmt.Errorf("missing password field")
	}

	return *record.Subject, []byte(record.Password), nil
}

func decodeJSONStringBytes(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, fmt.Errorf("password must be a JSON string")
	}

	end := len(data) - 1

	result := make([]byte, 0, len(data)-2)

	for i := 1; i < end; {
		b := data[i]

		if b != '\\' {
			if b < utf8.RuneSelf {
				if b < 0x20 || b == '"' {
					secret.Zero(result)

					return nil, fmt.Errorf("password contains invalid JSON string data")
				}

				result = append(result, b)
				i++

				continue
			}

			r, size := utf8.DecodeRune(data[i:end])

			if r == utf8.RuneError && size == 1 {
				secret.Zero(result)

				return nil, fmt.Errorf("password contains invalid UTF-8")
			}

			result = append(result, data[i:i+size]...)

			i += size

			continue
		}

		i++

		if i >= end {
			secret.Zero(result)

			return nil, fmt.Errorf("password contains incomplete JSON escape")
		}

		escape := data[i]
		i++

		switch escape {
		case '"', '\\', '/':
			result = append(result, escape)

		case 'b':
			result = append(result, '\b')

		case 'f':
			result = append(result, '\f')

		case 'n':
			result = append(result, '\n')

		case 'r':
			result = append(result, '\r')

		case 't':
			result = append(result, '\t')

		case 'u':
			if i+4 > end {
				secret.Zero(result)

				return nil, fmt.Errorf("password contains incomplete Unicode escape")
			}

			value, ok := decodeHex4(
				data[i : i+4],
			)
			if !ok {
				secret.Zero(result)

				return nil, fmt.Errorf("password contains invalid Unicode escape")
			}

			i += 4

			r := rune(value)

			switch {
			case value >= 0xD800 && value <= 0xDBFF:
				if i+6 > end ||
					data[i] != '\\' ||
					data[i+1] != 'u' {
					secret.Zero(result)

					return nil, fmt.Errorf("password contains incomplete Unicode surrogate pair")
				}

				low, ok := decodeHex4(data[i+2 : i+6])
				if !ok ||
					low < 0xDC00 ||
					low > 0xDFFF {
					secret.Zero(result)

					return nil, fmt.Errorf("password contains invalid Unicode surrogate pair")
				}

				r = utf16.DecodeRune(rune(value), rune(low))

				i += 6

			case value >= 0xDC00 && value <= 0xDFFF:
				secret.Zero(result)

				return nil, fmt.Errorf("password contains unexpected Unicode low surrogate")
			}

			result = utf8.AppendRune(result, r)

		default:
			secret.Zero(result)

			return nil, fmt.Errorf("password contains invalid JSON escape")
		}
	}

	return result, nil
}

func decodeHex4(data []byte) (uint16, bool) {
	if len(data) != 4 {
		return 0, false
	}

	var value uint16

	for _, b := range data {
		var digit byte

		switch {
		case b >= '0' && b <= '9':
			digit = b - '0'

		case b >= 'a' && b <= 'f':
			digit = b - 'a' + 10

		case b >= 'A' && b <= 'F':
			digit = b - 'A' + 10

		default:
			return 0, false
		}

		value = value<<4 | uint16(digit)
	}

	return value, true
}
