package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"encoding/json"
	"gopkg.in/yaml.v3"
)

type Format int

const (
	FormatUnknown Format = iota
	FormatYAML
	FormatJSON
)

func ReadPolicyFile(path string) ([]byte, Format, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, FormatUnknown, fmt.Errorf("read policy file %q: %w", path, err)
	}

	format, hasExtension := formatFromExtension(path)

	if !hasExtension {
		format, err = determineFormatFromDataWithoutExtension(data)
		if err != nil {
			return nil, format, fmt.Errorf("%w for %q", err, path)
		}
	}

	if format == FormatUnknown {
		return nil, format, fmt.Errorf("unknown policy file format for %q", path)
	}

	return data, format, nil
}

func formatFromExtension(path string) (format Format, extension bool) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		return FormatYAML, true
	case ".json":
		return FormatJSON, true
	case "":
		return FormatUnknown, false
	default:
		return FormatUnknown, true
	}
}

func determineFormatFromDataWithoutExtension(data []byte) (Format, error) {
	trimmedData := strings.TrimSpace(string(data))

	if len(trimmedData) == 0 {
		return FormatUnknown, fmt.Errorf("policy file is empty")
	}

	if json.Valid(data) {
		return FormatJSON, nil
	} else {
		var yamlData any
		if err := yaml.Unmarshal(data, &yamlData); err == nil {
			return FormatYAML, nil
		}
	}
	return FormatUnknown, fmt.Errorf("unknown policy file format")
}
