package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

func LoadConfig(path string) (Config, error) {
	data, format, readErr := ReadPolicyFile(path)
	if readErr != nil {
		return Config{}, readErr
	}

	config, canValidate, decodeErr := decodePolicyData(data, format)
	if decodeErr != nil && !canValidate {
		return Config{}, fmt.Errorf("decode policy data: %w", decodeErr)
	}

	maxExists, maxErr := lengthMaxExists(data, format)
	if maxErr != nil {
		if decodeErr != nil {
			return Config{}, errors.Join(decodeErr, fmt.Errorf("check length.max in %q: %w", path, maxErr))
		}

		return Config{}, fmt.Errorf("check length.max in %q: %w", path, maxErr)
	}

	if !maxExists {
		config.Policy.Length.Max = config.Policy.Length.Min
	}

	validationErrors := ValidatePolicy(config)

	diagnostics := []error{}

	if decodeErr != nil {
		diagnostics = append(diagnostics, decodeErr)
	}

	diagnostics = append(diagnostics, validationErrors...)

	if len(diagnostics) > 0 {
		return Config{}, errors.Join(diagnostics...)
	}

	return config, nil
}

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

func decodePolicyData(data []byte, format Format) (Config, bool, error) {
	config := defaultConfig()

	switch format {
	case FormatYAML:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)

		var diagnostics []error

		if decodeErr := dec.Decode(&config); decodeErr != nil {
			decodeErrors := formatYAMLDecodeErrors(data, decodeErr)
			formattedDecodeErr := errors.Join(decodeErrors...)


			var typeErr *yaml.TypeError

			if !errors.As(decodeErr, &typeErr) {
				return Config{}, false, fmt.Errorf("unmarshal YAML: %w", formattedDecodeErr)
			}

			diagnostics = append(diagnostics, formattedDecodeErr)
		}

		var extra any
		trailingErr := dec.Decode(&extra)

		if trailingErr == nil {
			diagnostics = append(diagnostics, fmt.Errorf("YAML policy must contain exactly one document"))
		} else if !errors.Is(trailingErr, io.EOF) {
			diagnostics = append( diagnostics, fmt.Errorf("read trailing YAML data: %w", trailingErr))
		}

		if len(diagnostics) > 0 {
			return config, true, fmt.Errorf("unmarshal YAML: %w", errors.Join(diagnostics...))
		}
	case FormatJSON:
		unknownFieldErrors, walkErr := validateJSONFields(data)

		diagnostics := append([]error{}, unknownFieldErrors...)

		if walkErr != nil {
			diagnostics = append(diagnostics, fmt.Errorf("walk JSON structure: %w", walkErr))

			return Config{}, false, fmt.Errorf("unmarshal JSON: %w", errors.Join(diagnostics...))
		}

		dec := json.NewDecoder(bytes.NewReader(data))

		if decodeErr := dec.Decode(&config); decodeErr != nil {
			diagnostics = append(diagnostics, decodeErr)

			var typeErr *json.UnmarshalTypeError

			if !errors.As(decodeErr, &typeErr) {
				return Config{}, false, fmt.Errorf("unmarshal JSON: %w", errors.Join(diagnostics...))
			}
		}

		var extra any
		trailingErr := dec.Decode(&extra)

		if trailingErr == nil {
			diagnostics = append(diagnostics, fmt.Errorf("JSON policy must contain exactly one value"))
		} else if trailingErr != io.EOF {
			diagnostics = append(diagnostics, fmt.Errorf("read trailing JSON data: %w", trailingErr))
		}

		if len(diagnostics) > 0 {
			return config, true, fmt.Errorf("unmarshal JSON: %w", errors.Join(diagnostics...))
		}
	default:
		return Config{}, false, fmt.Errorf("unsupported format: %v", format)
	}

	return config, true, nil
}

func lengthMaxExists(data []byte, format Format) (bool, error) {
	switch format {
	case FormatYAML:
		return lengthMaxExistsYAML(data)
	case FormatJSON:
		return lengthMaxExistsJSON(data)
	default:
		return false, fmt.Errorf("unsupported format: %v", format)
	}
}

func mappingValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		if keyNode.Value == key {
			return valueNode, true
		}
	}

	return nil, false
}

func lengthMaxExistsYAML(data []byte) (bool, error) {
	var root yaml.Node

	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parse YAML tree: %w", err)
	}

	if len(root.Content) == 0 {
		return false, nil
	}

	document := root.Content[0]

	policyNode, ok := mappingValue(document, "policy")
	if !ok {
		return false, nil
	}

	lengthNode, ok := mappingValue(policyNode, "length")
	if !ok {
		return false, nil
	}

	_, ok = mappingValue(lengthNode, "max")
	return ok, nil
}

func lengthMaxExistsJSON(data []byte) (bool, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parse JSON root: %w", err)
	}

	policyData, ok := root["policy"]
	if !ok {
		return false, nil
	}

	var policyObject map[string]json.RawMessage
	if err := json.Unmarshal(policyData, &policyObject); err != nil {
		return false, fmt.Errorf("parse JSON policy: %w", err)
	}

	lengthData, ok := policyObject["length"]
	if !ok {
		return false, nil
	}

	var lengthObject map[string]json.RawMessage
	if err := json.Unmarshal(lengthData, &lengthObject); err != nil {
		return false, fmt.Errorf("parse JSON policy.length: %w", err)
	}

	_, ok = lengthObject["max"]
	return ok, nil
}
