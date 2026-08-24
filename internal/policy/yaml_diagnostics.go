package policy

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

type errorLine struct {
	line    int
	message string
}

func yamlErrorLines(err error) []errorLine {
	var yamlErr *yaml.TypeError

	var allErrors = []errorLine{}

	if !errors.As(err, &yamlErr) {
		return nil
	}

	if len(yamlErr.Errors) == 0 {
		return nil
	}

	for _, message := range yamlErr.Errors {
		var line int

		n, scanErr := fmt.Sscanf(message, "line %d:", &line)
		if scanErr == nil && n == 1 && line > 0 {
			allErrors = append(allErrors, errorLine{
				line:    line,
				message: message,
			})
		} else {
			allErrors = append(allErrors, errorLine{
				line:    0,
				message: message,
			})
		}
	}

	return allErrors
}

func findYAMLPathByLine(root *yaml.Node, line int) (string, bool) {
	if root == nil || line <= 0 {
		return "", false
	}

	return findYAMLPath(root, line, "")
}

func findYAMLPath(node *yaml.Node, line int, currentPath string) (string, bool) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if path, found := findYAMLPath(child, line, currentPath); found {
				return path, true
			}
		}

	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			nextPath := appendYAMLKey(currentPath, keyNode.Value)

			// Для ошибки unknown field нужна строка самого ключа
			if keyNode.Line == line {
				return nextPath, true
			}

			if path, found := findYAMLPath(valueNode, line, nextPath); found {
				return path, true
			}
		}

	case yaml.SequenceNode:
		for index, child := range node.Content {
			nextPath := fmt.Sprintf("%s[%d]", currentPath, index)

			if path, found := findYAMLPath(child, line, nextPath); found {
				return path, true
			}
		}

	case yaml.ScalarNode:
		if node.Line == line && currentPath != "" {
			return currentPath, true
		}
	}

	return "", false
}

func appendYAMLKey(currentPath, key string) string {
	if currentPath == "" {
		return key
	}

	return currentPath + "." + key
}

func formatYAMLDecodeErrors(yamlDoc []byte, decodeErr error) []error {
	if decodeErr == nil {
		return nil
	}

	var root yaml.Node

	if err := yaml.Unmarshal(yamlDoc, &root); err != nil {
		return []error{decodeErr}
	}

	errorLines := yamlErrorLines(decodeErr)

	var diagnostics []error

	if len(errorLines) == 0 {
		diagnostics = append(diagnostics, fmt.Errorf("error of decoding: %w", decodeErr))
	}

	for _, er := range errorLines {
		path, found := findYAMLPathByLine(&root, er.line)

		if found {
			diagnostics = append(diagnostics, fmt.Errorf("%s: %s", path, er.message))
			continue
		}

		diagnostics = append(diagnostics, fmt.Errorf("%s", er.message))
	}

	return diagnostics
}
