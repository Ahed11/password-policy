package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

func validateJSONFields(jsonDoc []byte) ([]error, error) {
	dec := json.NewDecoder(bytes.NewReader(jsonDoc))

	var diagnostics []error

	rootType := reflect.TypeOf(Config{})

	err := walkJSONValue(dec, rootType, "", &diagnostics)
	if err != nil {
		return diagnostics, err
	}

	return diagnostics, nil
}

func walkJSONValue(dec *json.Decoder, schemaType reflect.Type, currentPath string, diagnostics *[]error) error {
	schemaType = dereferenceJSONType(schemaType)

	token, err := dec.Token()
	if err != nil {
		return err
	}

	delim, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delim {
	case '{':
		if schemaType == nil || schemaType.Kind() != reflect.Struct {
			return skipJSONObject(dec)
		}

		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}

			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("expected JSON object key")
			}

			nextPath := appendJSONKey(currentPath, key)

			fieldType, found := jsonFieldType(schemaType, key)
			if !found {
				*diagnostics = append(*diagnostics, fmt.Errorf("%s: unknown field", nextPath))

				if err := skipJSONValue(dec); err != nil {
					return err
				}

				continue
			}

			if err := walkJSONValue(dec, fieldType, nextPath, diagnostics); err != nil {
				return err
			}
		}

		_, err = dec.Token()
		return err

	case '[':
		if schemaType == nil || (schemaType.Kind() != reflect.Slice && schemaType.Kind() != reflect.Array) {
			return skipJSONArray(dec)
		}

		elementType := schemaType.Elem()
		index := 0

		for dec.More() {
			nextPath := fmt.Sprintf("%s[%d]", currentPath, index)

			if err := walkJSONValue(dec, elementType, nextPath, diagnostics); err != nil {
				return err
			}

			index++
		}

		_, err = dec.Token()
		return err
	}

	return nil
}

func jsonFieldType(structType reflect.Type, jsonKey string) (reflect.Type, bool) {
	structType = dereferenceJSONType(structType)

	if structType == nil || structType.Kind() != reflect.Struct {
		return nil, false
	}

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)

		if field.PkgPath != "" {
			continue
		}

		tag, hasTag := field.Tag.Lookup("json")

		if hasTag {
			if tag == "-" {
				continue
			}

			fieldName := tag

			if comma := strings.IndexByte(fieldName, ','); comma >= 0 {
				fieldName = fieldName[:comma]
			}

			if fieldName == "" {
				fieldName = field.Name
			}

			if fieldName == jsonKey {
				return field.Type, true
			}

			continue
		}

		if field.Name == jsonKey {
			return field.Type, true
		}
	}

	return nil, false
}

func dereferenceJSONType(valueType reflect.Type) reflect.Type {
	for valueType != nil && valueType.Kind() == reflect.Ptr {
		valueType = valueType.Elem()
	}

	return valueType
}

func appendJSONKey(currentPath, key string) string {
	if currentPath == "" {
		return key
	}

	return currentPath + "." + key
}

func skipJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	delim, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delim {
	case '{':
		return skipJSONObject(dec)
	case '[':
		return skipJSONArray(dec)
	default:
		return nil
	}
}

func skipJSONObject(dec *json.Decoder) error {
	for dec.More() {

		if _, err := dec.Token(); err != nil {
			return err
		}

		if err := skipJSONValue(dec); err != nil {
			return err
		}
	}

	_, err := dec.Token()
	return err
}

func skipJSONArray(dec *json.Decoder) error {
	for dec.More() {
		if err := skipJSONValue(dec); err != nil {
			return err
		}
	}

	_, err := dec.Token()
	return err
}
