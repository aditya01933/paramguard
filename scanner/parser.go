package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// ParseConfigFile parses a config file based on its extension
func ParseConfigFile(filePath string) (*Config, error) {
	ext := strings.ToLower(filepath.Ext(filePath))

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var configData map[string]interface{}

	switch ext {
	case ".json":
		configData, err = parseJSON(data)
	case ".yaml", ".yml":
		configData, err = parseYAML(data)
	case ".toml":
		configData, err = parseTOML(data)
	case ".env":
		configData, err = parseEnv(data)
	default:
		// Try to detect format
		configData, err = autoDetectFormat(data)
		if err != nil {
			return nil, fmt.Errorf("unsupported file format: %s", ext)
		}
	}

	if err != nil {
		return nil, err
	}

	return &Config{
		Data:     configData,
		FilePath: filePath,
	}, nil
}

func parseJSON(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return result, nil
}

func parseYAML(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	return result, nil
}

func parseTOML(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := toml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}
	return result, nil
}

func parseEnv(data []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes
		value = strings.Trim(value, "\"'")

		result[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse ENV: %w", err)
	}

	return result, nil
}

func autoDetectFormat(data []byte) (map[string]interface{}, error) {
	// Try JSON first
	if result, err := parseJSON(data); err == nil {
		return result, nil
	}

	// Try YAML
	if result, err := parseYAML(data); err == nil {
		return result, nil
	}

	// Try TOML
	if result, err := parseTOML(data); err == nil {
		return result, nil
	}

	return nil, fmt.Errorf("unable to auto-detect format")
}

// GetValue retrieves a value from nested config
func (c *Config) GetValue(path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	current := c.Data

	for i, part := range parts {
		if val, ok := current[part]; ok {
			if i == len(parts)-1 {
				return val, true
			}
			if nested, ok := val.(map[string]interface{}); ok {
				current = nested
			} else {
				return nil, false
			}
		} else {
			return nil, false
		}
	}

	return nil, false
}

// HasField checks if a field exists anywhere in the config
func (c *Config) HasField(field string) bool {
	return hasFieldRecursive(c.Data, field)
}

func hasFieldRecursive(data map[string]interface{}, field string) bool {
	for key, val := range data {
		if key == field {
			return true
		}
		if nested, ok := val.(map[string]interface{}); ok {
			if hasFieldRecursive(nested, field) {
				return true
			}
		}
	}
	return false
}

// GetAllFieldValues returns all values for a given field name
func (c *Config) GetAllFieldValues(field string) []interface{} {
	var values []interface{}
	collectFieldValues(c.Data, field, &values)
	return values
}

func collectFieldValues(data map[string]interface{}, field string, values *[]interface{}) {
	for key, val := range data {
		if key == field {
			*values = append(*values, val)
		}
		if nested, ok := val.(map[string]interface{}); ok {
			collectFieldValues(nested, field, values)
		}
	}
}

// GetAllContent returns all string content from the config
func (c *Config) GetAllContent() string {
	var content strings.Builder
	collectContent(c.Data, &content)
	return content.String()
}

func collectContent(data map[string]interface{}, content *strings.Builder) {
	for _, val := range data {
		switch v := val.(type) {
		case string:
			content.WriteString(v)
			content.WriteString(" ")
		case map[string]interface{}:
			collectContent(v, content)
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					content.WriteString(str)
					content.WriteString(" ")
				}
			}
		}
	}
}
