package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner_ScanFile(t *testing.T) {
	// Create temp rules file
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "rules.yaml")

	rulesContent := `
version: "1.0.0"
rules:
  - id: TEST_001
    name: "High Temperature"
    severity: HIGH
    category: parameters
    description: "Temperature too high"
    check:
      type: numeric_range
      parameter: temperature
      min: 0.0
      max: 1.0
    recommendation: "Lower temperature"
    references:
      - "Test reference"
  - id: TEST_002
    name: "API Key Found"
    severity: CRITICAL
    category: secrets
    description: "API key in config"
    check:
      type: pattern_match
      patterns:
        - "sk-[a-zA-Z0-9]{10,}"
    fields:
      - api_key
    recommendation: "Remove API key"
    references:
      - "Test reference"
`

	err := os.WriteFile(rulesFile, []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("failed to write rules file: %v", err)
	}

	// Create scanner
	scanner, err := NewScanner(rulesFile)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name           string
		configContent  string
		configFilename string
		wantFindings   int
	}{
		{
			name:           "vulnerable config",
			configFilename: "bad.json",
			configContent:  `{"temperature": 1.5, "api_key": "sk-test1234567890"}`,
			wantFindings:   2, // Both rules violated
		},
		{
			name:           "safe config",
			configFilename: "good.json",
			configContent:  `{"temperature": 0.7, "model": "gpt-4"}`,
			wantFindings:   0, // No violations
		},
		{
			name:           "partial violations",
			configFilename: "partial.json",
			configContent:  `{"temperature": 1.5}`,
			wantFindings:   1, // Only temperature rule violated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFile := filepath.Join(tmpDir, tt.configFilename)
			err := os.WriteFile(configFile, []byte(tt.configContent), 0644)
			if err != nil {
				t.Fatalf("failed to write config file: %v", err)
			}

			result, err := scanner.ScanFile(configFile)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			if len(result.Findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(result.Findings), tt.wantFindings)
			}

			if result.File != configFile {
				t.Errorf("result.File = %q, want %q", result.File, configFile)
			}
		})
	}
}

func TestNewScanner_InvalidRulesFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "missing rules file",
			content: "",
			wantErr: true,
		},
		{
			name:    "invalid yaml",
			content: "invalid: yaml: content:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			rulesFile := filepath.Join(tmpDir, "rules.yaml")

			if tt.content != "" {
				err := os.WriteFile(rulesFile, []byte(tt.content), 0644)
				if err != nil {
					t.Fatalf("failed to write rules file: %v", err)
				}
			} else {
				rulesFile = filepath.Join(tmpDir, "nonexistent.yaml")
			}

			_, err := NewScanner(rulesFile)

			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
