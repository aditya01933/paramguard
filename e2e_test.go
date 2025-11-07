package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_VulnerableConfig tests scanning a config with multiple issues
func TestE2E_VulnerableConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	// Create vulnerable config
	configFile := filepath.Join(tmpDir, "vulnerable.json")
	configContent := `{
		"temperature": 1.5,
		"api_key": "sk-test1234567890abcdefghijklmnopqr",
		"max_tokens": 10000
	}`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Build binary
	buildCmd := exec.Command("go", "build", "-o", "paramguard-test")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build: %v\n%s", err, output)
	}
	defer os.Remove("paramguard-test")

	// Run scanner
	cmd := exec.Command("./paramguard-test", "scan", configFile)
	output, err := cmd.CombinedOutput()

	// Should exit with code 1 (issues found)
	if err == nil {
		t.Error("expected non-zero exit code but got success")
	}

	outputStr := string(output)

	// Verify output contains expected findings
	expectedFindings := []string{
		"CRITICAL",
		"API Keys in Configuration",
		"SECRETS_001",
	}

	for _, expected := range expectedFindings {
		if !strings.Contains(outputStr, expected) {
			t.Errorf("output missing expected text %q", expected)
		}
	}
}

// TestE2E_SafeConfig tests scanning a safe configuration
func TestE2E_SafeConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	// Create safe config
	configFile := filepath.Join(tmpDir, "safe.json")
	configContent := `{
	    "model": "gpt-4-0613",
	    "temperature": 0.7,
	    "max_tokens": 1000,
	    "timeout": 30,
	    "system_prompt": "You are a helpful assistant",
	    "user_id": "user123",
	    "rate_limit": {
	        "rpm": 100,
	        "tpm": 10000,
	        "per_user_limit": true
	    },
	    "logging": true,
	    "content_moderation": true,
	    "error_handling": {
	        "max_retries": 3
	    },
	    "cors": ["https://example.com"],
	    "input_validation": true,
	    "output_validation": true
	}`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Build binary
	buildCmd := exec.Command("go", "build", "-o", "paramguard-test")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build: %v\n%s", err, output)
	}
	defer os.Remove("paramguard-test")

	// Run scanner
	cmd := exec.Command("./paramguard-test", "scan", configFile)
	output, err := cmd.CombinedOutput()

	// Should exit with code 0 (no issues)
	if err != nil {
		t.Errorf("expected zero exit code but got error: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "No issues found") {
		t.Errorf("expected 'No issues found' in output, got: %s", outputStr)
	}
}

// TestE2E_JSONOutput tests JSON output format
func TestE2E_JSONOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	// Create config with known issue
	configFile := filepath.Join(tmpDir, "test.json")
	configContent := `{"temperature": 1.5}`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Build binary
	buildCmd := exec.Command("go", "build", "-o", "paramguard-test")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build: %v\n%s", err, output)
	}
	defer os.Remove("paramguard-test")

	// Run scanner with JSON output
	cmd := exec.Command("./paramguard-test", "scan", "--format", "json", configFile)
	output, err := cmd.CombinedOutput()

	// Parse JSON output
	var result struct {
		Version string `json:"version"`
		Results []struct {
			File     string `json:"file"`
			Findings []struct {
				RuleID   string `json:"rule_id"`
				Severity string `json:"severity"`
			} `json:"findings"`
		} `json:"results"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nOutput: %s", err, output)
	}

	// Verify JSON structure
	if result.Version == "" {
		t.Error("expected version in JSON output")
	}

	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}

	if len(result.Results[0].Findings) == 0 {
		t.Error("expected findings in JSON output")
	}
}

// TestE2E_MultipleFiles tests scanning multiple config files
func TestE2E_MultipleFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	// Create multiple config files
	files := map[string]string{
		"config1.json": `{"temperature": 1.5}`,
		"config2.yaml": "temperature: 0.7",
		"config3.json": `{"api_key": "sk-test123456789012345678901234"}`,
	}

	for filename, content := range files {
		err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644)
		if err != nil {
			t.Fatalf("failed to write %s: %v", filename, err)
		}
	}

	// Build binary
	buildCmd := exec.Command("go", "build", "-o", "paramguard-test")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build: %v\n%s", err, output)
	}
	defer os.Remove("paramguard-test")

	// Run scanner on all files
	cmd := exec.Command("./paramguard-test", "scan",
		filepath.Join(tmpDir, "config1.json"),
		filepath.Join(tmpDir, "config2.yaml"),
		filepath.Join(tmpDir, "config3.json"),
	)
	output, err := cmd.CombinedOutput()

	// Should fail because of issues in config1 and config3
	if err == nil {
		t.Error("expected non-zero exit code")
	}

	outputStr := string(output)

	// Verify all files are mentioned
	for filename := range files {
		if !strings.Contains(outputStr, filename) {
			t.Errorf("output should mention file %q", filename)
		}
	}

	// Verify summary shows correct count
	if !strings.Contains(outputStr, "Total files scanned: 3") {
		t.Error("summary should show 3 files scanned")
	}
}

// TestE2E_CustomRulesFile tests using custom rules file
func TestE2E_CustomRulesFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	// Create custom rules with only one rule
	customRules := filepath.Join(tmpDir, "custom.yaml")
	rulesContent := `
version: "1.0.0"
rules:
  - id: CUSTOM_001
    name: "Custom Test Rule"
    severity: HIGH
    category: test
    description: "Test rule"
    check:
      type: numeric_range
      parameter: custom_param
      min: 0.0
      max: 10.0
    recommendation: "Fix it"
    references:
      - "Test"
`

	err := os.WriteFile(customRules, []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("failed to write custom rules: %v", err)
	}

	// Create config that violates custom rule
	configFile := filepath.Join(tmpDir, "test.json")
	err = os.WriteFile(configFile, []byte(`{"custom_param": 20}`), 0644)
	if err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Build binary
	buildCmd := exec.Command("go", "build", "-o", "paramguard-test")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build: %v\n%s", err, output)
	}
	defer os.Remove("paramguard-test")

	// Run with custom rules
	cmd := exec.Command("./paramguard-test", "scan", "--rules", customRules, configFile)
	output, err := cmd.CombinedOutput()

	// Should find the custom rule violation
	if err == nil {
		t.Error("expected non-zero exit code")
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "CUSTOM_001") {
		t.Errorf("expected custom rule ID in output, got: %s", outputStr)
	}
}

// TestE2E_InvalidConfigFile tests error handling for invalid files
func TestE2E_InvalidConfigFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Build binary
	buildCmd := exec.Command("go", "build", "-o", "paramguard-test")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build: %v\n%s", err, output)
	}
	defer os.Remove("paramguard-test")

	tests := []struct {
		name     string
		filename string
	}{
		{
			name:     "nonexistent file",
			filename: "nonexistent.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./paramguard-test", "scan", tt.filename)
			output, err := cmd.CombinedOutput()

			// Should error
			if err == nil {
				t.Error("expected error for invalid file")
			}

			outputStr := string(output)
			if !strings.Contains(outputStr, "Error") {
				t.Errorf("expected error message in output, got: %s", outputStr)
			}
		})
	}
}
