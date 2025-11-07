package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		filename string
		wantErr  bool
		wantKeys []string
	}{
		{
			name:     "valid json",
			filename: "test.json",
			content:  `{"model": "gpt-4", "temperature": 0.7, "max_tokens": 1000}`,
			wantErr:  false,
			wantKeys: []string{"model", "temperature", "max_tokens"},
		},
		{
			name:     "valid yaml",
			filename: "test.yaml",
			content:  "model: gpt-4\ntemperature: 0.7\nmax_tokens: 1000",
			wantErr:  false,
			wantKeys: []string{"model", "temperature", "max_tokens"},
		},
		{
			name:     "valid toml",
			filename: "test.toml",
			content:  "model = \"gpt-4\"\ntemperature = 0.7\nmax_tokens = 1000",
			wantErr:  false,
			wantKeys: []string{"model", "temperature", "max_tokens"},
		},
		{
			name:     "valid env",
			filename: ".env",
			content:  "MODEL=gpt-4\nTEMPERATURE=0.7\nMAX_TOKENS=1000",
			wantErr:  false,
			wantKeys: []string{"MODEL", "TEMPERATURE", "MAX_TOKENS"},
		},
		{
			name:     "invalid json",
			filename: "test.json",
			content:  `{"model": "gpt-4"`,
			wantErr:  true,
		},
		{
			name:     "empty file",
			filename: "test.json",
			content:  "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, tt.filename)

			err := os.WriteFile(filePath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			// Parse
			config, err := ParseConfigFile(filePath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify keys exist
			for _, key := range tt.wantKeys {
				if _, ok := config.Data[key]; !ok {
					t.Errorf("expected key %q not found", key)
				}
			}
		})
	}
}

func TestConfigHasField(t *testing.T) {
	config := &Config{
		Data: map[string]interface{}{
			"temperature": 0.7,
			"nested": map[string]interface{}{
				"api_key": "sk-test",
			},
		},
	}

	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{"top level field exists", "temperature", true},
		{"nested field exists", "api_key", true},
		{"field does not exist", "missing", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.HasField(tt.field)
			if got != tt.want {
				t.Errorf("HasField(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestConfigGetAllFieldValues(t *testing.T) {
	config := &Config{
		Data: map[string]interface{}{
			"temperature": 0.7,
			"settings": map[string]interface{}{
				"temperature": 0.9,
			},
		},
	}

	values := config.GetAllFieldValues("temperature")
	if len(values) != 2 {
		t.Errorf("expected 2 temperature values, got %d", len(values))
	}
}
