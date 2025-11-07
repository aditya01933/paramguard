package scanner

import (
	"testing"
)

func TestCheckRule_NumericRange(t *testing.T) {
	tests := []struct {
		name        string
		rule        Rule
		configData  map[string]interface{}
		wantViolate bool
	}{
		{
			name: "temperature too high",
			rule: Rule{
				ID:       "TEMP_001",
				Name:     "High Temperature",
				Severity: "HIGH",
				Check: Check{
					Type:      "numeric_range",
					Parameter: "temperature",
					Min:       0.0,
					Max:       1.0,
				},
			},
			configData: map[string]interface{}{
				"temperature": 1.5,
			},
			wantViolate: true,
		},
		{
			name: "temperature in safe range",
			rule: Rule{
				ID:       "TEMP_001",
				Name:     "High Temperature",
				Severity: "HIGH",
				Check: Check{
					Type:      "numeric_range",
					Parameter: "temperature",
					Min:       0.0,
					Max:       1.0,
				},
			},
			configData: map[string]interface{}{
				"temperature": 0.7,
			},
			wantViolate: false,
		},
		{
			name: "parameter missing",
			rule: Rule{
				ID:       "TEMP_001",
				Name:     "High Temperature",
				Severity: "HIGH",
				Check: Check{
					Type:      "numeric_range",
					Parameter: "temperature",
					Min:       0.0,
					Max:       1.0,
				},
			},
			configData: map[string]interface{}{
				"model": "gpt-4",
			},
			wantViolate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Data: tt.configData}
			finding := CheckRule(tt.rule, config)

			violated := finding != nil
			if violated != tt.wantViolate {
				t.Errorf("CheckRule() violated = %v, want %v", violated, tt.wantViolate)
			}
		})
	}
}

func TestCheckRule_PatternMatch(t *testing.T) {
	tests := []struct {
		name        string
		rule        Rule
		configData  map[string]interface{}
		wantViolate bool
	}{
		{
			name: "api key detected",
			rule: Rule{
				ID:       "SECRETS_001",
				Name:     "API Key",
				Severity: "CRITICAL",
				Check: Check{
					Type: "pattern_match",
					Patterns: []string{
						"sk-[a-zA-Z0-9_-]{20,}",
					},
				},
				Fields: []string{"api_key"},
			},
			configData: map[string]interface{}{
				"api_key": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901",
			},
			wantViolate: true,
		},
		{
			name: "no api key",
			rule: Rule{
				ID:       "SECRETS_001",
				Name:     "API Key",
				Severity: "CRITICAL",
				Check: Check{
					Type: "pattern_match",
					Patterns: []string{
						"sk-[a-zA-Z0-9_-]{20,}",
					},
				},
				Fields: []string{"api_key"},
			},
			configData: map[string]interface{}{
				"model": "gpt-4",
			},
			wantViolate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Data: tt.configData}
			finding := CheckRule(tt.rule, config)

			violated := finding != nil
			if violated != tt.wantViolate {
				t.Errorf("CheckRule() violated = %v, want %v", violated, tt.wantViolate)
			}
		})
	}
}

func TestCheckRule_MissingFields(t *testing.T) {
	tests := []struct {
		name        string
		rule        Rule
		configData  map[string]interface{}
		wantViolate bool
	}{
		{
			name: "all fields missing",
			rule: Rule{
				ID:       "RATE_001",
				Name:     "Missing Rate Limiting",
				Severity: "CRITICAL",
				Check: Check{
					Type: "missing_fields",
					Fields: []string{
						"rate_limit",
						"rpm",
						"tpm",
					},
				},
			},
			configData: map[string]interface{}{
				"model": "gpt-4",
			},
			wantViolate: true,
		},
		{
			name: "at least one field present",
			rule: Rule{
				ID:       "RATE_001",
				Name:     "Missing Rate Limiting",
				Severity: "CRITICAL",
				Check: Check{
					Type: "missing_fields",
					Fields: []string{
						"rate_limit",
						"rpm",
						"tpm",
					},
				},
			},
			configData: map[string]interface{}{
				"rpm": 100,
			},
			wantViolate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Data: tt.configData}
			finding := CheckRule(tt.rule, config)

			violated := finding != nil
			if violated != tt.wantViolate {
				t.Errorf("CheckRule() violated = %v, want %v", violated, tt.wantViolate)
			}
		})
	}
}

func TestCheckRule_CombinedConditions(t *testing.T) {
	tests := []struct {
		name        string
		rule        Rule
		configData  map[string]interface{}
		wantViolate bool
	}{
		{
			name: "multiple dangerous params combined",
			rule: Rule{
				ID:       "PARAM_001",
				Name:     "Multiple High-Risk Parameters",
				Severity: "CRITICAL",
				Check: Check{
					Type: "combined_conditions",
					Conditions: []Condition{
						{Parameter: "temperature", Operator: "greater_than", Value: 0.9},
						{Parameter: "top_p", Operator: "greater_than", Value: 0.95},
						{Parameter: "top_k", Operator: "greater_than", Value: 80},
					},
					Require: "at_least_two",
				},
			},
			configData: map[string]interface{}{
				"temperature": 1.5,
				"top_p":       0.98,
				"top_k":       100,
			},
			wantViolate: true,
		},
		{
			name: "only one dangerous param",
			rule: Rule{
				ID:       "PARAM_001",
				Name:     "Multiple High-Risk Parameters",
				Severity: "CRITICAL",
				Check: Check{
					Type: "combined_conditions",
					Conditions: []Condition{
						{Parameter: "temperature", Operator: "greater_than", Value: 0.9},
						{Parameter: "top_p", Operator: "greater_than", Value: 0.95},
					},
					Require: "at_least_two",
				},
			},
			configData: map[string]interface{}{
				"temperature": 1.5,
				"top_p":       0.8,
			},
			wantViolate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Data: tt.configData}
			finding := CheckRule(tt.rule, config)

			violated := finding != nil
			if violated != tt.wantViolate {
				t.Errorf("CheckRule() violated = %v, want %v", violated, tt.wantViolate)
			}
		})
	}
}

func TestCheckRule_FieldExists(t *testing.T) {
	rule := Rule{
		ID:       "SEED_001",
		Name:     "Seed in Production",
		Severity: "MEDIUM",
		Check: Check{
			Type:  "field_exists",
			Field: "seed",
		},
	}

	tests := []struct {
		name        string
		configData  map[string]interface{}
		wantViolate bool
	}{
		{
			name:        "seed field exists",
			configData:  map[string]interface{}{"seed": 12345},
			wantViolate: true,
		},
		{
			name:        "seed field missing",
			configData:  map[string]interface{}{"model": "gpt-4"},
			wantViolate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Data: tt.configData}
			finding := CheckRule(rule, config)

			violated := finding != nil
			if violated != tt.wantViolate {
				t.Errorf("CheckRule() violated = %v, want %v", violated, tt.wantViolate)
			}
		})
	}
}
