package scanner

// RulesFile represents the structure of rules.yaml
type RulesFile struct {
	Version    string   `yaml:"version"`
	Rules      []Rule   `yaml:"rules"`
	Categories []string `yaml:"categories"`
}

// Rule represents a single security rule
type Rule struct {
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	Severity       string   `yaml:"severity"`
	Category       string   `yaml:"category"`
	Description    string   `yaml:"description"`
	Check          Check    `yaml:"check"`
	Recommendation string   `yaml:"recommendation"`
	References     []string `yaml:"references"`
	Fields         []string `yaml:"fields,omitempty"`
}

// Check represents the detection logic
type Check struct {
	Type         string        `yaml:"type"`
	Parameter    string        `yaml:"parameter,omitempty"`
	Parameters   []string      `yaml:"parameters,omitempty"`
	Field        string        `yaml:"field,omitempty"`
	Fields       []string      `yaml:"fields,omitempty"`
	Patterns     []string      `yaml:"patterns,omitempty"`
	Operator     string        `yaml:"operator,omitempty"`
	Value        interface{}   `yaml:"value,omitempty"`
	Min          float64       `yaml:"min,omitempty"`
	Max          float64       `yaml:"max,omitempty"`
	Condition    string        `yaml:"condition,omitempty"`
	Conditions   []Condition   `yaml:"conditions,omitempty"`
	Require      string        `yaml:"require,omitempty"`
	HasAny       []string      `yaml:"has_any,omitempty"`
	MissingAll   []string      `yaml:"missing_all,omitempty"`
	Values       []interface{} `yaml:"values,omitempty"`
	MaxSequences int           `yaml:"max_sequences,omitempty"`
	MaxLength    int           `yaml:"max_length,omitempty"`
}

// Condition for combined checks
type Condition struct {
	Parameter string      `yaml:"parameter"`
	Operator  string      `yaml:"operator"`
	Value     interface{} `yaml:"value"`
}

// ScanResult represents the result of scanning a file
type ScanResult struct {
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

// Finding represents a security issue found
type Finding struct {
	RuleID         string   `json:"rule_id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Location       string   `json:"location,omitempty"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references"`
}

// Config represents a parsed configuration
type Config struct {
	Data     map[string]interface{}
	FilePath string
}
