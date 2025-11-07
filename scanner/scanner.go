package scanner

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Scanner holds the rules and performs scans
type Scanner struct {
	rules RulesFile
}

// NewScanner creates a new scanner with loaded rules
func NewScanner(rulesFile string) (*Scanner, error) {
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var rules RulesFile
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules file: %w", err)
	}

	return &Scanner{
		rules: rules,
	}, nil
}

// ScanFile scans a configuration file
func (s *Scanner) ScanFile(filePath string) (ScanResult, error) {
	config, err := ParseConfigFile(filePath)
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to parse config file: %w", err)
	}

	findings := []Finding{}

	for _, rule := range s.rules.Rules {
		if finding := CheckRule(rule, config); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return ScanResult{
		File:     filePath,
		Findings: findings,
	}, nil
}

// ScanConfig scans a parsed configuration
func (s *Scanner) ScanConfig(config *Config) []Finding {
	findings := []Finding{}

	for _, rule := range s.rules.Rules {
		if finding := CheckRule(rule, config); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}
