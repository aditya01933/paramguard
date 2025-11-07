package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// CheckRule evaluates a rule against the config
func CheckRule(rule Rule, config *Config) *Finding {
	var violated bool
	var location string

	switch rule.Check.Type {
	case "pattern_match":
		violated, location = checkPatternMatch(rule, config)
	case "numeric_range":
		violated, location = checkNumericRange(rule, config)
	case "missing_field":
		violated, location = checkMissingField(rule, config)
	case "missing_fields":
		violated, location = checkMissingFields(rule, config)
	case "field_exists":
		violated, location = checkFieldExists(rule, config)
	case "combined_conditions":
		violated, location = checkCombinedConditions(rule, config)
	case "conditional_missing":
		violated, location = checkConditionalMissing(rule, config)
	case "field_check":
		violated, location = checkFieldCheck(rule, config)
	case "stop_sequence_complexity":
		violated, location = checkStopSequenceComplexity(rule, config)
	default:
		return nil
	}

	if !violated {
		return nil
	}

	return &Finding{
		RuleID:         rule.ID,
		Name:           rule.Name,
		Severity:       rule.Severity,
		Category:       rule.Category,
		Description:    rule.Description,
		Location:       location,
		Recommendation: rule.Recommendation,
		References:     rule.References,
	}
}

func checkPatternMatch(rule Rule, config *Config) (bool, string) {
	// Check specific fields if provided
	if len(rule.Fields) > 0 {
		for _, field := range rule.Fields {
			values := config.GetAllFieldValues(field)
			for _, val := range values {
				if str, ok := val.(string); ok {
					for _, pattern := range rule.Check.Patterns {
						if matched, _ := regexp.MatchString(pattern, str); matched {
							return true, field
						}
					}
				}
			}
		}
		return false, ""
	}

	// Check all content
	content := config.GetAllContent()
	for _, pattern := range rule.Check.Patterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true, "config content"
		}
	}

	return false, ""
}

func checkNumericRange(rule Rule, config *Config) (bool, string) {
	// Check single parameter
	if rule.Check.Parameter != "" {
		return checkSingleNumeric(rule.Check.Parameter, rule.Check, config)
	}

	// Check multiple parameters
	if len(rule.Check.Parameters) > 0 {
		for _, param := range rule.Check.Parameters {
			if violated, loc := checkSingleNumeric(param, rule.Check, config); violated {
				return true, loc
			}
		}
	}

	return false, ""
}

func checkSingleNumeric(param string, check Check, config *Config) (bool, string) {
	values := config.GetAllFieldValues(param)
	if len(values) == 0 {
		return false, ""
	}

	for _, val := range values {
		var num float64
		switch v := val.(type) {
		case float64:
			num = v
		case float32:
			num = float64(v)
		case int:
			num = float64(v)
		case int64:
			num = float64(v)
		default:
			continue
		}

		// Check if outside range
		if check.Min != 0 || check.Max != 0 {
			if num < check.Min || num > check.Max {
				return true, param
			}
		}

		// Check specific conditions for any_value_exceeds
		if check.Condition == "any_value_exceeds" {
			if num < check.Min || num > check.Max {
				return true, param
			}
		}
	}

	return false, ""
}

func checkMissingField(rule Rule, config *Config) (bool, string) {
	field := rule.Check.Field
	if !config.HasField(field) {
		return true, field
	}
	return false, ""
}

func checkMissingFields(rule Rule, config *Config) (bool, string) {
	for _, field := range rule.Check.Fields {
		if config.HasField(field) {
			return false, ""
		}
	}
	// All fields are missing
	return true, strings.Join(rule.Check.Fields, ", ")
}

func checkFieldExists(rule Rule, config *Config) (bool, string) {
	field := rule.Check.Field
	if config.HasField(field) {
		return true, field
	}
	return false, ""
}

func checkCombinedConditions(rule Rule, config *Config) (bool, string) {
	metCount := 0
	locations := []string{}

	for _, condition := range rule.Check.Conditions {
		if checkCondition(condition, config) {
			metCount++
			locations = append(locations, condition.Parameter)
		}
	}

	require := rule.Check.Require
	switch require {
	case "all":
		if metCount == len(rule.Check.Conditions) {
			return true, strings.Join(locations, ", ")
		}
	case "at_least_two":
		if metCount >= 2 {
			return true, strings.Join(locations, ", ")
		}
	case "both":
		if metCount == 2 {
			return true, strings.Join(locations, ", ")
		}
	case "any":
		if metCount > 0 {
			return true, strings.Join(locations, ", ")
		}
	}

	return false, ""
}

func checkCondition(condition Condition, config *Config) bool {
	values := config.GetAllFieldValues(condition.Parameter)
	if len(values) == 0 {
		return false
	}

	for _, val := range values {
		switch condition.Operator {
		case "greater_than":
			if num, ok := toFloat(val); ok {
				if threshold, ok := toFloat(condition.Value); ok {
					if num > threshold {
						return true
					}
				}
			}
		case "not_equals":
			if fmt.Sprintf("%v", val) != fmt.Sprintf("%v", condition.Value) {
				return true
			}
		case "equals":
			if fmt.Sprintf("%v", val) == fmt.Sprintf("%v", condition.Value) {
				return true
			}
		}
	}

	return false
}

func checkConditionalMissing(rule Rule, config *Config) (bool, string) {
	// Check if any of HasAny fields exist
	hasAny := false
	for _, field := range rule.Check.HasAny {
		if config.HasField(field) {
			hasAny = true
			break
		}
	}

	if !hasAny {
		return false, ""
	}

	// Check if all MissingAll fields are missing
	for _, field := range rule.Check.MissingAll {
		if config.HasField(field) {
			return false, ""
		}
	}

	return true, strings.Join(rule.Check.MissingAll, ", ")
}

func checkFieldCheck(rule Rule, config *Config) (bool, string) {
	for _, field := range rule.Check.Fields {
		values := config.GetAllFieldValues(field)
		for _, val := range values {
			valStr := fmt.Sprintf("%v", val)
			for _, checkVal := range rule.Check.Values {
				if valStr == fmt.Sprintf("%v", checkVal) {
					return true, field
				}
			}
		}
	}
	return false, ""
}

func checkStopSequenceComplexity(rule Rule, config *Config) (bool, string) {
	field := rule.Check.Field
	values := config.GetAllFieldValues(field)

	for _, val := range values {
		switch v := val.(type) {
		case []interface{}:
			// Check number of sequences
			if rule.Check.MaxSequences > 0 && len(v) > rule.Check.MaxSequences {
				return true, field
			}
			// Check length of each sequence
			if rule.Check.MaxLength > 0 {
				for _, item := range v {
					if str, ok := item.(string); ok {
						if len(str) > rule.Check.MaxLength {
							return true, field
						}
					}
				}
			}
		case string:
			if rule.Check.MaxLength > 0 && len(v) > rule.Check.MaxLength {
				return true, field
			}
		}
	}

	return false, ""
}

func toFloat(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}
