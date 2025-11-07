package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aditya01933/paramguard/scanner"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "scan":
		runScan()
	case "version":
		fmt.Printf("paramguard v%s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runScan() {
	args := os.Args[2:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No config files specified")
		fmt.Fprintln(os.Stderr, "Usage: paramguard scan <config-file> [config-file...]")
		os.Exit(1)
	}

	var rulesFile string
	var outputFormat string
	var configFiles []string

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--rules":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --rules requires a file path")
				os.Exit(1)
			}
			rulesFile = args[i+1]
			i++
		case "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --format requires a value (text or json)")
				os.Exit(1)
			}
			outputFormat = args[i+1]
			i++
		default:
			configFiles = append(configFiles, args[i])
		}
	}

	if len(configFiles) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No config files specified")
		os.Exit(1)
	}

	// Default rules file
	if rulesFile == "" {
		rulesFile = "rules.yaml"
	}

	// Default format
	if outputFormat == "" {
		outputFormat = "text"
	}

	// Load rules
	s, err := scanner.NewScanner(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
		os.Exit(1)
	}

	// Scan all config files
	allResults := make([]scanner.ScanResult, 0)
	hasIssues := false

	for _, configFile := range configFiles {
		result, err := s.ScanFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", configFile, err)
			os.Exit(1)
		}
		allResults = append(allResults, result)
		if len(result.Findings) > 0 {
			hasIssues = true
		}
	}

	// Output results
	if outputFormat == "json" {
		outputJSON(allResults)
	} else {
		outputText(allResults)
	}

	// Exit code
	if hasIssues {
		os.Exit(1)
	}
	os.Exit(0)
}

func outputText(results []scanner.ScanResult) {
	totalFindings := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, result := range results {
		if len(result.Findings) == 0 {
			fmt.Printf("✓ %s - No issues found\n", result.File)
			continue
		}

		fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("📄 %s\n", result.File)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

		for _, finding := range result.Findings {
			totalFindings++

			var icon string
			switch finding.Severity {
			case "CRITICAL":
				icon = "🔴"
				criticalCount++
			case "HIGH":
				icon = "🟠"
				highCount++
			case "MEDIUM":
				icon = "🟡"
				mediumCount++
			case "LOW":
				icon = "🔵"
				lowCount++
			}

			fmt.Printf("\n%s %s [%s]\n", icon, finding.Name, finding.Severity)
			fmt.Printf("   ID: %s\n", finding.RuleID)
			fmt.Printf("   %s\n", finding.Description)

			if finding.Location != "" {
				fmt.Printf("   Location: %s\n", finding.Location)
			}

			fmt.Printf("   💡 %s\n", finding.Recommendation)

			if len(finding.References) > 0 {
				fmt.Printf("   📚 References:\n")
				for _, ref := range finding.References {
					fmt.Printf("      • %s\n", ref)
				}
			}
		}
	}

	// Summary
	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📊 SUMMARY\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Total files scanned: %d\n", len(results))
	fmt.Printf("Total findings: %d\n", totalFindings)
	if criticalCount > 0 {
		fmt.Printf("  🔴 Critical: %d\n", criticalCount)
	}
	if highCount > 0 {
		fmt.Printf("  🟠 High: %d\n", highCount)
	}
	if mediumCount > 0 {
		fmt.Printf("  🟡 Medium: %d\n", mediumCount)
	}
	if lowCount > 0 {
		fmt.Printf("  🔵 Low: %d\n", lowCount)
	}
	fmt.Println()
}

func outputJSON(results []scanner.ScanResult) {
	output := struct {
		Version string               `json:"version"`
		Results []scanner.ScanResult `json:"results"`
	}{
		Version: version,
		Results: results,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`ParamGuard - LLM Configuration Security Scanner

USAGE:
    paramguard scan [OPTIONS] <config-file> [config-file...]
    paramguard version
    paramguard help

COMMANDS:
    scan        Scan configuration files for security issues
    version     Print version information
    help        Print this help message

OPTIONS:
    --rules <file>      Path to custom rules file (default: rules.yaml)
    --format <format>   Output format: text or json (default: text)

EXAMPLES:
    # Scan a single config file
    paramguard scan config.json

    # Scan multiple files
    paramguard scan config.json settings.yaml .env

    # Use custom rules
    paramguard scan --rules custom-rules.yaml config.json

    # JSON output for CI/CD
    paramguard scan --format json config.json

EXIT CODES:
    0    No security issues found
    1    Security issues found or error occurred

SUPPORTED FORMATS:
    - JSON (.json)
    - YAML (.yaml, .yml)
    - TOML (.toml)
    - Environment files (.env)`)
}
