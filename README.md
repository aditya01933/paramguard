# LLM Configuration Security Scanner

A production-ready security scanner for LLM API configurations. Detects dangerous parameter settings, credential exposure, missing security controls, and configuration vulnerabilities based on academic research, CVEs, and OWASP LLM Top 10 2025 guidance.

**All detection rules are backed by authoritative sources:**
- Academic research papers (Princeton, IEOM, arXiv)
- Documented CVEs and real-world incidents
- OWASP LLM Top 10 2025 guidelines
- Industry security best practices

## Why This Tool?

While pasting configs into ChatGPT works for one-off checks, this tool is built for:

- ✅ **CI/CD Automation** - Run on every commit automatically
- ✅ **Deterministic Results** - Same config = same findings (unlike AI)
- ✅ **Speed & Cost** - 5-10ms scans, no API costs
- ✅ **Air-gapped/Compliance** - Works offline, no data leaves your infrastructure
- ✅ **Transparency** - Open source rules with research citations
- ✅ **Production-Ready** - Exit codes, JSON output, proper error handling

## Features

- 🔍 Scans JSON, YAML, TOML, and .env configuration files
- 🎯 46 security rules across 6 categories
- 📊 Evidence-based thresholds backed by research
- 🚨 4 severity levels: CRITICAL, HIGH, MEDIUM, LOW
- 📝 Clear recommendations with references
- 🔧 Customizable rules via external YAML file
- 💻 CLI tool with JSON output for automation
- ⚡ Fast: ~5-10ms per file
- 🔒 Works offline - no external API calls

## Installation

### From Source

```bash
git clone https://github.com/yourusername/llm-config-scanner.git
cd llm-config-scanner
go build -o llm-config-scanner
```

### From Binary

Download the latest release for your platform from [Releases](https://github.com/yourusername/llm-config-scanner/releases).

## Quick Start

```bash
# Scan a single config file
./llm-config-scanner scan config.json

# Scan multiple files
./llm-config-scanner scan config.json settings.yaml .env

# Use custom rules
./llm-config-scanner scan --rules custom-rules.yaml config.json

# JSON output for CI/CD
./llm-config-scanner scan --format json config.json
```

## Usage

### Basic Scanning

```bash
# Scan JSON config
./llm-config-scanner scan llm-config.json

# Scan YAML config
./llm-config-scanner scan openai-settings.yaml

# Scan .env file
./llm-config-scanner scan .env

# Scan multiple files at once
./llm-config-scanner scan config/*.yaml .env
```

### Custom Rules

```bash
# Use custom rules file
./llm-config-scanner scan --rules my-rules.yaml config.json

# Combine custom and default rules by merging YAML files
```

### Output Formats

**Text Output (default):**
```bash
./llm-config-scanner scan config.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📄 config.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 Dangerous Temperature Setting [CRITICAL]
   ID: TEMP_001
   Temperature > 1.0 significantly increases jailbreak success
   Location: temperature
   💡 Use temperature 0.0-0.7 for production
   📚 References:
      • Princeton Catastrophic Jailbreak Study
      • IEOM 2024 - Can LLMs Have a Fever?
```

**JSON Output:**
```bash
./llm-config-scanner scan --format json config.json

{
  "version": "1.0.0",
  "results": [
    {
      "file": "config.json",
      "findings": [
        {
          "rule_id": "TEMP_001",
          "name": "Dangerous Temperature Setting",
          "severity": "CRITICAL",
          "category": "parameters",
          "description": "Temperature > 1.0 significantly increases jailbreak success",
          "location": "temperature",
          "recommendation": "Use temperature 0.0-0.7 for production",
          "references": [
            "Princeton Catastrophic Jailbreak Study",
            "IEOM 2024 - Can LLMs Have a Fever?"
          ]
        }
      ]
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: LLM Config Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Download Scanner
        run: |
          wget https://github.com/yourusername/llm-config-scanner/releases/download/v1.0.0/llm-config-scanner-linux-amd64
          chmod +x llm-config-scanner-linux-amd64
          
      - name: Scan Configs
        run: ./llm-config-scanner-linux-amd64 scan config/*.json config/*.yaml
```

### GitLab CI

```yaml
llm-security-scan:
  stage: security
  script:
    - wget https://github.com/yourusername/llm-config-scanner/releases/download/v1.0.0/llm-config-scanner-linux-amd64
    - chmod +x llm-config-scanner-linux-amd64
    - ./llm-config-scanner-linux-amd64 scan config/*.json config/*.yaml
  allow_failure: false
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running LLM config security scan..."
./llm-config-scanner scan config/*.json config/*.yaml

if [ $? -ne 0 ]; then
    echo "❌ Security issues found. Commit blocked."
    exit 1
fi

echo "✅ Security scan passed"
exit 0
```

## Exit Codes

- `0` - No security issues found
- `1` - Security issues found OR error occurred

Simple pass/fail model makes CI/CD integration straightforward.

## Detection Rules

### Categories

1. **Secrets** - API keys, credentials, tokens in configs
2. **Parameters** - Temperature, top_p, top_k, token limits
3. **Rate Limiting** - Missing or insufficient rate limits
4. **Prompts** - System prompt vulnerabilities
5. **Configuration** - Missing security controls
6. **Monitoring** - Logging and audit requirements

### Severity Levels

- **CRITICAL** - Immediate security risk (credentials exposed, no rate limits)
- **HIGH** - Significant vulnerability (dangerous parameters, missing controls)
- **MEDIUM** - Security concern requiring attention (elevated values, missing monitoring)
- **LOW** - Best practice violation (minor issues, recommendations)

### Sample Rules

**CRITICAL Rules:**
- `SECRETS_001` - API Keys in Configuration
- `SECRETS_002` - Database Credentials
- `LOGIT_001` - Extreme Logit Bias Values (enables jailbreaking)
- `RATE_001` - Missing Rate Limiting ($46K-$100K/day attacks)
- `PARAM_001` - Multiple High-Risk Parameters (95%+ jailbreak success)
- `CONFIG_008` - Unsafe Eval/Exec in Tool Config

**HIGH Rules:**
- `TEMP_001` - Dangerous Temperature > 1.0
- `TEMP_004` - Negative Temperature (invalid)
- `TOPP_001` - Excessive Top-P > 0.95
- `TOPP_002` - Top-P Outside Valid Range
- `TOPK_002` - Invalid Top-K Value
- `TOKENS_001` - Unlimited Max Tokens
- `TOKENS_002` - Excessive Max Tokens
- `USER_001` - User-Controlled Parameters
- `SECRETS_003` - Hardcoded IP Addresses
- `CONFIG_003` - HTTP Instead of HTTPS
- `CONFIG_005` - Function Calling Without Validation
- `CONFIG_009` - Missing Input Sanitization
- `CONFIG_010` - Missing Output Sanitization
- `MONITOR_002` - No Content Moderation
- `MONITOR_004` - Plain Text Logging of Sensitive Data
- `RATE_002` - Single-Dimension Rate Limiting
- `RATE_005` - No Per-User Rate Limiting
- `SECRETS_005` - Insecure Model Loading Paths
- `PLUGIN_001` - Unsafe Plugin Configuration

**See `rules.yaml` for complete list with references.**

## Research-Backed Thresholds

All thresholds are evidence-based:

| Parameter | Safe Range | Dangerous | Source |
|-----------|------------|-----------|--------|
| Temperature | 0.0-0.7 | > 1.0 | Princeton Study (95%+ ASR), IEOM 2024 |
| Top_p | 0.5-0.92 | > 0.95 | Virtual Context Attack, Prompt Engineering Guide |
| Top_k | 20-80 | > 100 | FlexLLM Defense Research |
| Max_tokens | Use case specific | Unlimited | OWASP LLM10:2025, OpenAI Best Practices |
| Logit_bias | Disabled or ±10 | |±50| | arXiv:2403.09539v3 (Info Leakage) |

## Customizing Rules

Rules are defined in `rules.yaml` with this structure:

```yaml
rules:
  - id: CUSTOM_001
    name: "Your Custom Rule"
    severity: HIGH
    category: parameters
    description: "What this rule detects"
    check:
      type: numeric_range
      parameter: temperature
      min: 0.0
      max: 0.5
    recommendation: "How to fix it"
    references:
      - "Your source"
      - "Research paper"
```

### Check Types

- `pattern_match` - Regex pattern matching
- `numeric_range` - Numeric value thresholds
- `missing_field` - Required field missing
- `missing_fields` - Multiple required fields missing
- `field_exists` - Field should not exist
- `combined_conditions` - Multiple conditions together
- `conditional_missing` - Conditional field requirements
- `field_check` - Specific field value checks
- `stop_sequence_complexity` - Stop sequence validation

## Supported Config Formats

| Format | Extensions | Example |
|--------|------------|---------|
| JSON | `.json` | `config.json` |
| YAML | `.yaml`, `.yml` | `openai-settings.yaml` |
| TOML | `.toml` | `config.toml` |
| ENV | `.env` | `.env` |

Auto-detection attempts if extension is unrecognized.

## Example Configs Scanned

### OpenAI Configuration
```json
{
  "model": "gpt-4",
  "temperature": 0.7,
  "max_tokens": 1000,
  "top_p": 0.9,
  "frequency_penalty": 0.0,
  "presence_penalty": 0.0,
  "rate_limit": {
    "rpm": 100,
    "tpm": 10000
  }
}
```

### Anthropic Configuration
```yaml
model: claude-3-opus-20240229
temperature: 0.5
max_tokens: 1024
top_p: 0.9
system_prompt: "You are a helpful assistant"
rate_limiting:
  requests_per_minute: 50
  tokens_per_minute: 50000
```

### Environment Variables
```bash
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxx
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.7
OPENAI_MAX_TOKENS=1000
```

## Common Issues Detected

### 1. Credentials in Configs
**Risk:** System prompts often contain API keys "for convenience"
- **Finding:** `SECRETS_001` - API Keys in Configuration
- **Fix:** Move to environment variables or secret managers

### 2. No Rate Limiting
**Risk:** Documented attacks costing $46K-$100K per day
- **Finding:** `RATE_001` - Missing Rate Limiting
- **Fix:** Implement RPM + TPM + RPD limits

### 3. Dangerous Temperature
**Risk:** Temperature > 1.0 increases jailbreak from 23% to 28% success
- **Finding:** `TEMP_001` - Dangerous Temperature Setting
- **Fix:** Use 0.0-0.7 for production, 0.0-0.4 for critical apps

### 4. User-Controlled Parameters
**Risk:** Attackers systematically probe parameter spaces
- **Finding:** `USER_001` - User-Controlled Parameters Enabled
- **Fix:** Use fixed security-hardened configurations

### 5. System Prompt Information Leakage
**Risk:** Multi-turn attacks achieve 86.2% prompt extraction success
- **Finding:** `PROMPT_001` - Sensitive Information in System Prompt
- **Fix:** Externalize all internal references to code

### 6. HTTP Instead of HTTPS
**Risk:** Unencrypted transmission of sensitive data
- **Finding:** `CONFIG_003` - HTTP URLs Instead of HTTPS
- **Fix:** Use HTTPS for all API endpoints

### 7. Missing Input/Output Sanitization
**Risk:** Injection attacks and improper output handling
- **Finding:** `CONFIG_009` / `CONFIG_010` - Missing Sanitization
- **Fix:** Validate and sanitize all inputs and outputs

### 8. Function Calling Without Validation
**Risk:** Arbitrary function execution, excessive agency
- **Finding:** `CONFIG_005` - Function Calling Without Schema Validation
- **Fix:** Implement strict JSON schema validation, whitelist functions

## Project Structure

```
llm-config-scanner/
├── main.go                 # CLI entry point
├── scanner/
│   ├── scanner.go         # Core scanning engine
│   ├── parser.go          # Config file parsers
│   ├── rules.go           # Rules engine
│   └── types.go           # Data structures
├── rules.yaml             # Detection rules (customizable)
├── README.md
├── go.mod
└── go.sum
```

## Development

### Building

```bash
go build -o llm-config-scanner
```

### Running Tests

```bash
go test ./...
```

### Adding New Rules

1. Edit `rules.yaml`
2. Add your rule following the schema
3. Test with sample configs
4. Submit PR with rule + test cases

## Contributing

Contributions welcome! Please:

1. Ensure all rules have research citations
2. Add test cases for new rules
3. Update documentation
4. Follow Go best practices

## License

MIT License - see LICENSE file

## References

### Key Research Papers

1. **Catastrophic Jailbreak of Open-source LLMs** (Princeton, 2023)
   - arXiv:2310.06987
   - 95%+ attack success through parameter manipulation

2. **Can LLMs Have a Fever?** (IEOM 2024)
   - DOI: 10.46254/SA05.20240024
   - Temperature security analysis across models

3. **Logits of API-Protected LLMs Leak Information** (2024)
   - arXiv:2403.09539v3
   - Logit_bias information leakage vulnerabilities

4. **FlexLLM: Moving Target Defense** (2024)
   - arXiv:2412.07672
   - Parameter space vulnerability heatmaps

### Security Frameworks

- OWASP LLM Top 10 2025
- NIST AI 800-1
- OWASP API Security Top 10

### CVEs

- CVE-2024-3271 - Flowise credential exposure (45% of servers)
- CVE-2025-32711 - Microsoft 365 Copilot EchoLeak
- Multiple LLM jacking incidents ($46K-$100K/day)

## Acknowledgments

Built based on comprehensive security research from:
- Princeton SysML
- OWASP Foundation
- Security researchers at IOActive, Sysdig, Wiz
- Academic institutions worldwide

---

**Security Note:** This tool helps identify configuration vulnerabilities but is not a substitute for comprehensive security testing. Always conduct thorough security reviews of LLM applications before production deployment.
