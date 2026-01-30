# AI/ML Supply Chain Security Audit Report

## Report Metadata

| Field | Value |
|-------|-------|
| **Report ID** | `{{REPORT_ID}}` |
| **Project** | `{{PROJECT_NAME}}` |
| **Scan Date** | `{{SCAN_DATE}}` |
| **Scan Duration** | `{{SCAN_DURATION}}` |
| **Auditor** | Claude Code (llm-supply-chain-audit) |
| **Report Version** | 1.0 |

---

## Executive Summary

### Risk Score: {{RISK_SCORE}}/100

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | {{CRITICAL_COUNT}} | {{CRITICAL_STATUS}} |
| HIGH | {{HIGH_COUNT}} | {{HIGH_STATUS}} |
| MEDIUM | {{MEDIUM_COUNT}} | {{MEDIUM_STATUS}} |
| LOW | {{LOW_COUNT}} | {{LOW_STATUS}} |

### Key Findings

{{EXECUTIVE_SUMMARY}}

---

## 1. Package Dependency Audit

### 1.1 Summary

| Metric | Value |
|--------|-------|
| Total packages scanned | {{PKG_TOTAL}} |
| Verified packages | {{PKG_VERIFIED}} |
| Suspicious packages | {{PKG_SUSPICIOUS}} |
| Non-existent packages | {{PKG_NONEXISTENT}} |

### 1.2 Slopsquatting Detection

Packages that may be AI-hallucinated names:

| Package | Registry | Status | Risk Level | Details |
|---------|----------|--------|------------|---------|
{{SLOPSQUATTING_TABLE}}

### 1.3 Typosquatting Detection

Packages similar to popular libraries:

| Package | Similar To | Distance | Risk Level |
|---------|------------|----------|------------|
{{TYPOSQUATTING_TABLE}}

### 1.4 Package Age Analysis

Recently published packages (< 30 days):

| Package | First Published | Downloads | Risk |
|---------|-----------------|-----------|------|
{{PACKAGE_AGE_TABLE}}

### 1.5 Recommendations

{{PACKAGE_RECOMMENDATIONS}}

---

## 2. Model File Security Audit

### 2.1 Summary

| Metric | Value |
|--------|-------|
| Total model files | {{MODEL_TOTAL}} |
| Safe formats (.safetensors, .gguf) | {{MODEL_SAFE}} |
| Risky formats (.pt, .pkl, .joblib) | {{MODEL_RISKY}} |
| Files with suspicious patterns | {{MODEL_SUSPICIOUS}} |

### 2.2 Model Files by Risk Level

#### CRITICAL Risk (Pickle-based)

| File | Format | Size | Suspicious Patterns |
|------|--------|------|---------------------|
{{MODEL_CRITICAL_TABLE}}

#### HIGH Risk

| File | Format | Size | Notes |
|------|--------|------|-------|
{{MODEL_HIGH_TABLE}}

#### SAFE Formats

| File | Format | Size |
|------|--------|------|
{{MODEL_SAFE_TABLE}}

### 2.3 Suspicious Patterns Detected

```
{{MODEL_SUSPICIOUS_PATTERNS}}
```

### 2.4 Recommendations

{{MODEL_RECOMMENDATIONS}}

---

## 3. Code Pattern Analysis

### 3.1 Unsafe Model Loading

| Location | Pattern | Severity | Recommendation |
|----------|---------|----------|----------------|
{{CODE_MODEL_LOADING_TABLE}}

### 3.2 Remote Code Execution Risks

| Location | Pattern | Severity | Details |
|----------|---------|----------|---------|
{{CODE_RCE_TABLE}}

### 3.3 Recommendations

{{CODE_RECOMMENDATIONS}}

---

## 4. MCP Server Configuration Audit

### 4.1 Summary

| Metric | Value |
|--------|-------|
| MCP config files found | {{MCP_CONFIG_COUNT}} |
| Servers configured | {{MCP_SERVER_COUNT}} |
| Remote servers | {{MCP_REMOTE_COUNT}} |
| Suspicious configurations | {{MCP_SUSPICIOUS_COUNT}} |

### 4.2 Server Analysis

| Server Name | Transport | Risk Level | Issues |
|-------------|-----------|------------|--------|
{{MCP_SERVER_TABLE}}

### 4.3 CVE-2025-54136 (MCPoison) Check

{{MCP_POISON_STATUS}}

### 4.4 Recommendations

{{MCP_RECOMMENDATIONS}}

---

## 5. CI/CD Pipeline Security

### 5.1 Workflow Analysis

| Workflow | Secrets Exposed | External Actions | Risk |
|----------|-----------------|------------------|------|
{{CICD_WORKFLOW_TABLE}}

### 5.2 Dependency Installation Security

| File | Method | Pinned Versions | Hash Verification |
|------|--------|-----------------|-------------------|
{{CICD_DEPS_TABLE}}

### 5.3 Recommendations

{{CICD_RECOMMENDATIONS}}

---

## 6. Detailed Findings

### 6.1 CRITICAL Findings

{{CRITICAL_FINDINGS}}

### 6.2 HIGH Findings

{{HIGH_FINDINGS}}

### 6.3 MEDIUM Findings

{{MEDIUM_FINDINGS}}

### 6.4 LOW Findings

{{LOW_FINDINGS}}

---

## 7. Remediation Roadmap

### Immediate Actions (0-7 days)

{{REMEDIATION_IMMEDIATE}}

### Short-term Actions (1-4 weeks)

{{REMEDIATION_SHORT_TERM}}

### Long-term Actions (1-3 months)

{{REMEDIATION_LONG_TERM}}

---

## 8. Compliance Matrix

### OWASP LLM Top 10:2025 Coverage

| ID | Vulnerability | Status | Findings |
|----|---------------|--------|----------|
| LLM01 | Prompt Injection | {{LLM01_STATUS}} | {{LLM01_FINDINGS}} |
| LLM02 | Sensitive Information Disclosure | {{LLM02_STATUS}} | {{LLM02_FINDINGS}} |
| LLM03 | Supply Chain Vulnerabilities | {{LLM03_STATUS}} | {{LLM03_FINDINGS}} |
| LLM04 | Data and Model Poisoning | {{LLM04_STATUS}} | {{LLM04_FINDINGS}} |
| LLM05 | Improper Output Handling | {{LLM05_STATUS}} | {{LLM05_FINDINGS}} |
| LLM06 | Excessive Agency | {{LLM06_STATUS}} | {{LLM06_FINDINGS}} |
| LLM07 | System Prompt Leakage | {{LLM07_STATUS}} | {{LLM07_FINDINGS}} |
| LLM08 | Vector and Embedding Weaknesses | {{LLM08_STATUS}} | {{LLM08_FINDINGS}} |
| LLM09 | Misinformation | {{LLM09_STATUS}} | {{LLM09_FINDINGS}} |
| LLM10 | Unbounded Consumption | {{LLM10_STATUS}} | {{LLM10_FINDINGS}} |

---

## 9. Appendices

### A. Scan Configuration

```json
{{SCAN_CONFIG}}
```

### B. Files Scanned

```
{{FILES_SCANNED}}
```

### C. Tool Versions

| Tool | Version |
|------|---------|
| llm-supply-chain-audit | {{TOOL_VERSION}} |
| Python | {{PYTHON_VERSION}} |
| pip-audit | {{PIP_AUDIT_VERSION}} |

### D. References

- [OWASP LLM Top 10:2025](https://genai.owasp.org/)
- [Safetensors Documentation](https://huggingface.co/docs/safetensors/)
- [CVE-2025-54136 (MCPoison)](https://nvd.nist.gov/vuln/detail/CVE-2025-54136)
- [Slopsquatting Research](https://arxiv.org/abs/2406.XXXXX)

---

## Report Generation

Generated by: `llm-supply-chain-audit` Claude Code Skill
Template Version: 1.0
Report Format: Markdown

---

*This report was automatically generated. Please review all findings and recommendations before taking action.*
