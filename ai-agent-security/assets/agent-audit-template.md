# AI Agent Security Audit Report

## Report Metadata

| Field | Value |
|-------|-------|
| **Report ID** | `{{REPORT_ID}}` |
| **Project** | `{{PROJECT_NAME}}` |
| **Scan Date** | `{{SCAN_DATE}}` |
| **Auditor** | Claude Code (ai-agent-security) |
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

### Agent Inventory

| Metric | Value |
|--------|-------|
| Frameworks Detected | {{FRAMEWORKS}} |
| Agent Definitions | {{AGENT_COUNT}} |
| Tool Definitions | {{TOOL_COUNT}} |
| Files Scanned | {{FILES_SCANNED}} |

### Key Findings

{{EXECUTIVE_SUMMARY}}

---

## 1. Agent Architecture Analysis

### 1.1 Detected Frameworks

| Framework | Version | Agent Count | Tools |
|-----------|---------|-------------|-------|
{{FRAMEWORK_TABLE}}

### 1.2 Agent Inventory

| Agent Name | Type | Tools | Risk Level |
|------------|------|-------|------------|
{{AGENT_INVENTORY_TABLE}}

---

## 2. OWASP LLM Top 10 Assessment

### 2.1 Coverage Matrix

| ID | Vulnerability | Status | Findings | Severity |
|----|---------------|--------|----------|----------|
| LLM01 | Prompt Injection | {{LLM01_STATUS}} | {{LLM01_COUNT}} | {{LLM01_SEV}} |
| LLM02 | Sensitive Info Disclosure | {{LLM02_STATUS}} | {{LLM02_COUNT}} | {{LLM02_SEV}} |
| LLM03 | Supply Chain | {{LLM03_STATUS}} | {{LLM03_COUNT}} | {{LLM03_SEV}} |
| LLM04 | Data/Model Poisoning | {{LLM04_STATUS}} | {{LLM04_COUNT}} | {{LLM04_SEV}} |
| LLM05 | Improper Output Handling | {{LLM05_STATUS}} | {{LLM05_COUNT}} | {{LLM05_SEV}} |
| **LLM06** | **Excessive Agency** | {{LLM06_STATUS}} | {{LLM06_COUNT}} | {{LLM06_SEV}} |
| LLM07 | System Prompt Leakage | {{LLM07_STATUS}} | {{LLM07_COUNT}} | {{LLM07_SEV}} |
| LLM08 | Vector/Embedding Weaknesses | {{LLM08_STATUS}} | {{LLM08_COUNT}} | {{LLM08_SEV}} |
| LLM09 | Misinformation | {{LLM09_STATUS}} | {{LLM09_COUNT}} | {{LLM09_SEV}} |
| LLM10 | Unbounded Consumption | {{LLM10_STATUS}} | {{LLM10_COUNT}} | {{LLM10_SEV}} |

---

## 3. Excessive Agency Analysis (LLM06)

### 3.1 Summary

| Risk Factor | Status | Details |
|-------------|--------|---------|
| Unrestricted Tool Access | {{TOOL_ACCESS_STATUS}} | {{TOOL_ACCESS_DETAILS}} |
| Missing Permission Boundaries | {{PERMISSION_STATUS}} | {{PERMISSION_DETAILS}} |
| Delegation Without Controls | {{DELEGATION_STATUS}} | {{DELEGATION_DETAILS}} |
| Admin-Level Capabilities | {{ADMIN_STATUS}} | {{ADMIN_DETAILS}} |

### 3.2 Tool Permission Audit

| Tool | Capabilities | Risk Level | Recommendation |
|------|--------------|------------|----------------|
{{TOOL_PERMISSION_TABLE}}

### 3.3 Findings

{{EXCESSIVE_AGENCY_FINDINGS}}

---

## 4. Tool Security Analysis

### 4.1 Tool Risk Classification

| Risk Level | Count | Examples |
|------------|-------|----------|
| CRITICAL | {{TOOL_CRITICAL}} | Code execution, shell access |
| HIGH | {{TOOL_HIGH}} | File write, database access |
| MEDIUM | {{TOOL_MEDIUM}} | Network requests, file read |
| LOW | {{TOOL_LOW}} | Read-only operations |

### 4.2 Dangerous Tool Patterns

{{DANGEROUS_TOOL_PATTERNS}}

### 4.3 Recommendations

{{TOOL_RECOMMENDATIONS}}

---

## 5. Agent Configuration Security

### 5.1 Resource Limits

| Agent | max_iterations | max_execution_time | Status |
|-------|----------------|-------------------|--------|
{{RESOURCE_LIMITS_TABLE}}

### 5.2 Error Handling

| Agent | handle_parsing_errors | Verbose Mode | Status |
|-------|----------------------|--------------|--------|
{{ERROR_HANDLING_TABLE}}

### 5.3 Recommendations

{{CONFIG_RECOMMENDATIONS}}

---

## 6. Prompt Injection Defense

### 6.1 Input Validation

| Location | Validation Type | Status |
|----------|-----------------|--------|
{{INPUT_VALIDATION_TABLE}}

### 6.2 Prompt Construction

| Pattern | Risk | Location | Fix |
|---------|------|----------|-----|
{{PROMPT_CONSTRUCTION_TABLE}}

### 6.3 Recommendations

{{PROMPT_INJECTION_RECOMMENDATIONS}}

---

## 7. Memory and State Security

### 7.1 Memory Configuration

| Agent | Memory Type | Limit | Encryption | Status |
|-------|-------------|-------|------------|--------|
{{MEMORY_CONFIG_TABLE}}

### 7.2 State Isolation

| Concern | Status | Details |
|---------|--------|---------|
| User Isolation | {{USER_ISOLATION}} | {{USER_ISOLATION_DETAILS}} |
| Session Isolation | {{SESSION_ISOLATION}} | {{SESSION_ISOLATION_DETAILS}} |
| Cross-Agent Leakage | {{CROSS_AGENT}} | {{CROSS_AGENT_DETAILS}} |

### 7.3 Recommendations

{{MEMORY_RECOMMENDATIONS}}

---

## 8. Multi-Agent Security

### 8.1 Communication Analysis

| Source Agent | Target Agent | Channel | Validation |
|--------------|--------------|---------|------------|
{{AGENT_COMMUNICATION_TABLE}}

### 8.2 Trust Model

| Agent | Trust Level | Can Delegate | Permissions |
|-------|-------------|--------------|-------------|
{{TRUST_MODEL_TABLE}}

### 8.3 Recommendations

{{MULTI_AGENT_RECOMMENDATIONS}}

---

## 9. Sandboxing Assessment

### 9.1 Isolation Levels

| Component | Isolation Level | Method | Status |
|-----------|----------------|--------|--------|
| Code Execution | {{CODE_ISOLATION}} | {{CODE_METHOD}} | {{CODE_STATUS}} |
| File System | {{FS_ISOLATION}} | {{FS_METHOD}} | {{FS_STATUS}} |
| Network | {{NET_ISOLATION}} | {{NET_METHOD}} | {{NET_STATUS}} |
| Resources | {{RES_ISOLATION}} | {{RES_METHOD}} | {{RES_STATUS}} |

### 9.2 Container Configuration

```yaml
{{CONTAINER_CONFIG}}
```

### 9.3 Recommendations

{{SANDBOXING_RECOMMENDATIONS}}

---

## 10. Detailed Findings

### 10.1 CRITICAL Findings

{{CRITICAL_FINDINGS}}

### 10.2 HIGH Findings

{{HIGH_FINDINGS}}

### 10.3 MEDIUM Findings

{{MEDIUM_FINDINGS}}

### 10.4 LOW Findings

{{LOW_FINDINGS}}

---

## 11. Remediation Roadmap

### Immediate Actions (0-7 days)

{{REMEDIATION_IMMEDIATE}}

### Short-term Actions (1-4 weeks)

{{REMEDIATION_SHORT_TERM}}

### Long-term Actions (1-3 months)

{{REMEDIATION_LONG_TERM}}

---

## 12. Appendices

### A. Scan Configuration

```json
{{SCAN_CONFIG}}
```

### B. Files Scanned

```
{{FILES_SCANNED_LIST}}
```

### C. Detection Patterns Used

| Category | Patterns | Matches |
|----------|----------|---------|
{{PATTERN_TABLE}}

### D. Tool Versions

| Tool | Version |
|------|---------|
| ai-agent-security | {{TOOL_VERSION}} |
| Python | {{PYTHON_VERSION}} |

### E. References

- [OWASP LLM Top 10:2025](https://genai.owasp.org/)
- [LLM06 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [LangChain Security Best Practices](https://python.langchain.com/docs/security)
- [RestrictedPython Documentation](https://restrictedpython.readthedocs.io/)

---

## Report Generation

Generated by: `ai-agent-security` Claude Code Skill
Template Version: 1.0
Report Format: Markdown

---

*This report was automatically generated. Please review all findings and recommendations before taking action.*
