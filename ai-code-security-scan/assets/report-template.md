# AI Code Security Scan Report

## Report Metadata
| Field | Value |
|-------|-------|
| **Project** | `[PROJECT_PATH]` |
| **Scan Date** | `[SCAN_DATE]` |
| **Scan Type** | `[Quick/Full]` |
| **Scanner Version** | `ai-code-security-scan v1.0` |
| **Files Scanned** | `[COUNT]` |
| **Frameworks Detected** | `[FRAMEWORKS]` |

---

## Executive Summary

### Risk Overview

| Severity | Count | Action Required |
|----------|-------|-----------------|
| 🔴 CRITICAL | `[COUNT]` | Immediate fix required |
| 🟠 HIGH | `[COUNT]` | Fix before deployment |
| 🟡 MEDIUM | `[COUNT]` | Fix in next release |
| 🟢 LOW | `[COUNT]` | Consider fixing |
| ℹ️ INFO | `[COUNT]` | Informational |

### Key Findings

1. **[FINDING_TITLE_1]** - `[SEVERITY]`
   - Location: `[FILE:LINE]`
   - Impact: `[IMPACT_DESCRIPTION]`

2. **[FINDING_TITLE_2]** - `[SEVERITY]`
   - Location: `[FILE:LINE]`
   - Impact: `[IMPACT_DESCRIPTION]`

3. **[FINDING_TITLE_3]** - `[SEVERITY]`
   - Location: `[FILE:LINE]`
   - Impact: `[IMPACT_DESCRIPTION]`

---

## OWASP LLM Top 10:2025 Coverage

| ID | Category | Status | Findings |
|----|----------|--------|----------|
| LLM01 | Prompt Injection | ⬜ Not Scanned / ✅ Pass / ❌ Fail | `[COUNT]` |
| LLM02 | Sensitive Information Disclosure | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM03 | Supply Chain Vulnerabilities | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM04 | Data and Model Poisoning | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM05 | Insecure Output Handling | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM06 | Excessive Agency | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM07 | System Prompt Leakage | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM08 | Vector and Embedding Weaknesses | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM09 | Misinformation | ⬜ / ✅ / ❌ | `[COUNT]` |
| LLM10 | Unbounded Consumption | ⬜ / ✅ / ❌ | `[COUNT]` |

---

## Detailed Findings

### 🔴 CRITICAL Findings

#### [FINDING_ID]: [FINDING_TITLE]

| Field | Value |
|-------|-------|
| **OWASP ID** | `[LLM0X]` |
| **Category** | `[CATEGORY]` |
| **File** | `[FILE_PATH]:[LINE_NUMBER]` |
| **Severity** | CRITICAL |

**Code:**
```python
[CODE_SNIPPET]
```

**Description:**
[DETAILED_DESCRIPTION_OF_THE_VULNERABILITY]

**Risk:**
[EXPLANATION_OF_THE_SECURITY_RISK_AND_POTENTIAL_IMPACT]

**Remediation:**
```python
[FIXED_CODE_EXAMPLE]
```

**References:**
- [OWASP LLM Top 10 - LLM0X](https://genai.owasp.org/llm-top-10/)
- [Additional reference if applicable]

---

### 🟠 HIGH Findings

#### [FINDING_ID]: [FINDING_TITLE]

| Field | Value |
|-------|-------|
| **OWASP ID** | `[LLM0X]` |
| **Category** | `[CATEGORY]` |
| **File** | `[FILE_PATH]:[LINE_NUMBER]` |
| **Severity** | HIGH |

**Code:**
```python
[CODE_SNIPPET]
```

**Description:**
[DETAILED_DESCRIPTION]

**Risk:**
[RISK_EXPLANATION]

**Remediation:**
[FIX_RECOMMENDATION]

---

### 🟡 MEDIUM Findings

#### [FINDING_ID]: [FINDING_TITLE]

| Field | Value |
|-------|-------|
| **OWASP ID** | `[LLM0X]` |
| **Category** | `[CATEGORY]` |
| **File** | `[FILE_PATH]:[LINE_NUMBER]` |
| **Severity** | MEDIUM |

**Description:**
[DESCRIPTION]

**Remediation:**
[FIX]

---

### 🟢 LOW Findings

| Finding | File | Description | Fix |
|---------|------|-------------|-----|
| [TITLE] | `[FILE:LINE]` | [DESC] | [FIX] |

---

## Supply Chain Analysis

### Dependency Check Results

| Package | Registry | Status | Age | Risk Level | Notes |
|---------|----------|--------|-----|------------|-------|
| `[PACKAGE_NAME]` | PyPI/npm | ✅ Exists / ❌ Missing | [DAYS] days | [RISK] | [NOTES] |

### Hallucinated Packages Detected

⚠️ **WARNING**: The following packages do not exist and may be AI hallucinations:

| Package | Source File | Registry | Action |
|---------|-------------|----------|--------|
| `[PACKAGE]` | `[FILE]` | PyPI/npm | Remove immediately |

### Model Loading Security

| Pattern | File | Risk | Recommendation |
|---------|------|------|----------------|
| `torch.load()` | `[FILE:LINE]` | CRITICAL | Use safetensors |
| `pickle.load()` | `[FILE:LINE]` | CRITICAL | Use safe formats |

---

## AI Framework-Specific Findings

### LangChain

| Pattern | Count | Risk | Location |
|---------|-------|------|----------|
| `AgentExecutor` without `max_iterations` | [N] | HIGH | [FILES] |
| `PythonREPLTool` | [N] | CRITICAL | [FILES] |
| `verbose=True` | [N] | MEDIUM | [FILES] |

### OpenAI SDK

| Pattern | Count | Risk | Location |
|---------|-------|------|----------|
| No timeout configured | [N] | MEDIUM | [FILES] |
| No max_tokens limit | [N] | MEDIUM | [FILES] |

### Hardcoded Secrets

| Type | File | Line | Status |
|------|------|------|--------|
| OpenAI API Key | `[FILE]` | [LINE] | ❌ Exposed |
| Anthropic API Key | `[FILE]` | [LINE] | ❌ Exposed |

---

## Recommendations

### Immediate Actions (CRITICAL/HIGH)

1. **[ACTION_1]**
   - Remove/fix: `[SPECIFIC_FILE:LINE]`
   - Why: [REASON]
   - How: [STEPS]

2. **[ACTION_2]**
   - Remove/fix: `[SPECIFIC_FILE:LINE]`
   - Why: [REASON]
   - How: [STEPS]

### Short-term Actions (MEDIUM)

1. [ACTION_DESCRIPTION]
2. [ACTION_DESCRIPTION]

### Best Practices

- [ ] Use environment variables for all API keys
- [ ] Implement input validation for all user-provided content
- [ ] Add rate limiting to LLM endpoints
- [ ] Use safetensors format for model files
- [ ] Set `trust_remote_code=False` when loading models
- [ ] Add `max_iterations` to all AgentExecutors
- [ ] Implement human-in-the-loop for sensitive operations
- [ ] Sanitize logs to remove PII and prompts
- [ ] Use lockfiles for all dependencies
- [ ] Verify packages exist before installation

---

## Appendix

### Scan Configuration

```json
{
  "scan_type": "[Quick/Full]",
  "severity_filter": "[CRITICAL/HIGH/MEDIUM/LOW]",
  "excluded_dirs": [".venv", "node_modules", ".git"],
  "frameworks_checked": ["langchain", "openai", "anthropic"]
}
```

### Files Scanned

<details>
<summary>Click to expand file list ([COUNT] files)</summary>

```
[FILE_LIST]
```

</details>

### Pattern Definitions

This scan used detection patterns based on:
- OWASP LLM Top 10:2025
- AI-specific security research
- Known vulnerability patterns in LangChain, OpenAI, and Anthropic SDKs

---

## Report Footer

| Generated By | ai-code-security-scan |
|--------------|----------------------|
| Date | [DATE] |
| Version | 1.0 |
| Contact | [CONTACT_INFO] |

---

*This report was generated automatically. Please review findings manually before taking action.*
