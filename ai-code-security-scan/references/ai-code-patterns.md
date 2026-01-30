# AI Code Vulnerability Detection Patterns

## Contents
- AI API Key Patterns
- AI Framework Misconfigurations
- Dangerous AI Code Patterns
- AI-Generated Code Weaknesses
- Regex Pattern Reference

---

## AI API Key Patterns

### Risk Level: CRITICAL

```python
SECRET_PATTERNS = [
    # OpenAI
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}",
        "severity": "CRITICAL",
        "description": "OpenAI API key (legacy format)",
    },
    {
        "name": "OpenAI Project API Key",
        "pattern": r"sk-proj-[a-zA-Z0-9_-]{80,}",
        "severity": "CRITICAL",
        "description": "OpenAI project-scoped API key",
    },

    # Anthropic
    {
        "name": "Anthropic API Key",
        "pattern": r"sk-ant-api\d{2}-[a-zA-Z0-9_-]{80,}",
        "severity": "CRITICAL",
        "description": "Anthropic Claude API key",
    },

    # Google AI
    {
        "name": "Google AI API Key",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "CRITICAL",
        "description": "Google AI / Gemini API key",
    },

    # Cohere
    {
        "name": "Cohere API Key",
        "pattern": r"(?i)cohere[_-]?api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9]{40}['\"]",
        "severity": "CRITICAL",
        "description": "Cohere API key",
    },

    # Hugging Face
    {
        "name": "Hugging Face Token",
        "pattern": r"hf_[a-zA-Z0-9]{34,}",
        "severity": "HIGH",
        "description": "Hugging Face access token",
    },

    # Pinecone
    {
        "name": "Pinecone API Key",
        "pattern": r"(?i)pinecone[_-]?api[_-]?key\s*[=:]\s*['\"][a-f0-9-]{36}['\"]",
        "severity": "HIGH",
        "description": "Pinecone vector database API key",
    },

    # Replicate
    {
        "name": "Replicate API Token",
        "pattern": r"r8_[a-zA-Z0-9]{37}",
        "severity": "HIGH",
        "description": "Replicate API token",
    },

    # OpenRouter
    {
        "name": "OpenRouter API Key",
        "pattern": r"sk-or-v1-[a-f0-9]{64}",
        "severity": "CRITICAL",
        "description": "OpenRouter API key",
    },

    # Weights & Biases
    {
        "name": "Weights & Biases API Key",
        "pattern": r"(?i)wandb[_-]?api[_-]?key\s*[=:]\s*['\"][a-f0-9]{40}['\"]",
        "severity": "HIGH",
        "description": "Weights & Biases API key",
    },
]
```

---

## AI Framework Misconfigurations

### LangChain Misconfigurations

```python
LANGCHAIN_PATTERNS = [
    # Verbose mode in production
    {
        "name": "LangChain Verbose Mode",
        "pattern": r"verbose\s*=\s*True",
        "severity": "MEDIUM",
        "context": ["langchain", "LLMChain", "AgentExecutor"],
        "description": "Verbose mode exposes internal chain reasoning in production",
        "fix": "Set verbose=False in production environments",
    },

    # Callbacks logging sensitive data
    {
        "name": "Stdout Callback in Production",
        "pattern": r"StdOutCallbackHandler\(\)",
        "severity": "MEDIUM",
        "description": "Stdout callbacks may log prompts and responses",
        "fix": "Use custom callbacks that sanitize output in production",
    },

    # Unsafe agent types
    {
        "name": "Unsafe Agent with Code Execution",
        "pattern": r"create_python_agent|create_csv_agent|PythonREPLTool",
        "severity": "HIGH",
        "description": "Agent with code execution capability can be exploited via prompt injection",
        "fix": "Use sandboxed execution or restrict to read-only operations",
    },

    # No error handling in chains
    {
        "name": "Chain Without Error Handling",
        "pattern": r"\.invoke\(.*\)(?!\s*#.*error|\s*except|\s*try)",
        "severity": "LOW",
        "description": "Chain invocation without error handling may expose stack traces",
        "fix": "Wrap chain invocations in try/except blocks",
    },

    # Deprecated imports
    {
        "name": "Deprecated LangChain Import",
        "pattern": r"from langchain\.(llms|chat_models|embeddings)\s+import",
        "severity": "INFO",
        "description": "Using deprecated LangChain import paths (pre-0.2)",
        "fix": "Use langchain_openai, langchain_anthropic, etc.",
    },
]
```

### OpenAI SDK Misconfigurations

```python
OPENAI_PATTERNS = [
    # No timeout configured
    {
        "name": "OpenAI Client Without Timeout",
        "pattern": r"OpenAI\((?!.*timeout)",
        "severity": "MEDIUM",
        "description": "No timeout configured; may hang indefinitely",
        "fix": "Set timeout: OpenAI(timeout=30.0)",
    },

    # No max_tokens limit
    {
        "name": "No Max Tokens Limit",
        "pattern": r"\.create\((?!.*max_tokens)(?!.*max_completion_tokens)",
        "severity": "MEDIUM",
        "context": ["chat.completions", "completions"],
        "description": "No token limit; may generate excessive output",
        "fix": "Set max_tokens to appropriate limit",
    },

    # Streaming without error handling
    {
        "name": "Streaming Without Error Handling",
        "pattern": r"stream\s*=\s*True(?!.*try|.*except|.*error)",
        "severity": "LOW",
        "description": "Streaming response without error handling for broken connections",
        "fix": "Add try/except around stream iteration",
    },
]
```

---

## Dangerous AI Code Patterns

### Critical Patterns

```python
DANGEROUS_PATTERNS = [
    # LLM output execution
    {
        "name": "Executing LLM Output",
        "pattern": r"(eval|exec)\s*\(.*\.(content|text|output|result)",
        "severity": "CRITICAL",
        "description": "Executing LLM-generated code without sandboxing leads to RCE",
    },

    # LLM output in SQL
    {
        "name": "LLM Output in SQL Query",
        "pattern": r"(execute|cursor)\s*\(.*\.(content|text|output)",
        "severity": "CRITICAL",
        "description": "LLM output used directly in SQL query enables injection",
    },

    # LLM output in shell commands
    {
        "name": "LLM Output in Shell Command",
        "pattern": r"(os\.system|subprocess\.(run|call|Popen))\s*\(.*\.(content|text|output)",
        "severity": "CRITICAL",
        "description": "LLM output used in shell command enables command injection",
    },

    # Unvalidated model loading
    {
        "name": "Unvalidated Model Source",
        "pattern": r"(from_pretrained|load_model|torch\.load)\s*\(.*(?:request|input|param|arg|user|query)",
        "severity": "CRITICAL",
        "description": "Loading model from user-controlled source enables RCE via pickle",
    },

    # Dynamic tool creation from LLM output
    {
        "name": "Dynamic Tool from LLM",
        "pattern": r"Tool\(.*func\s*=\s*.*\.(content|text|output)",
        "severity": "CRITICAL",
        "description": "Creating tools from LLM output enables arbitrary code execution",
    },
]
```

---

## AI-Generated Code Weaknesses

Common patterns in code generated by AI assistants that introduce vulnerabilities.

### Error Handling Anti-Patterns

```python
# AI often generates broad exception catching
try:
    result = api_call()
except Exception:  # Too broad - hides real errors
    pass

# AI often skips input validation
@app.post("/process")
async def process(data: dict):  # No Pydantic model, no validation
    return {"result": data["value"]}  # KeyError possible
```

### Insecure Defaults

```python
# AI often uses debug/development defaults
app = FastAPI(debug=True)  # Debug mode
CORS(app, origins=["*"])   # Allow all origins
SECRET_KEY = "changeme"    # Placeholder secret
```

### Detection Regex

```python
AI_GENERATED_WEAKNESS_PATTERNS = [
    {
        "name": "Broad Exception Catch",
        "pattern": r"except\s+(Exception|BaseException)\s*:",
        "severity": "LOW",
        "description": "Overly broad exception handling (common AI-generated pattern)",
    },
    {
        "name": "Wildcard CORS",
        "pattern": r"(allow_origins|origins)\s*=\s*\[\s*['\"]?\*['\"]?\s*\]",
        "severity": "HIGH",
        "description": "CORS allows all origins (common AI-generated insecure default)",
    },
    {
        "name": "Placeholder Secret",
        "pattern": r"(secret|key|password)\s*=\s*['\"]?(changeme|password|secret|admin|test|default)['\"]?",
        "severity": "HIGH",
        "description": "Placeholder secret left in code (common AI-generated oversight)",
    },
    {
        "name": "Debug Mode Enabled",
        "pattern": r"debug\s*=\s*True",
        "severity": "HIGH",
        "description": "Debug mode enabled (common AI-generated default)",
    },
    {
        "name": "No Input Validation",
        "pattern": r"def\s+\w+\(.*:\s*dict\s*\)",
        "severity": "MEDIUM",
        "description": "Raw dict parameter without Pydantic validation",
    },
    {
        "name": "Hardcoded URL",
        "pattern": r"(http://localhost|http://127\.0\.0\.1|http://0\.0\.0\.0):\d+",
        "severity": "LOW",
        "description": "Hardcoded localhost URL (should use environment variable)",
    },
]
```

---

## Regex Pattern Reference

Complete regex patterns for automated scanning:

```python
ALL_PATTERNS = {
    "critical": [
        r"sk-[a-zA-Z0-9]{20,}",                          # OpenAI key
        r"sk-ant-api\d{2}-[a-zA-Z0-9_-]{80,}",           # Anthropic key
        r"sk-proj-[a-zA-Z0-9_-]{80,}",                    # OpenAI project key
        r"sk-or-v1-[a-f0-9]{64}",                         # OpenRouter key
        r"(eval|exec)\s*\(.*\.(content|text|output)",      # LLM output execution
        r"torch\.load\(.*(?:user|input|request)",          # Unsafe model loading
        r"pickle\.loads?\(.*(?:user|input|request)",        # Pickle deserialization
    ],
    "high": [
        r"hf_[a-zA-Z0-9]{34,}",                           # HuggingFace token
        r"r8_[a-zA-Z0-9]{37}",                            # Replicate token
        r"AIza[0-9A-Za-z_-]{35}",                          # Google AI key
        r"create_python_agent|PythonREPLTool",             # Code execution agent
        r"load_tools\(.*shell",                            # Shell tool
        r"(allow_origins|origins)\s*=\s*\[\s*['\"]?\*",   # Wildcard CORS
    ],
    "medium": [
        r"verbose\s*=\s*True",                             # Verbose mode
        r"StdOutCallbackHandler",                          # Stdout callback
        r"debug\s*=\s*True",                               # Debug mode
        r"log.*\.(info|debug).*prompt",                    # Logging prompts
        r"ConversationBufferMemory\(\)",                    # Unbounded memory
    ],
}
```
