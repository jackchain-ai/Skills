# Tool Permission Model

## Contents
- Tool Risk Classification
- Permission Enforcement
- Tool Sandboxing
- Rate Limiting
- Audit Logging

---

## Tool Risk Classification

### Risk Matrix

| Category | Risk Level | Examples | Mitigations Required |
|----------|------------|----------|---------------------|
| **Read-Only Data** | LOW | Search, lookup, read file | Input validation |
| **Write Data** | MEDIUM | Create file, update record | Authorization, validation |
| **External Network** | MEDIUM-HIGH | API calls, web requests | Allowlist, rate limits |
| **Code Execution** | CRITICAL | Run script, eval, exec | Sandbox, strict limits |
| **System Access** | CRITICAL | Shell, file system, process | Sandbox, minimal scope |
| **Privileged Actions** | CRITICAL | Delete user, admin ops | MFA, audit logging |

### Tool Classification by Framework

#### LangChain Tools

```python
LANGCHAIN_TOOL_RISK = {
    # LOW risk - read-only
    "wikipedia": "LOW",
    "arxiv": "LOW",
    "pubmed": "LOW",
    "google_search": "LOW",

    # MEDIUM risk - external APIs
    "requests": "MEDIUM",
    "serpapi": "MEDIUM",
    "openweathermap": "MEDIUM",

    # HIGH risk - code/file operations
    "python_repl": "CRITICAL",
    "bash": "CRITICAL",
    "file_management": "HIGH",
    "sql_database": "HIGH",

    # Custom tools - assess individually
    "custom": "ASSESS_REQUIRED",
}
```

#### Common Tool Patterns

```python
# CRITICAL - Never allow unrestricted
CRITICAL_PATTERNS = [
    r"subprocess\.(run|call|Popen)",
    r"os\.(system|popen|exec)",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__\s*\(",
    r"compile\s*\(",
]

# HIGH - Require strict validation
HIGH_RISK_PATTERNS = [
    r"open\s*\([^)]*['\"][wa]",  # File write
    r"requests\.(get|post|put|delete)",  # Network
    r"(sqlite3|psycopg2|pymysql)\.connect",  # Database
    r"shutil\.(copy|move|rmtree)",  # File operations
]

# MEDIUM - Require input validation
MEDIUM_RISK_PATTERNS = [
    r"open\s*\([^)]*['\"]r",  # File read
    r"json\.loads?\s*\(",  # Deserialization
    r"pickle\.loads?\s*\(",  # Unsafe deserialize (actually CRITICAL)
]
```

---

## Permission Enforcement

### Pattern 1: Tool Permission Decorator

```python
from functools import wraps
from typing import Callable, List, Optional
from enum import Enum

class Permission(Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    EXECUTE_CODE = "execute_code"
    NETWORK_ACCESS = "network_access"
    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    ADMIN_ACTION = "admin_action"


class PermissionDenied(Exception):
    """Raised when a tool lacks required permissions."""
    pass


class ToolPermissionManager:
    """Manage tool permissions per user/session."""

    def __init__(self):
        self._permissions: dict = {}

    def grant(self, user_id: str, permissions: List[Permission]):
        """Grant permissions to user."""
        if user_id not in self._permissions:
            self._permissions[user_id] = set()
        self._permissions[user_id].update(permissions)

    def revoke(self, user_id: str, permissions: List[Permission]):
        """Revoke permissions from user."""
        if user_id in self._permissions:
            self._permissions[user_id] -= set(permissions)

    def check(self, user_id: str, permission: Permission) -> bool:
        """Check if user has permission."""
        return permission in self._permissions.get(user_id, set())

    def require(self, *permissions: Permission):
        """Decorator to require permissions."""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, user_id: str = None, **kwargs):
                if not user_id:
                    raise PermissionDenied("User ID required")

                for perm in permissions:
                    if not self.check(user_id, perm):
                        raise PermissionDenied(
                            f"Missing permission: {perm.value}"
                        )

                return func(*args, **kwargs)
            return wrapper
        return decorator


# Global instance
permission_manager = ToolPermissionManager()


# Usage example
@permission_manager.require(Permission.READ_FILE)
def read_document(path: str, user_id: str = None) -> str:
    """Read document - requires READ_FILE permission."""
    # Implementation
    pass


@permission_manager.require(Permission.EXECUTE_CODE)
def run_python_code(code: str, user_id: str = None) -> str:
    """Execute Python - requires EXECUTE_CODE permission."""
    # Implementation (in sandbox!)
    pass
```

### Pattern 2: Path Restriction

```python
import os
from pathlib import Path
from typing import List, Optional

class PathRestrictor:
    """Restrict file access to allowed paths."""

    def __init__(self, allowed_paths: List[str], denied_paths: List[str] = None):
        self.allowed = [Path(p).resolve() for p in allowed_paths]
        self.denied = [Path(p).resolve() for p in (denied_paths or [])]

    def is_allowed(self, path: str) -> bool:
        """Check if path is within allowed directories."""
        try:
            resolved = Path(path).resolve()

            # Check denied paths first (blocklist)
            for denied in self.denied:
                if self._is_subpath(resolved, denied):
                    return False

            # Check allowed paths (allowlist)
            for allowed in self.allowed:
                if self._is_subpath(resolved, allowed):
                    return True

            return False
        except Exception:
            return False

    def _is_subpath(self, path: Path, parent: Path) -> bool:
        """Check if path is under parent."""
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False

    def validate(self, path: str) -> Path:
        """Validate and return resolved path, or raise error."""
        if not self.is_allowed(path):
            raise PermissionError(f"Access denied: {path}")
        return Path(path).resolve()


# Usage
restrictor = PathRestrictor(
    allowed_paths=["/data/public/", "/tmp/agent/"],
    denied_paths=["/data/public/secrets/"]
)

@tool
def read_file(path: str) -> str:
    """Read a file from allowed paths only."""
    safe_path = restrictor.validate(path)
    return safe_path.read_text()
```

### Pattern 3: URL Allowlisting

```python
from urllib.parse import urlparse
from typing import Set
import re

class URLAllowlist:
    """Restrict network access to allowed domains."""

    def __init__(self):
        self.allowed_domains: Set[str] = set()
        self.allowed_patterns: list = []
        self.blocked_domains: Set[str] = set()

    def add_domain(self, domain: str):
        """Add allowed domain (exact match)."""
        self.allowed_domains.add(domain.lower())

    def add_pattern(self, pattern: str):
        """Add allowed domain pattern (regex)."""
        self.allowed_patterns.append(re.compile(pattern, re.IGNORECASE))

    def block_domain(self, domain: str):
        """Block specific domain."""
        self.blocked_domains.add(domain.lower())

    def is_allowed(self, url: str) -> bool:
        """Check if URL is allowed."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]

            # Check blocklist first
            if domain in self.blocked_domains:
                return False

            # Check exact match
            if domain in self.allowed_domains:
                return True

            # Check patterns
            for pattern in self.allowed_patterns:
                if pattern.match(domain):
                    return True

            return False
        except Exception:
            return False

    def validate(self, url: str) -> str:
        """Validate URL or raise error."""
        if not self.is_allowed(url):
            raise PermissionError(f"URL not allowed: {url}")
        return url


# Usage
url_allowlist = URLAllowlist()
url_allowlist.add_domain("api.openai.com")
url_allowlist.add_domain("api.anthropic.com")
url_allowlist.add_pattern(r".*\.wikipedia\.org")
url_allowlist.block_domain("evil.com")

@tool
def fetch_url(url: str) -> str:
    """Fetch content from allowed URLs only."""
    safe_url = url_allowlist.validate(url)
    return requests.get(safe_url).text
```

---

## Tool Sandboxing

### Pattern 4: Docker Sandbox for Code Execution

```python
import docker
import tempfile
import os
from typing import Tuple

class DockerSandbox:
    """Execute code in isolated Docker container."""

    def __init__(
        self,
        image: str = "python:3.11-slim",
        memory_limit: str = "256m",
        cpu_period: int = 100000,
        cpu_quota: int = 50000,  # 50% of one CPU
        timeout: int = 30,
    ):
        self.client = docker.from_env()
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_period = cpu_period
        self.cpu_quota = cpu_quota
        self.timeout = timeout

    def execute(self, code: str) -> Tuple[str, str, int]:
        """
        Execute code in sandbox.
        Returns: (stdout, stderr, exit_code)
        """
        # Write code to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False
        ) as f:
            f.write(code)
            code_path = f.name

        try:
            container = self.client.containers.run(
                self.image,
                command=f"python /code/script.py",
                volumes={
                    code_path: {"bind": "/code/script.py", "mode": "ro"}
                },
                mem_limit=self.memory_limit,
                cpu_period=self.cpu_period,
                cpu_quota=self.cpu_quota,
                network_disabled=True,  # No network access
                read_only=True,  # Read-only filesystem
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
            )

            # container.run returns bytes directly when detach=False
            stdout = container.decode() if container else ""
            return stdout, "", 0

        except docker.errors.ContainerError as e:
            return "", str(e), e.exit_status
        except Exception as e:
            return "", str(e), 1
        finally:
            os.unlink(code_path)


# Usage
sandbox = DockerSandbox()

@tool
def run_python_safely(code: str) -> str:
    """Execute Python code in isolated sandbox."""
    stdout, stderr, exit_code = sandbox.execute(code)
    if exit_code != 0:
        return f"Error: {stderr}"
    return stdout
```

### Pattern 5: RestrictedPython Sandbox

```python
from RestrictedPython import compile_restricted, safe_globals
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import (
    guarded_iter_unpack_sequence,
    safer_getattr,
)
import io
import sys

class RestrictedPythonSandbox:
    """Execute Python with restricted builtins."""

    def __init__(self, max_output: int = 10000):
        self.max_output = max_output
        self.safe_builtins = self._get_safe_builtins()

    def _get_safe_builtins(self) -> dict:
        """Get restricted builtins."""
        safe = safe_globals.copy()
        safe["_getiter_"] = default_guarded_getiter
        safe["_iter_unpack_sequence_"] = guarded_iter_unpack_sequence
        safe["_getattr_"] = safer_getattr

        # Add safe builtins
        safe["__builtins__"] = {
            "len": len,
            "range": range,
            "str": str,
            "int": int,
            "float": float,
            "list": list,
            "dict": dict,
            "tuple": tuple,
            "set": set,
            "bool": bool,
            "min": min,
            "max": max,
            "sum": sum,
            "sorted": sorted,
            "enumerate": enumerate,
            "zip": zip,
            "map": map,
            "filter": filter,
            "print": self._safe_print,
        }

        return safe

    def _safe_print(self, *args, **kwargs):
        """Safe print that captures output."""
        output = io.StringIO()
        print(*args, file=output, **kwargs)
        return output.getvalue()

    def execute(self, code: str) -> str:
        """Execute restricted Python code."""
        try:
            # Compile with restrictions
            byte_code = compile_restricted(
                code,
                filename="<agent>",
                mode="exec",
            )

            if byte_code.errors:
                return f"Compilation errors: {byte_code.errors}"

            # Capture output
            output_buffer = io.StringIO()

            # Override print in globals
            exec_globals = self.safe_builtins.copy()
            exec_globals["_print_"] = lambda *args: print(
                *args, file=output_buffer
            )

            # Execute
            exec(byte_code.code, exec_globals)

            result = output_buffer.getvalue()
            if len(result) > self.max_output:
                result = result[:self.max_output] + "... [TRUNCATED]"

            return result

        except Exception as e:
            return f"Execution error: {str(e)}"
```

---

## Rate Limiting

### Pattern 6: Tool Rate Limiter

```python
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
import threading

class ToolRateLimiter:
    """Rate limit tool calls per user."""

    def __init__(self):
        self._calls = defaultdict(list)
        self._lock = threading.Lock()

        # Default limits per tool category
        self.limits = {
            "default": (100, timedelta(minutes=1)),  # 100/minute
            "expensive": (10, timedelta(minutes=1)),  # 10/minute
            "critical": (5, timedelta(minutes=5)),   # 5/5min
        }

    def set_limit(self, category: str, max_calls: int, window: timedelta):
        """Set rate limit for category."""
        self.limits[category] = (max_calls, window)

    def check(
        self,
        user_id: str,
        tool_name: str,
        category: str = "default"
    ) -> bool:
        """Check if call is allowed."""
        max_calls, window = self.limits.get(
            category, self.limits["default"]
        )
        key = f"{user_id}:{tool_name}"
        now = datetime.utcnow()
        cutoff = now - window

        with self._lock:
            # Clean old entries
            self._calls[key] = [
                t for t in self._calls[key]
                if t > cutoff
            ]

            # Check limit
            if len(self._calls[key]) >= max_calls:
                return False

            # Record this call
            self._calls[key].append(now)
            return True

    def get_remaining(
        self,
        user_id: str,
        tool_name: str,
        category: str = "default"
    ) -> int:
        """Get remaining calls in window."""
        max_calls, window = self.limits.get(
            category, self.limits["default"]
        )
        key = f"{user_id}:{tool_name}"
        now = datetime.utcnow()
        cutoff = now - window

        with self._lock:
            recent_calls = [
                t for t in self._calls[key]
                if t > cutoff
            ]
            return max(0, max_calls - len(recent_calls))


# Usage
rate_limiter = ToolRateLimiter()
rate_limiter.set_limit("api_call", 30, timedelta(minutes=1))
rate_limiter.set_limit("code_execution", 5, timedelta(minutes=5))

def rate_limited(category: str = "default"):
    """Decorator for rate limiting."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, user_id: str = None, **kwargs):
            tool_name = func.__name__
            if not rate_limiter.check(user_id, tool_name, category):
                remaining = rate_limiter.get_remaining(
                    user_id, tool_name, category
                )
                raise RateLimitError(
                    f"Rate limit exceeded for {tool_name}. "
                    f"Remaining: {remaining}"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


@rate_limited(category="api_call")
def call_external_api(endpoint: str, user_id: str = None) -> str:
    """Call external API with rate limiting."""
    pass
```

---

## Audit Logging

### Pattern 7: Tool Execution Audit Log

```python
import json
import logging
from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class ToolExecutionLog:
    """Structured tool execution log entry."""
    timestamp: str
    user_id: str
    tool_name: str
    tool_category: str
    input_summary: str
    output_summary: str
    execution_time_ms: int
    success: bool
    error: Optional[str] = None
    permissions_used: list = None
    rate_limit_remaining: Optional[int] = None


class ToolAuditLogger:
    """Audit log all tool executions."""

    def __init__(self, logger_name: str = "tool.audit"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)

    def log_execution(
        self,
        user_id: str,
        tool_name: str,
        tool_input: Any,
        tool_output: Any,
        execution_time_ms: int,
        success: bool,
        error: Optional[str] = None,
        category: str = "default",
        permissions: list = None,
    ):
        """Log tool execution."""
        # Summarize input/output (don't log full content)
        input_summary = self._summarize(tool_input)
        output_summary = self._summarize(tool_output)

        log_entry = ToolExecutionLog(
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            tool_name=tool_name,
            tool_category=category,
            input_summary=input_summary,
            output_summary=output_summary,
            execution_time_ms=execution_time_ms,
            success=success,
            error=error,
            permissions_used=permissions or [],
        )

        self.logger.info(json.dumps(asdict(log_entry)))

    def _summarize(self, data: Any, max_len: int = 200) -> str:
        """Create summary of data for logging."""
        if data is None:
            return "null"

        text = str(data)
        if len(text) > max_len:
            return text[:max_len] + "..."
        return text

    def log_permission_denied(
        self,
        user_id: str,
        tool_name: str,
        required_permission: str,
    ):
        """Log permission denied event."""
        self.logger.warning(json.dumps({
            "event": "PERMISSION_DENIED",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "tool_name": tool_name,
            "required_permission": required_permission,
        }))

    def log_rate_limit(
        self,
        user_id: str,
        tool_name: str,
        category: str,
    ):
        """Log rate limit exceeded event."""
        self.logger.warning(json.dumps({
            "event": "RATE_LIMIT_EXCEEDED",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "tool_name": tool_name,
            "category": category,
        }))
```

---

## Quick Reference

### Permission Levels

| Level | Can Do | Cannot Do | Example Tools |
|-------|--------|-----------|---------------|
| READ | Read public data | Write, execute, network | search, lookup |
| WRITE | Read + write data | Execute, admin | create_file, update_record |
| NETWORK | Read + external API | Local write, execute | fetch_url, api_call |
| EXECUTE | Run code in sandbox | System access, admin | python_repl (sandboxed) |
| ADMIN | All privileged ops | - | delete_user, system_config |

### Tool Security Checklist

```
Before adding a new tool:
□ Classify risk level (LOW/MEDIUM/HIGH/CRITICAL)
□ Define required permissions
□ Implement input validation
□ Add path/URL restrictions if applicable
□ Set up rate limits
□ Configure audit logging
□ Test in sandbox environment
□ Document security considerations
```
