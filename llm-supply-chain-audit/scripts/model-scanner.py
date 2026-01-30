#!/usr/bin/env python3
"""
Model File Security Scanner

Scans directories for ML model files and assesses their security risk.
Detects unsafe formats (pickle, joblib), checks for suspicious patterns,
and recommends safetensors migration.

Usage:
    python model-scanner.py /path/to/project [--deep] [--json]
"""

import argparse
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ModelFinding:
    """A security finding related to a model file."""
    severity: str
    file_path: str
    file_size_mb: float
    format_type: str
    description: str
    recommendation: str
    suspicious_patterns: list = field(default_factory=list)


# Model format definitions
MODEL_FORMATS = {
    ".pt": {"name": "PyTorch", "risk": "CRITICAL", "uses_pickle": True},
    ".pth": {"name": "PyTorch", "risk": "CRITICAL", "uses_pickle": True},
    ".bin": {"name": "PyTorch/Generic", "risk": "HIGH", "uses_pickle": True},
    ".pkl": {"name": "Pickle", "risk": "CRITICAL", "uses_pickle": True},
    ".pickle": {"name": "Pickle", "risk": "CRITICAL", "uses_pickle": True},
    ".joblib": {"name": "Joblib", "risk": "CRITICAL", "uses_pickle": True},
    ".h5": {"name": "Keras HDF5", "risk": "HIGH", "uses_pickle": False},
    ".hdf5": {"name": "HDF5", "risk": "HIGH", "uses_pickle": False},
    ".keras": {"name": "Keras", "risk": "HIGH", "uses_pickle": False},
    ".onnx": {"name": "ONNX", "risk": "LOW", "uses_pickle": False},
    ".safetensors": {"name": "Safetensors", "risk": "SAFE", "uses_pickle": False},
    ".gguf": {"name": "GGUF", "risk": "SAFE", "uses_pickle": False},
    ".ggml": {"name": "GGML", "risk": "LOW", "uses_pickle": False},
    ".tflite": {"name": "TFLite", "risk": "LOW", "uses_pickle": False},
    ".pb": {"name": "TF SavedModel", "risk": "MEDIUM", "uses_pickle": False},
}

# Suspicious byte patterns in pickle files
PICKLE_OPCODES = {
    b'\x80': "PROTO",
    b'c': "GLOBAL (imports module)",
    b'\x81': "NEWOBJ",
    b'R': "REDUCE (calls function)",
    b'i': "INST",
    b'o': "OBJ",
    b'\x93': "STACK_GLOBAL",
}

# Suspicious strings to look for in binary model files
SUSPICIOUS_STRINGS = [
    b"os.system",
    b"subprocess",
    b"socket.socket",
    b"urllib.request",
    b"requests.get",
    b"requests.post",
    b"eval(",
    b"exec(",
    b"__import__",
    b"__reduce__",
    b"__reduce_ex__",
    b"__getstate__",
    b"__setstate__",
    b"/bin/sh",
    b"/bin/bash",
    b"cmd.exe",
    b"powershell",
    b"curl ",
    b"wget ",
    b"base64.b64decode",
    b"codecs.decode",
    b"crypto",
    b"reverse_shell",
    b"bind_shell",
]

# Suspicious module imports in pickle
DANGEROUS_PICKLE_MODULES = [
    b"os",
    b"sys",
    b"subprocess",
    b"socket",
    b"http",
    b"urllib",
    b"requests",
    b"shutil",
    b"tempfile",
    b"ctypes",
    b"importlib",
    b"builtins",
    b"posix",
    b"nt",  # Windows
    b"io",
    b"codecs",
]


def get_file_size_mb(path: Path) -> float:
    """Get file size in megabytes."""
    return path.stat().st_size / (1024 * 1024)


def scan_pickle_content(file_path: Path, deep: bool = False) -> list:
    """Scan binary content of pickle-based files for suspicious patterns."""
    findings = []

    try:
        with open(file_path, "rb") as f:
            # Read first 10MB for scanning (or whole file in deep mode)
            content = f.read(10 * 1024 * 1024 if not deep else -1)
    except Exception as e:
        findings.append(f"Could not read file: {e}")
        return findings

    # Check for suspicious strings
    for pattern in SUSPICIOUS_STRINGS:
        if pattern in content:
            findings.append(f"Suspicious string found: {pattern.decode('ascii', errors='replace')}")

    # Check for dangerous module imports in pickle stream
    for module in DANGEROUS_PICKLE_MODULES:
        # Pickle GLOBAL opcode: 'c' followed by module name
        pickle_import = b'c' + module + b'\n'
        if pickle_import in content:
            findings.append(f"Pickle imports dangerous module: {module.decode()}")

        # STACK_GLOBAL opcode pattern
        if b'\x93' in content and module in content:
            # More complex but might indicate module loading
            pass

    # Check for REDUCE opcode (function execution)
    reduce_count = content.count(b'R')
    if reduce_count > 100:
        findings.append(f"High number of REDUCE opcodes ({reduce_count}) - unusual for model files")

    return findings


def scan_hdf5_file(file_path: Path) -> list:
    """Scan HDF5/Keras files for Lambda layers."""
    findings = []

    try:
        content = file_path.read_bytes()

        # Check for Lambda layers (which can contain arbitrary code)
        if b"Lambda" in content or b"lambda" in content:
            findings.append("Contains Lambda layer - may execute arbitrary code")

        # Check for custom objects
        if b"custom_objects" in content:
            findings.append("Contains custom objects - review before loading")

    except Exception as e:
        findings.append(f"Could not scan HDF5 file: {e}")

    return findings


def scan_code_for_model_loading(project_path: Path) -> list:
    """Scan Python code for unsafe model loading patterns."""
    findings = []

    patterns = [
        {
            "regex": r"torch\.load\s*\(",
            "severity": "CRITICAL",
            "description": "Unsafe torch.load() - uses pickle deserialization",
            "recommendation": "Use torch.load(..., weights_only=True) or safetensors",
        },
        {
            "regex": r"pickle\.loads?\s*\(",
            "severity": "CRITICAL",
            "description": "Direct pickle deserialization",
            "recommendation": "Use safetensors or JSON format",
        },
        {
            "regex": r"joblib\.load\s*\(",
            "severity": "CRITICAL",
            "description": "Joblib load (uses pickle internally)",
            "recommendation": "Use ONNX or safetensors format",
        },
        {
            "regex": r"np\.load\s*\(.*allow_pickle\s*=\s*True",
            "severity": "HIGH",
            "description": "NumPy load with allow_pickle=True",
            "recommendation": "Set allow_pickle=False",
        },
        {
            "regex": r"from_pretrained\s*\(.*trust_remote_code\s*=\s*True",
            "severity": "CRITICAL",
            "description": "Remote code execution enabled for model loading",
            "recommendation": "Set trust_remote_code=False",
        },
        {
            "regex": r"from_pretrained\s*\((?!.*revision=)",
            "severity": "MEDIUM",
            "description": "Model loading without pinned revision",
            "recommendation": "Pin to specific commit hash with revision=",
        },
        {
            "regex": r"torch\.hub\.load\s*\(",
            "severity": "HIGH",
            "description": "Loading model from torch hub (downloads and executes)",
            "recommendation": "Download and verify model files manually",
        },
    ]

    exclude_dirs = {".venv", "venv", "node_modules", ".git", "__pycache__"}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for fname in files:
            if not fname.endswith(".py"):
                continue

            fpath = Path(root) / fname
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                lines = content.split("\n")

                for pattern in patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern["regex"], line):
                            findings.append(ModelFinding(
                                severity=pattern["severity"],
                                file_path=f"{fpath}:{i}",
                                file_size_mb=0,
                                format_type="code_pattern",
                                description=pattern["description"],
                                recommendation=pattern["recommendation"],
                                suspicious_patterns=[line.strip()[:200]],
                            ))
            except Exception:
                continue

    return findings


def scan_model_files(project_path: Path, deep: bool = False) -> list:
    """Scan directory for model files and assess risk."""
    findings = []
    exclude_dirs = {".venv", "venv", "node_modules", ".git", "__pycache__", ".mypy_cache"}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for fname in files:
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()

            if ext not in MODEL_FORMATS:
                continue

            fmt = MODEL_FORMATS[ext]
            size_mb = get_file_size_mb(fpath)

            finding = ModelFinding(
                severity=fmt["risk"],
                file_path=str(fpath),
                file_size_mb=round(size_mb, 2),
                format_type=fmt["name"],
                description=f"{fmt['name']} model file ({ext})",
                recommendation="",
                suspicious_patterns=[],
            )

            # Set recommendation based on risk
            if fmt["risk"] == "CRITICAL":
                finding.recommendation = "Convert to safetensors format"
            elif fmt["risk"] == "HIGH":
                finding.recommendation = "Audit for malicious content, prefer safetensors"
            elif fmt["risk"] == "SAFE":
                finding.recommendation = "Safe format - no action needed"
                finding.description += " - SAFE format"
            else:
                finding.recommendation = "Review and consider safetensors migration"

            # Deep scan for pickle-based files
            if fmt["uses_pickle"] and (deep or size_mb < 100):
                suspicious = scan_pickle_content(fpath, deep)
                finding.suspicious_patterns = suspicious
                if suspicious:
                    finding.severity = "CRITICAL"
                    finding.description += f" - {len(suspicious)} suspicious pattern(s) found!"

            # Scan HDF5 files for Lambda layers
            if ext in (".h5", ".hdf5", ".keras"):
                h5_findings = scan_hdf5_file(fpath)
                finding.suspicious_patterns.extend(h5_findings)
                if h5_findings:
                    finding.severity = "HIGH"

            findings.append(finding)

    return findings


def format_console_output(model_findings: list, code_findings: list) -> str:
    """Format results for console output."""
    output = []
    output.append("=" * 70)
    output.append("MODEL FILE SECURITY SCAN RESULTS")
    output.append("=" * 70)

    # Summary
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4}
    all_findings = model_findings + code_findings

    counts = {}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    output.append(f"\nTotal model files found: {len(model_findings)}")
    output.append(f"Code patterns found: {len(code_findings)}")
    output.append("\nSeverity breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        if counts.get(sev, 0) > 0:
            output.append(f"  {sev}: {counts[sev]}")

    # Model files
    risky_models = [f for f in model_findings if f.severity not in ("SAFE", "LOW")]
    if risky_models:
        output.append("\n" + "-" * 70)
        output.append("RISKY MODEL FILES")
        output.append("-" * 70)
        for f in sorted(risky_models, key=lambda x: severity_order.get(x.severity, 4)):
            output.append(f"\n[{f.severity}] {f.file_path}")
            output.append(f"  Format: {f.format_type} ({f.file_size_mb} MB)")
            output.append(f"  Risk: {f.description}")
            output.append(f"  Fix: {f.recommendation}")
            if f.suspicious_patterns:
                output.append("  Suspicious patterns:")
                for p in f.suspicious_patterns[:5]:
                    output.append(f"    ⚠ {p}")

    # Safe models
    safe_models = [f for f in model_findings if f.severity == "SAFE"]
    if safe_models:
        output.append(f"\n✅ Safe model files: {len(safe_models)}")
        for f in safe_models:
            output.append(f"  {f.file_path} ({f.format_type})")

    # Code patterns
    if code_findings:
        output.append("\n" + "-" * 70)
        output.append("UNSAFE MODEL LOADING PATTERNS IN CODE")
        output.append("-" * 70)
        for f in sorted(code_findings, key=lambda x: severity_order.get(x.severity, 4)):
            output.append(f"\n[{f.severity}] {f.file_path}")
            output.append(f"  Issue: {f.description}")
            output.append(f"  Fix: {f.recommendation}")
            if f.suspicious_patterns:
                output.append(f"  Code: {f.suspicious_patterns[0]}")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description="Model File Security Scanner - Detect unsafe model formats and loading patterns"
    )
    parser.add_argument("path", help="Path to project directory to scan")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep scan: read entire files (slower but more thorough)"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path"
    )
    parser.add_argument(
        "--models-only",
        action="store_true",
        help="Only scan model files, skip code pattern analysis"
    )

    args = parser.parse_args()

    project_path = Path(args.path)
    if not project_path.exists():
        print(f"Error: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {project_path} for model files...", file=sys.stderr)
    model_findings = scan_model_files(project_path, args.deep)

    code_findings = []
    if not args.models_only:
        print("Scanning code for unsafe model loading patterns...", file=sys.stderr)
        code_findings = scan_code_for_model_loading(project_path)

    if args.json or args.output:
        result = {
            "scan_time": datetime.now().isoformat(),
            "project_path": str(project_path),
            "deep_scan": args.deep,
            "model_files": [
                {
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "file_size_mb": f.file_size_mb,
                    "format": f.format_type,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "suspicious_patterns": f.suspicious_patterns,
                }
                for f in model_findings
            ],
            "code_patterns": [
                {
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "code": f.suspicious_patterns,
                }
                for f in code_findings
            ],
        }

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(result, indent=2))
    else:
        print(format_console_output(model_findings, code_findings))

    # Exit code
    critical_or_high = any(
        f.severity in ("CRITICAL", "HIGH")
        for f in model_findings + code_findings
        if f.suspicious_patterns  # Only fail for findings with actual evidence
    )
    code_critical = any(
        f.severity == "CRITICAL" for f in code_findings
    )

    if critical_or_high or code_critical:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
