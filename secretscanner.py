from __future__ import annotations
import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import List, Pattern, Tuple

#!/usr/bin/env python3
"""
secretscanner.py

"""


LOG = logging.getLogger("secretscanner")


@dataclass
class Finding:
    path: str
    line: int
    pattern_name: str
    match: str


def build_patterns() -> List[Tuple[str, Pattern]]:
    """
    Return a list of (name, compiled_regex) for common secret patterns.
    """
    patterns = [
        # AWS Access Key ID
        ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        # AWS Secret Access Key (40 base64-like chars). Conservative anchor: look for assignment or key label nearby often.
        ("AWS Secret Access Key", re.compile(r"(?i)(aws_secret_access_key|aws_secret|secret_access_key)[\"'\s:=]*([A-Za-z0-9/+=]{40})")),
        # Google API Key
        ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
        # Slack token
        ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
        # Generic API key assignment
        ("API Key (assignment)", re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|app[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?")),
        # Generic 'secret' assignment
        ("Secret (assignment)", re.compile(r"(?i)\b(secret|private[_-]?key|passwd|password)\b\s*[:=]\s*['\"]?([^'\"\s]{6,})['\"]?")),
        # JWT-ish token (conservative)
        ("JWT (likely)", re.compile(r"\beyJ[0-9A-Za-z-_]+\.[0-9A-Za-z-_]+\.[0-9A-Za-z-_]+\b")),
        # RSA/PRIVATE KEY block
        ("Private Key Block", re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH)? ?PRIVATE KEY-----.*?-----END (RSA|DSA|EC|OPENSSH)? ?PRIVATE KEY-----", re.DOTALL)),
    ]
    return patterns


def is_binary_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
            return b"\0" in chunk
    except Exception:
        return True


def scan_text_content(path: str, content: str, patterns: List[Tuple[str, Pattern]]) -> List[Finding]:
    findings: List[Finding] = []
    # For line-based patterns, check line by line
    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        for name, regex in patterns:
            # Skip the multiline-only pattern when scanning lines to avoid mismatches
            if regex.flags & re.DOTALL and "\n" in regex.pattern:
                # We'll handle block patterns on whole content below
                continue
            for m in regex.finditer(line):
                # Some regexes have the secret in a capture group; prefer that
                match_text = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
                findings.append(Finding(path=path, line=idx, pattern_name=name, match=match_text))
    # Now handle whole-file (multiline) patterns
    for name, regex in patterns:
        # only patterns that can span multiple lines (e.g., private key block)
        if regex.flags & re.DOTALL or "\n" in regex.pattern:
            for m in regex.finditer(content):
                start_line = content[: m.start()].count("\n") + 1
                match_text = m.group(0)
                findings.append(Finding(path=path, line=start_line, pattern_name=name, match=match_text))
    return findings


def scan_file(path: str, patterns: List[Tuple[str, Pattern]]) -> List[Finding]:
    LOG.debug("Scanning file: %s", path)
    if is_binary_file(path):
        LOG.debug("Skipping binary file: %s", path)
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        LOG.warning("Failed to read %s: %s", path, e)
        return []
    return scan_text_content(path, content, patterns)


def scan_path(path: str, recursive: bool = True, exclude_dirs: List[str] = None) -> List[Finding]:
    if exclude_dirs is None:
        exclude_dirs = [".git", "node_modules", "__pycache__"]
    patterns = build_patterns()
    results: List[Finding] = []
    if os.path.isfile(path):
        results.extend(scan_file(path, patterns))
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            # mutate dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for fname in files:
                fpath = os.path.join(root, fname)
                results.extend(scan_file(fpath, patterns))
            if not recursive:
                break
    else:
        LOG.error("Path not found: %s", path)
    return results


def output_findings(findings: List[Finding], out_format: str = "text", out_file: str | None = None):
    if out_format == "json":
        payload = [asdict(f) for f in findings]
        text = json.dumps(payload, indent=2)
    else:
        lines = []
        for f in findings:
            lines.append(f"{f.path}:{f.line} [{f.pattern_name}] -> {f.match}")
        text = "\n".join(lines) if lines else "No findings."
    if out_file:
        try:
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(text)
            LOG.info("Wrote output to %s", out_file)
        except Exception as e:
            LOG.error("Failed to write output file %s: %s", out_file, e)
            print(text)
    else:
        print(text)


def configure_logging(level: str):
    numeric = getattr(logging, level.upper(), None)
    if not isinstance(numeric, int):
        numeric = logging.INFO
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(numeric)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secret Scanner - scan files or directories for common secret patterns")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--no-recursive", dest="recursive", action="store_false", help="Do not recurse into directories")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--output", "-o", help="Write output to file instead of stdout")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--exclude", "-e", action="append", help="Directories to exclude (can be repeated)", default=[])
    return parser.parse_args(argv)


def main(argv: List[str] | None = None):
    if argv is None:
        argv = sys.argv[1:]
    args = parse_args(argv)
    configure_logging(args.log_level)
    LOG.debug("Starting scan: path=%s recursive=%s", args.path, args.recursive)
    exclude = args.exclude or []
    # Merge with defaults inside scan_path
    findings = scan_path(args.path, recursive=args.recursive, exclude_dirs=exclude)
    LOG.info("Scan complete. %d finding(s).", len(findings))
    output_findings(findings, out_format=args.format, out_file=args.output)


if __name__ == "__main__":
    main()