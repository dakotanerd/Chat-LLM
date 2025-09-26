#!/usr/bin/env python3
"""
generate_dataset.py — improved dataset generator

Features:
- Load vulnerability rulepack from rules.json or rules.yaml (optional).
- Built-in rulepack fallback with CWE/OWASP tags, fix suggestions, severities.
- Support for many file types (python, js, php, dockerfile, terraform, env, sql, cs, ...).
- Python AST-assisted checks for more accurate detection.
- Multiprocessing to scan files faster.
- JSONL output (vuln_dataset.jsonl), plus CSV and HTML summary reports.
- CLI flags: --include-root, --out, --min-severity, --langs, --examples, --append-candidates
- Candidate-rule detection written to candidates.jsonl for human review (self-learning bootstrap).
"""

from __future__ import annotations
import argparse
import concurrent.futures
import csv
import json
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Optional YAML support - not required
try:
    import yaml
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False

# ---------------------------
# Config & Defaults
# ---------------------------
BASE_SAMPLE_DIR = "code_samples"
DEFAULT_OUTPUT = "vuln_dataset.jsonl"
CSV_OUTPUT = "vuln_dataset.csv"
HTML_OUTPUT = "vuln_dataset_summary.html"
CANDIDATES_FILE = "candidates.jsonl"
MAX_PROMPT_LINES = 400
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB (skip larger files)
WORKERS = max(1, (os.cpu_count() or 2) - 1)

# Severity order for filtering
SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# Built-in rulepack (fallback). Each rule: pattern, description, severity, cwe, owasp, fix, examples(optional)
BUILTIN_RULES = {
    # ext -> list of rules
    ".py": [
        {
            "pattern": r"\beval\s*\(",
            "description": "Use of eval() can execute arbitrary code",
            "severity": "High",
            "cwe": ["CWE-94"],
            "owasp": ["A1: Injection"],
            "fix": "Avoid eval(); use ast.literal_eval or safer parsing.",
        },
        {
            "pattern": r"\bexec\s*\(",
            "description": "Use of exec() can execute arbitrary code",
            "severity": "High",
            "cwe": ["CWE-94"],
            "owasp": ["A1: Injection"],
            "fix": "Avoid exec(); refactor code to eliminate dynamic execution.",
        },
        {
            "pattern": r"pickle\.(loads|load)\s*\(",
            "description": "Untrusted pickle deserialization",
            "severity": "Critical",
            "cwe": ["CWE-502"],
            "owasp": ["A9: Using Components with Known Vulnerabilities"],
            "fix": "Do not unpickle untrusted data; use safe formats like JSON.",
        },
        {
            "pattern": r"yaml\.load\s*\(",
            "description": "Unsafe YAML deserialization",
            "severity": "High",
            "cwe": ["CWE-502"],
            "owasp": ["A9: Using Components with Known Vulnerabilities"],
            "fix": "Use yaml.safe_load rather than yaml.load.",
        },
        {
            "pattern": r"requests\.(get|post)\s*\(.*verify\s*=\s*False",
            "description": "Insecure TLS verification (verify=False)",
            "severity": "High",
            "cwe": ["CWE-295"],
            "owasp": ["A6: Security Misconfiguration"],
            "fix": "Do not disable certificate verification; use proper certificates.",
        },
    ],
    ".js": [
        {
            "pattern": r"\beval\s*\(",
            "description": "Use of eval() can execute arbitrary JS",
            "severity": "High",
            "cwe": ["CWE-95"],
            "owasp": ["A1: Injection", "A3: XSS"],
            "fix": "Avoid eval(); use safe parsing and templating.",
        },
        {
            "pattern": r"innerHTML\s*=",
            "description": "Direct DOM assignment via innerHTML (possible XSS)",
            "severity": "Medium",
            "cwe": ["CWE-79"],
            "owasp": ["A3: Cross-Site Scripting (XSS)"],
            "fix": "Sanitize/escape all untrusted input before inserting into DOM.",
        },
    ],
    ".php": [
        {
            "pattern": r"\beval\s*\(",
            "description": "Use of eval in PHP is dangerous",
            "severity": "High",
            "cwe": ["CWE-94"],
            "owasp": ["A1: Injection"],
            "fix": "Avoid eval(); use safer alternatives.",
        },
        {
            "pattern": r"include\s*\(\s*\$_(GET|POST|REQUEST)\[",
            "description": "Dynamic include from user input (Remote File Inclusion)",
            "severity": "Critical",
            "cwe": ["CWE-98"],
            "owasp": ["A1: Injection"],
            "fix": "Never include files based on unsanitized user input.",
        },
    ],
    # Dockerfile / IaC hints
    "Dockerfile": [
        {
            "pattern": r"^\s*FROM\s+.*:latest\b",
            "description": "Using :latest tag in FROM (non-deterministic base image)",
            "severity": "Low",
            "cwe": [],
            "owasp": ["A6: Misconfiguration"],
            "fix": "Pin image versions to specific tags/digests for reproducible builds.",
        },
        {
            "pattern": r"^\s*USER\s+root\b",
            "description": "Running container as root user",
            "severity": "Medium",
            "cwe": [],
            "owasp": ["A6: Misconfiguration"],
            "fix": "Use a non-root user in Dockerfiles where possible.",
        },
    ],
    ".tf": [
        {
            "pattern": r'0\.0\.0\.0\/0',
            "description": "Open ingress 0.0.0.0/0 (wide network exposure)",
            "severity": "High",
            "cwe": [],
            "owasp": ["A6: Misconfiguration"],
            "fix": "Restrict CIDR blocks to required ranges.",
        },
    ],
    ".env": [
        {
            "pattern": r"(?i)^(?:AWS|SECRET|API|TOKEN|PASSWORD|PASS|KEY)[_]?=.+",
            "description": "Potential hardcoded secret in .env or env-like file",
            "severity": "High",
            "cwe": ["CWE-200"],
            "owasp": ["A3: Sensitive Data Exposure"],
            "fix": "Use secret stores rather than committing to repo.",
        },
    ],
    ".sql": [
        {
            "pattern": r"SELECT\s+.*\+\s*\w",
            "description": "String concatenation in SQL (possible SQL injection)",
            "severity": "High",
            "cwe": ["CWE-89"],
            "owasp": ["A1: Injection"],
            "fix": "Use parameterized queries/prepared statements.",
        },
    ],
    ".cs": [
        {
            "pattern": r"Process\.Start\(",
            "description": "Process.Start may lead to command injection if passed unsanitized input",
            "severity": "High",
            "cwe": ["CWE-78"],
            "owasp": ["A1: Injection"],
            "fix": "Validate/sanitize inputs and avoid starting processes with untrusted data.",
        },
    ],
}

# ---------------------------
# Dataclasses
# ---------------------------
@dataclass
class Finding:
    description: str
    severity: str
    cwe: List[str]
    owasp: List[str]
    fix: str
    line: Optional[int] = None
    context: Optional[str] = None  # snippet around the match

@dataclass
class Entry:
    file: str
    language: str
    size: int
    line_count: int
    prompt: str
    completion: str
    vulnerabilities: List[Dict]

# ---------------------------
# Helper functions
# ---------------------------
def load_rulepack(path: Optional[str]) -> Dict[str, List[Dict]]:
    """Load rules from JSON or YAML. If none provided, return BUILTIN_RULES."""
    if not path:
        return BUILTIN_RULES
    p = Path(path)
    if not p.exists():
        logging.warning("Rulepack not found at %s — falling back to builtin rules", path)
        return BUILTIN_RULES
    try:
        if p.suffix.lower() in (".yml", ".yaml") and YAML_AVAILABLE:
            with p.open("r", encoding="utf-8") as fh:
                return yaml.safe_load(fh)
        else:
            with p.open("r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception as e:
        logging.warning("Failed to load rulepack (%s): %s — using builtin rules", path, e)
        return BUILTIN_RULES

def detect_language(path: Path) -> str:
    ext = path.suffix.lower()
    if path.name.lower() == "dockerfile" or path.suffix == "":
        if "dockerfile" in path.name.lower():
            return "Dockerfile"
    # normalize some extensions: terraform .tf
    if ext == ".tf":
        return ".tf"
    # default mapping by extension (use built-in rule keys)
    if ext in BUILTIN_RULES:
        return ext
    # attempt to match many others by convention
    return ext or "unknown"

def snippet_around(content: str, pos: int, context_lines: int = 3) -> str:
    lines = content.splitlines()
    lineno = content[:pos].count("\n")
    start = max(0, lineno - context_lines)
    end = min(len(lines), lineno + context_lines + 1)
    return "\n".join(lines[start:end])

def regex_find_all(rule: Dict, content: str) -> List[Tuple[int, re.Match]]:
    pattern = rule.get("pattern")
    flags = re.MULTILINE
    try:
        rx = re.compile(pattern, flags)
    except Exception:
        # try slower full-match compile fallback
        rx = re.compile(re.escape(pattern), flags)
    matches = []
    for m in rx.finditer(content):
        matches.append((m.start(), m))
    return matches

# Python AST helper to find eval/exec usages more accurately
def python_ast_checks(content: str) -> List[Finding]:
    import ast as _ast
    findings: List[Finding] = []
    try:
        tree = _ast.parse(content)
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call):
                func = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
                if func in ("eval", "exec"):
                    line = getattr(node, "lineno", None)
                    findings.append(Finding(
                        description=f"AST detected use of {func}()",
                        severity="High",
                        cwe=["CWE-94"],
                        owasp=["A1: Injection"],
                        fix="Avoid dynamic code execution; sanitize inputs or refactor.",
                        line=line,
                        context=None
                    ))
    except Exception:
        # If AST fails, we silently skip AST checks
        pass
    return findings

# ---------------------------
# Core classification
# ---------------------------
def classify_vulnerability(content: str, rulepack: Dict[str, List[Dict]], path: Path
                           ) -> Tuple[List[Dict], List[Dict]]:
    """
    Returns (findings, candidates)
    findings: list of matched vulnerability dicts
    candidates: candidate patterns (new suspicious things) for review
    """
    findings = []
    candidates = []
    lang_key = detect_language(path)
    # merge language-specific rules + generic (rules under key "*" or ".generic")
    rules = rulepack.get(lang_key, []) + rulepack.get("*", []) + rulepack.get(".generic", [])
    # run regex rules
    for rule in rules:
        for pos, match in regex_find_all(rule, content):
            line = content[:pos].count("\n") + 1
            ctx = snippet_around(content, pos)
            findings.append({
                "description": rule.get("description"),
                "severity": rule.get("severity", "Medium"),
                "cwe": rule.get("cwe", []),
                "owasp": rule.get("owasp", []),
                "fix": rule.get("fix", ""),
                "line": line,
                "context": ctx
            })
    # special AST checks for Python
    if lang_key == ".py" or path.suffix.lower() == ".py":
        ast_findings = python_ast_checks(content)
        for f in ast_findings:
            findings.append(asdict(f))
    # heuristics for other file types (Dockerfile/Terraform/.env) — run basic patterns if no rulepack provided
    if not rules:
        # if there were no rules, attempt simple generic secret detection
        for m in re.finditer(r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*['\"].{4,}['\"]", content):
            pos = m.start()
            findings.append({
                "description": "Possible hardcoded secret",
                "severity": "High",
                "cwe": [],
                "owasp": ["A3: Sensitive Data Exposure"],
                "fix": "Remove secret from code, use secret manager.",
                "line": content[:pos].count("\n") + 1,
                "context": snippet_around(content, pos)
            })
    # Candidate discovery: if content contains suspicious tokens not in rules, create candidate entry
    # e.g., unescaped 'eval' occurrences when no eval rule existed
    # We only add candidate if no matching rule matched for that token
    suspicious_tokens = ["eval(", "exec(", "system(", "Runtime.getRuntime", "pickle.loads", "yaml.load", "innerHTML", "onerror="]
    for token in suspicious_tokens:
        if token in content:
            # check whether any finding already mentions token
            if not any(token.strip("()").lower() in (f["description"] or "").lower() for f in findings):
                # create candidate
                pos = content.find(token)
                candidates.append({
                    "candidate_pattern": re.escape(token),
                    "example_context": snippet_around(content, pos),
                    "file": str(path),
                    "line": content[:pos].count("\n") + 1,
                    "note": "Candidate pattern auto-suggested. Review before adding to rulepack."
                })
    return findings, candidates

# ---------------------------
# File scanning worker
# ---------------------------
def process_file(path: Path, rulepack: Dict[str, List[Dict]], max_lines: int = MAX_PROMPT_LINES
                 ) -> Optional[Entry]:
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            logging.debug("Skipping %s (too large: %d)", path, size)
            return None
        # read up to max_lines
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            lines = []
            for i, line in enumerate(fh):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n"))
            content = "\n".join(lines)
    except Exception as e:
        logging.debug("Could not read %s: %s", path, e)
        return None

    findings, candidates = classify_vulnerability(content, rulepack, path)

    # build prompt (truncated)
    lang = detect_language(path)
    prompt = f"Analyze this {lang} code for vulnerabilities:\n{content}"
    completion = "\n".join([f"{f['description']} ({f.get('severity','?')}) [line:{f.get('line')}]" for f in findings]) or "No issues found"

    entry = Entry(
        file=str(path),
        language=lang,
        size=len(content.encode("utf-8")),
        line_count=len(content.splitlines()),
        prompt=prompt,
        completion=completion,
        vulnerabilities=findings
    )
    return entry, candidates

# ---------------------------
# Output helpers
# ---------------------------
def write_jsonl(entries: List[Entry], out_path: Path):
    with out_path.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")

def write_csv(entries: List[Entry], out_path: Path):
    with out_path.open("w", encoding="utf-8", newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "language", "size", "line_count", "vuln_count", "top_vulns"])
        for e in entries:
            vuln_count = len(e.vulnerabilities)
            top_vulns = "; ".join(sorted({v.get("description","") for v in e.vulnerabilities})[:3])
            writer.writerow([e.file, e.language, e.size, e.line_count, vuln_count, top_vulns])

def write_html_summary(entries: List[Entry], out_path: Path, stats: Dict):
    # minimal styled HTML summary with counts by severity and top vuln types
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = [f"<html><head><meta charset='utf-8'><title>Vuln Dataset Summary</title>",
            "<style>body{font-family:Arial,Helvetica,sans-serif;padding:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f4f4f4}</style></head><body>"]
    html.append(f"<h1>Vulnerability Dataset Summary</h1><p>Generated: {now}</p>")
    html.append("<h2>Stats</h2><ul>")
    html.append(f"<li>Files scanned: {stats.get('files_scanned',0)}</li>")
    html.append(f"<li>Total findings: {stats.get('total_findings',0)}</li>")
    for sev, count in stats.get('by_severity', {}).items():
        html.append(f"<li>{sev}: {count}</li>")
    html.append("</ul>")

    html.append("<h2>Top vulnerability descriptions</h2>")
    html.append("<table><tr><th>#</th><th>Description</th><th>Count</th></tr>")
    for i, (desc, cnt) in enumerate(stats.get('top_vulns', [])[:40], 1):
        html.append(f"<tr><td>{i}</td><td>{desc}</td><td>{cnt}</td></tr>")
    html.append("</table>")

    html.append("<h2>Sample entries</h2>")
    html.append("<table><tr><th>File</th><th>Language</th><th>Findings</th></tr>")
    for e in entries[:50]:
        top = "<br>".join([f"{v['description']} ({v['severity']}) [line:{v.get('line')}]" for v in e.vulnerabilities[:5]])
        html.append(f"<tr><td>{e.file}</td><td>{e.language}</td><td>{top}</td></tr>")
    html.append("</table></body></html>")

    out_path.write_text("\n".join(html), encoding="utf-8")

# ---------------------------
# CLI / Runner
# ---------------------------
def collect_files(include_root: bool, base_dir: str, selected_langs: Optional[List[str]]) -> List[Path]:
    files = []
    base = Path(base_dir)
    if base.exists():
        for entry in base.iterdir():
            if entry.is_dir():
                for p in entry.rglob("*.*"):
                    files.append(p)
    if include_root:
        for p in Path(".").iterdir():
            if p.is_file():
                files.append(p)
    # filter by extension if selected_langs provided (langs are ext keys or names)
    if selected_langs:
        def matches(p: Path) -> bool:
            key = detect_language(p)
            return any(k.lower() in (key.lower(), p.suffix.lower(), p.suffix.lower().lstrip('.')) for k in selected_langs)
        files = [p for p in files if matches(p)]
    # deduplicate and sort
    unique = {}
    for p in files:
        try:
            stat = p.stat()
        except Exception:
            continue
        key = (p.resolve(), stat.st_mtime, stat.st_size)
        unique[key] = p
    return sorted(unique.values(), key=lambda x: str(x))

def run_scan(rulepack_path: Optional[str], include_root: bool, out_path: str,
             min_severity: str, langs: Optional[List[str]], examples: int,
             append_candidates: bool):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    rulepack = load_rulepack(rulepack_path)
    files = collect_files(include_root, BASE_SAMPLE_DIR, langs)
    entries = []
    all_candidates = []
    stats = {"files_scanned": 0, "total_findings": 0, "by_severity": Counter(), "top_vulns": Counter()}

    if not files:
        logging.warning("No files found to scan (check code_samples/).")
        return

    logging.info("Scanning %d files with %d workers...", len(files), WORKERS)

    # helper for severity threshold
    min_sev_val = SEVERITY_ORDER.get(min_severity, 0)

    with concurrent.futures.ProcessPoolExecutor(max_workers=WORKERS) as exe:
        # dispatch jobs
        futures = {exe.submit(process_file, p, rulepack, MAX_PROMPT_LINES): p for p in files}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:
                logging.debug("Error scanning %s: %s", p, exc)
                continue
            if res is None:
                continue
            entry, candidates = res
            # filter by min severity: keep entry if any vulnerability >= threshold
            keep = False
            for v in entry.vulnerabilities:
                sev_val = SEVERITY_ORDER.get(v.get("severity","Medium"), 1)
                stats["by_severity"][v.get("severity","Unknown")] += 1
                stats["top_vulns"][v.get("description","")] += 1
                if sev_val >= min_sev_val:
                    keep = True
            stats["total_findings"] = sum(stats["by_severity"].values())
            stats["files_scanned"] += 1
            if keep or min_sev_val == 0:
                entries.append(entry)
            all_candidates.extend(candidates or [])
    # write outputs
    outp = Path(out_path)
    write_jsonl(entries, outp)
    write_csv(entries, Path(CSV_OUTPUT))
    write_html_summary(entries, Path(HTML_OUTPUT), {
        "files_scanned": stats["files_scanned"],
        "total_findings": stats["total_findings"],
        "by_severity": dict(stats["by_severity"]),
        "top_vulns": stats["top_vulns"].most_common()
    })
    logging.info("Wrote %s (%d entries), %s, %s", outp, len(entries), CSV_OUTPUT, HTML_OUTPUT)

    # write candidates if requested
    if append_candidates and all_candidates:
        cpath = Path(CANDIDATES_FILE)
        # append as JSONL
        with cpath.open("a", encoding="utf-8") as fh:
            for c in all_candidates:
                fh.write(json.dumps(c, ensure_ascii=False) + "\n")
        logging.info("Appended %d candidate patterns to %s", len(all_candidates), cpath)

    # print compact summary
    print("\n=== Summary ===")
    print(f"Files scanned: {stats['files_scanned']}")
    print(f"Total findings: {stats['total_findings']}")
    top = stats["top_vulns"].most_common(10)
    print("Top findings:")
    for desc, cnt in top:
        print(f" - {desc} ({cnt})")
    print(f"Output written: {outp}  ({len(entries)} entries)")
    print(f"CSV: {CSV_OUTPUT}  HTML summary: {HTML_OUTPUT}")
    if append_candidates:
        print(f"Candidates appended to: {CANDIDATES_FILE}")

# ---------------------------
# CLI
# ---------------------------
def main_cli():
    p = argparse.ArgumentParser(description="Generate enhanced vulnerability dataset from sample code")
    p.add_argument("--rulepack", help="Path to rules JSON/YAML (optional). If omitted, builtin rules used.")
    p.add_argument("--include-root", action="store_true", help="Also include files from repository root")
    p.add_argument("--out", default=DEFAULT_OUTPUT, help="Output JSONL file path")
    p.add_argument("--min-severity", default="Low", choices=list(SEVERITY_ORDER.keys()), help="Minimum severity to include")
    p.add_argument("--langs", help="Comma-separated language keys or extensions to include (e.g. .py, .js, Dockerfile)")
    p.add_argument("--examples", type=int, default=0, help="Number of example snippets per vuln to embed (not implemented fully)")
    p.add_argument("--append-candidates", action="store_true", help="Append candidate patterns to candidates.jsonl for review")
    args = p.parse_args()

    langs = [x.strip() for x in args.langs.split(",")] if args.langs else None
    run_scan(args.rulepack, args.include_root, args.out, args.min_severity, langs, args.examples, args.append_candidates)

if __name__ == "__main__":
    main_cli()
