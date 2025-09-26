# heuristics.py
import re
from sql_patterns import SQL_PATTERNS

HEURISTICS = {
    "Python": [
        (r"\beval\s*\(", "Unsafe eval", "High", "Avoid eval; use ast.literal_eval or validate inputs."),
        (r"\bexec\s*\(", "Unsafe exec", "High", "Avoid exec; use safer alternatives or functions."),
        (r"subprocess\..+\bshell\s*=\s*True", "Subprocess shell=True", "High", "Use list arguments; avoid shell=True."),
        (r"pickle\.(loads|load)\s*\(", "Unsafe pickle deserialization", "High", "Do not unpickle untrusted data."),
    ],
    "C": [
        (r"\bstrcpy\s*\(", "Buffer overflow (strcpy)", "High", "Use strncpy instead."),
        (r"\bgets\s*\(", "Buffer overflow (gets)", "High", "Use fgets instead."),
    ],
    "Java": [
        (r'String\s+\w*password\w*\s*;', "Plaintext password storage", "High", "Hash passwords using bcrypt or Argon2."),
        (r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.exec\s*\(", "Command execution", "High", "Avoid using Runtime.exec; sanitize inputs or use safer APIs."),
    ]
}

GENERIC_RULES = [
    (r"(password\s*[:=]\s*['\"]\w+['\"]|passwd\s*[:=]\s*['\"]\w+['\"])",
     "Hardcoded credentials", "High", "Use environment variables or a secrets manager instead."),
    (r"API[_-]?KEY\s*[:=]\s*['\"].+['\"]",
     "Hardcoded API key", "High", "Store API keys securely outside source code.")
]

def run_heuristics(lang, content, lines):
    findings = []
    # Language-specific heuristics
    for pattern, typ, severity, fix in HEURISTICS.get(lang, []):
        for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            line_num = content[:m.start()].count("\n")
            problem_line = lines[line_num] if line_num < len(lines) else ""
            findings.append({
                "type": typ,
                "severity": severity,
                "problem_line": problem_line.strip(),
                "fix": fix,
                "line": line_num + 1,
                "ai_suggestion": ""
            })
    # Generic rules
    for pattern, typ, severity, fix in GENERIC_RULES:
        for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            line_num = content[:m.start()].count("\n")
            problem_line = lines[line_num] if line_num < len(lines) else ""
            findings.append({
                "type": typ,
                "severity": severity,
                "problem_line": problem_line.strip(),
                "fix": fix,
                "line": line_num + 1,
                "ai_suggestion": ""
            })
    # SQL injection patterns
    if lang in SQL_PATTERNS:
        for pattern, typ, severity, fix in SQL_PATTERNS[lang]:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                line_num = content[:m.start()].count("\n")
                problem_line = lines[line_num] if line_num < len(lines) else ""
                findings.append({
                    "type": typ,
                    "severity": severity,
                    "problem_line": problem_line.strip(),
                    "fix": fix,
                    "line": line_num + 1,
                    "ai_suggestion": ""
                })
    if not findings:
        findings = [{"note": "No obvious issues found."}]
    return findings
