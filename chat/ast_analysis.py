# ast_analysis.py
import ast

def python_ast_analysis(content, lines):
    findings = []
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = getattr(node.func, 'id', getattr(node.func, 'attr', None))
                if func in ('eval', 'exec'):
                    line_num = node.lineno - 1
                    problem_line = lines[line_num] if line_num < len(lines) else ""
                    findings.append({
                        "type": f"AST Unsafe {func}",
                        "severity": "High",
                        "problem_line": problem_line.strip(),
                        "fix": f"Avoid using {func}; sanitize inputs.",
                        "line": node.lineno,
                        "ai_suggestion": ""
                    })
    except Exception:
        pass
    return findings
