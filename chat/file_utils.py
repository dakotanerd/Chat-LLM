# file_utils.py
from pathlib import Path

EXT_LANG_MAP = {
    ".py": "Python", ".c": "C", ".cpp": "C++", ".h": "C/C++ Header", ".java": "Java",
    ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go", ".rs": "Rust", ".php": "PHP",
    ".sh": "Shell", ".rb": "Ruby", ".swift": "Swift", ".kt": "Kotlin", ".lua": "Lua",
    ".ps1": "PowerShell", ".dart": "Dart", ".scala": "Scala", ".r": "R", ".html": "HTML"
}

def detect_language(path):
    return EXT_LANG_MAP.get(Path(path).suffix.lower(), "Unknown")

def gather_files(paths):
    all_files = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            all_files.append(str(p))
        elif p.is_dir():
            for f in p.rglob("*.*"):
                all_files.append(str(f))
    return all_files

def read_file(path, max_lines=500):
    try:
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()[:max_lines]
        return "\n".join(lines), lines
    except Exception as e:
        return None, None
