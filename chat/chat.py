#!/usr/bin/env python3
import argparse
import json
from file_utils import detect_language, gather_files, read_file
from heuristics import run_heuristics
from ast_analysis import python_ast_analysis
from logger import save_to_log

MAX_LINES = 500

def analyze_file(path):
    content, lines = read_file(path, max_lines=MAX_LINES)
    if content is None:
        return {"error": f"Could not read file: {path}"}
    lang = detect_language(path)
    findings = run_heuristics(lang, content, lines)
    if lang == "Python":
        findings += python_ast_analysis(content, lines)
    severity_summary = {}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_summary[sev] = severity_summary.get(sev, 0) + 1
    return {
        "file": path,
        "language": lang,
        "method": "heuristics+AST+SQL",
        "findings": findings,
        "severity_summary": severity_summary,
        "file_size": len(content),
        "line_count": len(lines)
    }

def main():
    parser = argparse.ArgumentParser(description="Enhanced chat vulnerability analyzer")
    parser.add_argument("-f", "--file", nargs="+", help="Files or directories to analyze")
    parser.add_argument("-p", "--prompt", help="Code snippet to analyze")
    parser.add_argument("--view-log", action="store_true")
    parser.add_argument("--clear-log", action="store_true")
    args = parser.parse_args()

    if args.view_log:
        try:
            with open("chat_log.jsonl", "r", encoding="utf-8") as f:
                print(f.read())
        except FileNotFoundError:
            print("No log file.")
        return

    if args.clear_log:
        open("chat_log.jsonl", "w", encoding="utf-8").close()
        print("Log cleared.")
        return

    if args.file:
        files = gather_files(args.file)
        for f in files:
            result = analyze_file(f)
            print(json.dumps(result, indent=2))
            save_to_log(result, f"File: {f}")
    elif args.prompt:
        lines = args.prompt.splitlines()
        findings = run_heuristics("Python", args.prompt, lines) + python_ast_analysis(args.prompt, lines)
        severity_summary = {}
        for f in findings:
            sev = f.get("severity", "Info")
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
        result = {
            "method": "heuristics+AST+SQL",
            "language": "Python",
            "findings": findings,
            "severity_summary": severity_summary,
            "line_count": len(lines)
        }
        print(json.dumps(result, indent=2))
        save_to_log(result, f"Prompt: {args.prompt}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
