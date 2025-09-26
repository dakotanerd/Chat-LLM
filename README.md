# BitNet Vulnerability Analyzer

**BitNet** is a local code vulnerability analyzer that uses both **heuristic checks** and an optional **dataset-based matching** system to identify potential security issues in code. It supports multiple programming languages and can scan individual files, entire folders, or code snippets.

This tool is designed to help developers and security researchers quickly detect common vulnerabilities such as SQL injection, buffer overflows, unsafe file handling, and insecure coding patterns.

---

## Features

* Supports multiple languages: Python, C, C++, Java, JavaScript, PHP, Shell, Go, and Rust.
* Detects vulnerabilities using **heuristic checks**:

  * SQL Injection
  * Plaintext password storage
  * Unsafe use of `eval`, `exec`, or system commands
  * Hardcoded credentials
  * Unsafe file handling
* Optional **dataset-based matching** against a JSONL dataset for known code patterns.
* Logs analysis results to `chat_log.txt`.
* Supports analyzing:

  * Single files
  * Entire directories recursively
  * Direct code snippets

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/BitNet.git
   cd BitNet
   ```
2. Ensure you have Python 3 installed.
3. Install required packages (if any):

   ```bash
   pip install -r requirements.txt
   ```
4. (Optional) Add your dataset in `vuln_dataset.jsonl` for dataset-based matching.

---

## Usage

Analyze a single file:

```bash
python chat.py -f path/to/file.py
```

Analyze an entire folder:

```bash
python chat.py -f path/to/folder/
```

Analyze a code snippet directly:

```bash
python chat.py -p "some code snippet or keywords"
```

View analysis log:

```bash
python chat.py --view-log
```

Clear the log:

```bash
python chat.py --clear-log
```

---

## Output Example

```json
{
  "language": "Java",
  "method": "heuristics",
  "findings": [
    {
      "type": "Plaintext password storage",
      "description": "Storing passwords in plaintext is unsafe.",
      "fix": "Hash passwords before storing (bcrypt or similar).",
      "line": 8
    },
    {
      "type": "SQL Injection risk",
      "description": "User input concatenated into SQL string can lead to SQL injection.",
      "fix": "Use PreparedStatement instead of concatenation.",
      "line": 34
    }
  ]
}
```

---

## Project Structure

```
BitNet/
├─ chat.py                # Main analysis script
├─ generate_dataset.py    # Script to create dataset JSONL from code samples
├─ code_samples/          # Example code samples for dataset
├─ tests/                 # Test files for each language
├─ vuln_dataset.jsonl     # Dataset of known vulnerable patterns
├─ chat_log.txt           # Log of all scans
└─ README.md
```

---

## Contribution

Contributions are welcome! You can:

* Add new heuristic checks
* Extend support to more languages
* Improve dataset matching
* Add more test code samples

---

## License

This project is licensed under the MIT License.
