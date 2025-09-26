# sql_patterns.py

SQL_PATTERNS = {
    "Java": [
        (r'"\s*SELECT\s+.*\s+FROM\s+.*\s*"\s*\+\s*\w+', "Possible SQL Injection", "High",
         "Use prepared statements instead of string concatenation."),
    ],
    "Python": [
        (r'"\s*SELECT\s+.*\s+FROM\s+.*\s*"\s*%s', "Possible SQL Injection", "High",
         "Use parameterized queries with DB API."),
    ],
    "PHP": [
        (r'\$.*=\s*".*SELECT.*FROM.*".*\$_(GET|POST|REQUEST)', "Possible SQL Injection", "High",
         "Use prepared statements or ORM methods."),
    ],
    # Add other languages similarly
}
