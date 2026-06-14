"""
CWE Knowledge Base — Top 25 Most Dangerous Software Weaknesses
==============================================================
Source: MITRE CWE Top 25 (https://cwe.mitre.org/top25/)
Each entry contains:
  - cwe_id      : Official CWE identifier
  - name        : Weakness name
  - description : Natural language description
  - example     : Short vulnerable code snippet
  - fix         : Typical remediation
"""

CWE_KNOWLEDGE_BASE = [
    {
        "cwe_id": "CWE-79",
        "name": "Cross-site Scripting (XSS)",
        "description": "The application embeds untrusted user input into web output without proper escaping, allowing attackers to inject malicious scripts.",
        "example": 'document.getElementById("out").innerHTML = userInput;',
        "fix": "Sanitize and escape all user-controlled input before rendering in HTML. Use textContent instead of innerHTML."
    },
    {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "description": "User-supplied input is incorporated directly into SQL queries without sanitization, allowing attackers to manipulate database queries.",
        "example": 'query = "SELECT * FROM users WHERE name = \'" + username + "\'"',
        "fix": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings."
    },
    {
        "cwe_id": "CWE-20",
        "name": "Improper Input Validation",
        "description": "The application does not validate or incorrectly validates input, which can lead to unexpected behavior or security vulnerabilities.",
        "example": "def process(data):\n    result = data[0] / data[1]  # no validation",
        "fix": "Validate all inputs for type, length, format, and range before processing."
    },
    {
        "cwe_id": "CWE-125",
        "name": "Out-of-bounds Read",
        "description": "The program reads data beyond the end or before the beginning of a buffer, leading to crashes or information disclosure.",
        "example": "for i in range(len(arr) + 1):\n    print(arr[i])",
        "fix": "Ensure loop indices stay within valid bounds. Use range(len(arr)) not range(len(arr)+1)."
    },
    {
        "cwe_id": "CWE-78",
        "name": "OS Command Injection",
        "description": "User-controlled input is passed to OS commands without sanitization, allowing attackers to execute arbitrary commands.",
        "example": 'os.system("ping " + user_input)',
        "fix": "Use subprocess with argument lists instead of shell=True. Validate and sanitize all user input before passing to OS commands."
    },
    {
        "cwe_id": "CWE-416",
        "name": "Use After Free",
        "description": "The program references memory after it has been freed, leading to undefined behavior or crashes.",
        "example": "free(ptr);\nprintf(\"%s\", ptr);  // use after free",
        "fix": "Set pointers to NULL after freeing memory. Use smart pointers in C++."
    },
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "description": "User input is used to construct file paths without validation, allowing attackers to access files outside the intended directory.",
        "example": 'open("/var/data/" + user_filename)',
        "fix": "Validate and sanitize file paths. Use os.path.realpath() and verify the result stays within the allowed directory."
    },
    {
        "cwe_id": "CWE-476",
        "name": "NULL Pointer Dereference",
        "description": "The program dereferences a pointer that is expected to be valid but is NULL, causing crashes.",
        "example": "result = find_user(id)\nprint(result.name)  # result may be None",
        "fix": "Always check for None/NULL before dereferencing pointers or calling methods on objects."
    },
    {
        "cwe_id": "CWE-190",
        "name": "Integer Overflow",
        "description": "An integer calculation produces a result that exceeds the maximum value for the data type, causing unexpected behavior.",
        "example": "total = price * quantity  # no overflow check",
        "fix": "Validate that arithmetic results stay within expected ranges. Use checked arithmetic or big integer types."
    },
    {
        "cwe_id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "description": "The application deserializes data from untrusted sources without validation, which can lead to remote code execution.",
        "example": "data = pickle.load(open(user_file, 'rb'))",
        "fix": "Never deserialize data from untrusted sources with pickle. Use safe formats like JSON with schema validation."
    },
    {
        "cwe_id": "CWE-798",
        "name": "Hardcoded Credentials",
        "description": "The application contains hardcoded passwords, API keys, or other credentials in source code.",
        "example": 'API_KEY = "sk-abc123secret"\nDB_PASS = "admin1234"',
        "fix": "Store credentials in environment variables or a secrets manager. Never hardcode sensitive values in source code."
    },
    {
        "cwe_id": "CWE-306",
        "name": "Missing Authentication",
        "description": "The application exposes functionality that should require authentication without enforcing it.",
        "example": "@app.route('/admin/delete')\ndef delete_user():  # no auth check",
        "fix": "Implement authentication checks for all sensitive endpoints. Use decorators or middleware to enforce access control."
    },
    {
        "cwe_id": "CWE-362",
        "name": "Race Condition",
        "description": "The program contains a code sequence that can be affected by external processes, leading to unexpected behavior.",
        "example": "if os.path.exists(file):\n    os.remove(file)  # file may be modified between check and use",
        "fix": "Use proper locking mechanisms. Avoid time-of-check to time-of-use (TOCTOU) patterns."
    },
    {
        "cwe_id": "CWE-401",
        "name": "Memory Leak",
        "description": "The program allocates memory but fails to release it, causing memory consumption to grow over time.",
        "example": "f = open('file.txt')\ndata = f.read()\n# f.close() never called",
        "fix": "Use context managers (with statement) to ensure resources are always released. Explicitly close files and connections."
    },
    {
        "cwe_id": "CWE-327",
        "name": "Weak Cryptographic Algorithm",
        "description": "The application uses a broken or weak cryptographic algorithm that provides insufficient security.",
        "example": "hashlib.md5(password.encode()).hexdigest()",
        "fix": "Use strong hashing algorithms like bcrypt, scrypt, or Argon2 for passwords. Use SHA-256 or better for general hashing."
    },
    {
        "cwe_id": "CWE-295",
        "name": "Improper Certificate Validation",
        "description": "The application does not properly validate SSL/TLS certificates, allowing man-in-the-middle attacks.",
        "example": "requests.get(url, verify=False)",
        "fix": "Always validate SSL certificates. Never set verify=False in production. Use proper certificate pinning."
    },
    {
        "cwe_id": "CWE-732",
        "name": "Incorrect Permission Assignment",
        "description": "The application assigns incorrect permissions to resources, allowing unauthorized access.",
        "example": "os.chmod('sensitive_file.txt', 0o777)",
        "fix": "Apply the principle of least privilege. Set restrictive permissions and only grant access as needed."
    },
    {
        "cwe_id": "CWE-400",
        "name": "Uncontrolled Resource Consumption",
        "description": "The application does not limit resource consumption, allowing attackers to cause denial of service.",
        "example": "while True:\n    data = request.recv(99999999)",
        "fix": "Implement rate limiting, input size limits, and timeouts. Validate resource-intensive operations."
    },
    {
        "cwe_id": "CWE-611",
        "name": "XML External Entity Injection (XXE)",
        "description": "The XML parser processes external entity references from user-controlled XML, allowing information disclosure.",
        "example": "tree = ET.parse(user_xml_file)",
        "fix": "Disable external entity processing in XML parsers. Use defusedxml library in Python."
    },
    {
        "cwe_id": "CWE-94",
        "name": "Code Injection",
        "description": "User-controlled input is passed to code execution functions, allowing arbitrary code execution.",
        "example": "eval(user_input)\nexec(user_code)",
        "fix": "Never use eval() or exec() with user input. Use safe alternatives or strict input validation."
    },
    {
        "cwe_id": "CWE-209",
        "name": "Information Exposure Through Error Messages",
        "description": "Error messages reveal sensitive information such as stack traces, file paths, or system details.",
        "example": "except Exception as e:\n    return str(e)  # exposes internal details",
        "fix": "Log detailed errors server-side. Return generic error messages to users. Never expose stack traces in production."
    },
    {
        "cwe_id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The application does not verify that requests are intentionally submitted by authenticated users.",
        "example": "@app.route('/transfer', methods=['POST'])\ndef transfer():  # no CSRF token check",
        "fix": "Implement CSRF tokens for all state-changing requests. Validate the Origin and Referer headers."
    },
    {
        "cwe_id": "CWE-434",
        "name": "Unrestricted File Upload",
        "description": "The application allows users to upload files without validating type, content, or size.",
        "example": "file = request.files['upload']\nfile.save('/uploads/' + file.filename)",
        "fix": "Validate file type by content, not extension. Restrict allowed types, limit file size, and store outside web root."
    },
    {
        "cwe_id": "CWE-601",
        "name": "Open Redirect",
        "description": "The application redirects users to attacker-controlled URLs without validation.",
        "example": "redirect_url = request.args.get('next')\nreturn redirect(redirect_url)",
        "fix": "Validate redirect URLs against a whitelist of allowed destinations. Never redirect to user-supplied URLs directly."
    },
    {
        "cwe_id": "CWE-863",
        "name": "Incorrect Authorization",
        "description": "The application performs authorization checks incorrectly, allowing users to access unauthorized resources.",
        "example": "if user_id = admin_id:  # assignment instead of comparison\n    grant_access()",
        "fix": "Use == for comparisons not =. Implement proper role-based access control with server-side verification."
    }
]
