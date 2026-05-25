"""Detection rules for Sentinel File Scanner.

Rules are intentionally explainable: each rule has regex patterns, a severity,
a score, a category, and an explanation. This keeps the scanner functional and
also easy to explain.
"""

from __future__ import annotations

RULES = [
    {
        "id": "AUTH_FAILED_LOGIN",
        "name": "Failed login attempt",
        "severity": "MEDIUM",
        "score": 12,
        "category": "Authentication",
        "explanation": "A failed authentication or login message was found.",
        "patterns": [
            r"failed\s+login",
            r"login\s+failed",
            r"failed\s+password",
            r"authentication\s+failed",
            r"invalid\s+user",
            r"invalid\s+password",
            r"logon\s+failure",
            r"account\s+failed\s+to\s+log\s+on",
            r"event\s*id\s*[:=]?\s*4625",
        ],
    },
    {
        "id": "PRIVILEGED_ACCOUNT_REFERENCE",
        "name": "Privileged account reference",
        "severity": "MEDIUM",
        "score": 10,
        "category": "Authentication",
        "explanation": "The file mentions a privileged account such as admin, root, administrator, or system.",
        "patterns": [
            r"\badmin\b",
            r"\badministrator\b",
            r"\broot\b",
            r"\bsystem\b",
        ],
    },
    {
        "id": "SERVICE_CRASH",
        "name": "Service crash or failure",
        "severity": "HIGH",
        "score": 25,
        "category": "System Stability",
        "explanation": "A service crash, unexpected stop, shutdown, or application failure was found.",
        "patterns": [
            r"service\s+crashed",
            r"service\s+stopped\s+unexpectedly",
            r"service\s+failure",
            r"application\s+error",
            r"critical\s+error",
            r"faulting\s+application",
            r"unexpected\s+shutdown",
            r"event\s*id\s*[:=]?\s*7031",
            r"event\s*id\s*[:=]?\s*1000",
        ],
    },
    {
        "id": "SUSPICIOUS_POWERSHELL",
        "name": "Suspicious PowerShell usage",
        "severity": "CRITICAL",
        "score": 50,
        "category": "Command Execution",
        "explanation": "Suspicious PowerShell execution flags were found, often seen in attacker tradecraft.",
        "patterns": [
            r"powershell.*-enc",
            r"powershell.*-encodedcommand",
            r"powershell.*executionpolicy\s+bypass",
            r"powershell.*-w\s+hidden",
            r"powershell.*windowstyle\s+hidden",
            r"iex\s*\(",
            r"invoke-expression",
            r"downloadstring",
            r"frombase64string",
        ],
    },
    {
        "id": "SUSPICIOUS_COMMAND_TOOL",
        "name": "Suspicious command-line tool",
        "severity": "HIGH",
        "score": 30,
        "category": "Command Execution",
        "explanation": "A command commonly used during intrusion activity was found.",
        "patterns": [
            r"\bcmd\.exe\b",
            r"\bwget\b",
            r"\bcurl\b",
            r"\bnc\.exe\b",
            r"\bncat\b",
            r"\bnetcat\b",
            r"certutil.*-urlcache",
            r"bitsadmin",
            r"mshta\.exe",
            r"rundll32\.exe",
            r"regsvr32\.exe",
            r"wmic\.exe",
        ],
    },
    {
        "id": "ACCOUNT_MANIPULATION",
        "name": "Account or privilege manipulation",
        "severity": "HIGH",
        "score": 35,
        "category": "Persistence / Privilege",
        "explanation": "The file contains commands that can create users or modify administrator group membership.",
        "patterns": [
            r"net\s+user\s+\S+\s+\S+\s+/add",
            r"net\s+localgroup\s+administrators\s+\S+\s+/add",
            r"add-localgroupmember",
            r"new-localuser",
        ],
    },
    {
        "id": "NETWORK_INDICATOR",
        "name": "External network indicator",
        "severity": "MEDIUM",
        "score": 14,
        "category": "Network",
        "explanation": "A URL, FTP address, or external network location was found.",
        "patterns": [
            r"https?://[^\s\"']+",
            r"ftp://[^\s\"']+",
        ],
    },
    {
        "id": "BASE64_LIKE_CONTENT",
        "name": "Base64-like encoded content",
        "severity": "MEDIUM",
        "score": 16,
        "category": "Obfuscation",
        "explanation": "Long encoded-looking content was found, which may hide commands or payloads.",
        "patterns": [
            r"\b[A-Za-z0-9+/]{80,}={0,2}\b",
        ],
    },
    {
        "id": "POSSIBLE_SECRET",
        "name": "Possible exposed secret",
        "severity": "HIGH",
        "score": 28,
        "category": "Credential Exposure",
        "explanation": "The file appears to contain a password, token, API key, or cloud access key.",
        "patterns": [
            r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{6,}",
            r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[\"']?[^\s\"']{8,}",
            r"AKIA[0-9A-Z]{16}",
            r"(?i)bearer\s+[a-z0-9._\-]{20,}",
        ],
    },
]

FAILED_LOGIN_RULE_ID = "AUTH_FAILED_LOGIN"
SERVICE_CRASH_RULE_ID = "SERVICE_CRASH"
