"""Detection rules for Sentinel File Scanner.

This file defines Sentinel's rule-based detection logic.

The scanner reads files line by line and checks each line against these rules.
Each rule contains:
- an id
- a human-readable name
- a severity
- a score
- a category
- an explanation
- one or more regex patterns

Why rules are stored this way:
    The goal is to make Sentinel explainable.

Instead of hiding detection logic inside complicated code, each rule clearly
shows what kind of behavior it detects and why that behavior matters.

This is useful for:
- debugging the scanner
- explaining results in the UI
- writing the dissertation
- expanding Sentinel later with more rules
"""

from __future__ import annotations


# RULES is the main detection rule list used by scanner.py.
#
# Each dictionary represents one detection rule.
# The regex patterns are intentionally grouped by behavior instead of being
# spread across the scanner code.
#
# This makes the scanner easier to maintain:
# - scanner.py handles how scanning works
# - rules.py defines what Sentinel should look for
RULES = [
    {
        # Stable rule ID used internally by Sentinel.
        # This should not be changed casually because other parts of the app
        # may refer to it when grouping or counting detections.
        "id": "AUTH_FAILED_LOGIN",

        # Human-readable name shown in scan results.
        "name": "Failed login attempt",

        # MEDIUM severity is used here because one failed login can be normal,
        # but it can become suspicious when repeated many times.
        "severity": "MEDIUM",

        # Score contributes to the final threat score.
        # Failed logins are suspicious, but less severe than malware or
        # privilege manipulation by themselves.
        "score": 12,

        # Category helps group related detections.
        "category": "Authentication",

        # Explanation is used to make the finding understandable to a user.
        "explanation": "A failed authentication or login message was found.",

        # These regex patterns cover common failed-login wording from logs,
        # authentication messages, and Windows Event ID 4625.
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

        # MEDIUM severity is used because mentioning admin/root/system is not
        # always malicious. It becomes more meaningful when combined with other
        # suspicious behavior.
        "severity": "MEDIUM",
        "score": 10,
        "category": "Authentication",
        "explanation": "The file mentions a privileged account such as admin, root, administrator, or system.",

        # Word boundaries are used so Sentinel does not match these words inside
        # unrelated longer words by accident.
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

        # HIGH severity is used because repeated crashes or service failures can
        # indicate instability, tampering, or failed exploitation attempts.
        "severity": "HIGH",
        "score": 25,
        "category": "System Stability",
        "explanation": "A service crash, unexpected stop, shutdown, or application failure was found.",

        # These patterns cover both plain-language service crash messages and
        # common Windows event IDs:
        # - 7031: service terminated unexpectedly
        # - 1000: application error
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

        # CRITICAL severity is used because these PowerShell patterns are often
        # linked to malware, payload download, obfuscation, or stealthy execution.
        "severity": "CRITICAL",
        "score": 50,
        "category": "Command Execution",
        "explanation": "Suspicious PowerShell execution flags were found, often seen in attacker tradecraft.",

        # These patterns focus on suspicious PowerShell behavior:
        # - encoded commands
        # - execution policy bypass
        # - hidden windows
        # - Invoke-Expression usage
        # - downloading code
        # - base64 decoding
        #
        # Not every PowerShell command is malicious, so Sentinel only looks for
        # suspicious combinations and high-risk keywords.
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

        # HIGH severity is used because these tools are frequently used in real
        # attacks, but they can also have legitimate administrative uses.
        "severity": "HIGH",
        "score": 30,
        "category": "Command Execution",
        "explanation": "A command commonly used during intrusion activity was found.",

        # This rule detects tools commonly used for:
        # - command execution
        # - downloading files
        # - living-off-the-land activity
        # - script execution
        # - remote execution or system discovery
        #
        # This does not automatically prove malware.
        # It means the file deserves attention.
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

        # HIGH severity is used because creating users or adding accounts to the
        # administrators group can indicate persistence or privilege escalation.
        "severity": "HIGH",
        "score": 35,
        "category": "Persistence / Privilege",
        "explanation": "The file contains commands that can create users or modify administrator group membership.",

        # These patterns look for common Windows account manipulation commands.
        # This is especially important because malware and attackers often create
        # backup users or add users to privileged groups for persistence.
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

        # MEDIUM severity is used because URLs and FTP links are not always bad.
        # However, they become suspicious when combined with download tools,
        # scripts, encoded content, or command execution.
        "severity": "MEDIUM",
        "score": 14,
        "category": "Network",
        "explanation": "A URL, FTP address, or external network location was found.",

        # Detects HTTP, HTTPS, and FTP links.
        # These may indicate download locations, callbacks, or external resources.
        "patterns": [
            r"https?://[^\s\"']+",
            r"ftp://[^\s\"']+",
        ],
    },
    {
        "id": "BASE64_LIKE_CONTENT",
        "name": "Base64-like encoded content",

        # MEDIUM severity is used because base64 text can be harmless, but it is
        # also commonly used to hide commands or payloads.
        "severity": "MEDIUM",
        "score": 16,
        "category": "Obfuscation",
        "explanation": "Long encoded-looking content was found, which may hide commands or payloads.",

        # This pattern looks for long base64-like strings.
        #
        # The length threshold is intentionally high to reduce false positives.
        # Short base64-looking strings can appear in normal files, but very long
        # encoded blobs are more suspicious.
        "patterns": [
            r"\b[A-Za-z0-9+/]{80,}={0,2}\b",
        ],
    },
    {
        "id": "POSSIBLE_SECRET",
        "name": "Possible exposed secret",

        # HIGH severity is used because leaked credentials, tokens, or API keys
        # can allow unauthorized access even if the file is not malware.
        "severity": "HIGH",
        "score": 28,
        "category": "Credential Exposure",
        "explanation": "The file appears to contain a password, token, API key, or cloud access key.",

        # These patterns detect common secret formats:
        # - password-like assignments
        # - API keys, secrets, and tokens
        # - AWS access key IDs
        # - bearer tokens
        #
        # The patterns are intentionally broad because this is an MVP scanner.
        # A later version could add more precise secret validation.
        "patterns": [
            r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{6,}",
            r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[\"']?[^\s\"']{8,}",
            r"AKIA[0-9A-Z]{16}",
            r"(?i)bearer\s+[a-z0-9._\-]{20,}",
        ],
    },
]


# These constants identify rules that are used by higher-level correlation logic.
#
# For example:
# - scanner.py can detect individual failed login lines.
# - another function can count repeated failed logins and raise the severity.
#
# Using constants avoids hardcoding string IDs in multiple places.
FAILED_LOGIN_RULE_ID = "AUTH_FAILED_LOGIN"
SERVICE_CRASH_RULE_ID = "SERVICE_CRASH"