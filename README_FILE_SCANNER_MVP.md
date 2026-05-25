# Sentinel File Scanner MVP v4

Sentinel is now a local security file analysis tool. It scans readable text-based files, not only logs.

## What it scans

Sentinel can scan files such as:

- `.txt`, `.log`, `.csv`, `.json`, `.xml`, `.yaml`, `.yml`, `.md`
- `.py`, `.js`, `.ts`, `.html`, `.css`, `.sql`
- `.ini`, `.conf`, `.cfg`, `.env`, `.properties`
- `.ps1`, `.bat`, `.cmd`, `.sh`

Binary files such as `.exe`, `.zip`, `.png`, `.pdf`, `.docx`, and database files are rejected cleanly with an unsupported-file message.

## Functional flow

1. Open the app.
2. Browse for a file or drag and drop a file into the drop area.
3. Click **Scan**.
4. Sentinel reads the file content.
5. Sentinel applies security detection rules.
6. Results are shown in the UI.
7. Scan history and findings are saved in SQLite at `data/sentinel.db`.

## Run

```bash
pip install -r requirements.txt
python main.py
```

## Test backend only

```bash
python scripts/test_backend.py
```

## Drag and drop

Drag and drop uses `tkinterdnd2`. If drag and drop does not work, run:

```bash
pip install tkinterdnd2
```

Then close and reopen the app.

## Included test files

Use files in `sample_files/`:

- `safe_document.md` should be SAFE.
- `suspicious_powershell.ps1` should be CRITICAL.
- `suspicious_batch.bat` should be HIGH or CRITICAL.
- `config_with_secret.json` should flag possible secrets.
