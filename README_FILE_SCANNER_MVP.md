# Sentinel File Scanner MVP v4

Sentinel is a local security file analysis tool. It scans readable security files, scripts, configuration files, logs, and ZIP archives.

The app is designed as a desktop-based threat analysis console. It can scan files locally, use Docker container isolation when available, apply antivirus checks, detect suspicious patterns, and save scan history to SQLite.

## Main features

- Desktop UI built with Tkinter
- Browse and drag-and-drop file selection
- Local scan mode using Microsoft Defender when available
- Docker Sandbox Mode using ClamAV Docker and Sentinel's rule scanner
- Auto Mode that tries Docker first and falls back to local scanning
- Safe ZIP archive scanning
- Rule-based detection for suspicious commands, secrets, network indicators, failed logins, and service crashes
- Threat scoring and severity levels
- Recent alerts and scan history
- Beginner-friendly Threat Guide page
- Local SQLite storage

## What it scans

Sentinel can scan files such as:

- `.txt`, `.log`, `.csv`, `.json`, `.xml`, `.yaml`, `.yml`, `.md`
- `.py`, `.js`, `.ts`, `.html`, `.css`, `.sql`
- `.ini`, `.conf`, `.cfg`, `.env`, `.properties`
- `.ps1`, `.bat`, `.cmd`, `.sh`
- `.zip`

ZIP files are handled safely. Sentinel extracts ZIP contents into a temporary folder, scans the extracted files, combines the results, and then removes the temporary files.

Binary files such as `.exe`, `.png`, `.pdf`, `.docx`, and database files are not scanned by the text rule scanner. Antivirus scanning may still inspect some files depending on the selected scan mode.

## Scan modes

### Auto Mode

Auto Mode tries Docker Sandbox Mode first.

If Docker is unavailable or the Docker scan fails, Sentinel falls back to Local Scan Mode.

### Docker Sandbox Mode

Docker Sandbox Mode uses Docker container isolation.

It uses:

- ClamAV Docker for antivirus scanning
- Sentinel's custom `sentinel-scanner` Docker image for rule-based scanning

If the custom `sentinel-scanner` image is missing, Sentinel attempts to build it automatically from the Dockerfile.

### Local Scan Mode

Local Scan Mode runs on the host machine.

It uses:

- Microsoft Defender when available
- Sentinel's local rule-based scanner

This mode does not provide Docker container isolation.

## Functional flow

1. Open the app.
2. Browse for a file or drag and drop a file into the drop area.
3. Choose the scan mode in Settings if needed.
4. Click **Scan**.
5. Sentinel routes the file through Auto, Docker, or Local mode.
6. Antivirus scanning runs when available.
7. Sentinel applies rule-based detection.
8. ZIP archives are safely extracted and scanned if needed.
9. Results are shown in the UI.
10. Scan history and findings are saved in SQLite at `data/sentinel.db`.

## Threat levels

Sentinel uses these result levels:

- `SAFE`: no suspicious indicators were detected
- `MEDIUM`: unusual or incomplete scan result that should be reviewed
- `HIGH`: suspicious behavior was detected
- `CRITICAL`: malware was detected or a severe indicator was found

The Threat Guide tab inside the app explains these levels and common detection categories.

## Run

Install requirements:

```bash
pip install -r requirements.txt