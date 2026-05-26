"""Sentinel backend package.

This package contains the scanning logic used by the desktop UI.

The backend is responsible for:
- routing scans between Docker, local, and auto scan modes
- running antivirus checks through ClamAV or Microsoft Defender
- safely handling ZIP archives
- applying Sentinel's rule-based detections
- saving scan results to local storage

This file does not need executable code.
Its main purpose is to mark the backend folder as a Python package,
so files can import each other using package imports.
"""