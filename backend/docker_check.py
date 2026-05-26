"""Docker availability checks for Sentinel.

This module handles Docker startup and readiness checks.

Sentinel uses Docker for sandboxed scanning when Docker mode or Auto Mode is selected.
However, Docker Desktop may be installed but not currently running.

Instead of immediately failing, Sentinel tries to:
1. Check whether Docker Engine is already available.
2. Start Docker Desktop if it is installed but closed.
3. Wait for Docker Engine to become ready.
4. Return a clear status message to the scan router.

This keeps the scan router cleaner and gives the UI better warning messages.
"""

import subprocess
import time
from pathlib import Path


# Known Docker Desktop installation paths on Windows.
# For this MVP, Sentinel checks the default Docker Desktop location.
# More paths can be added later if needed.
DOCKER_DESKTOP_PATHS = [
    r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
]


def is_docker_available() -> bool:
    """Check whether Docker is installed and Docker Engine is running.

    This function uses:
        docker info

    Why docker info?
        It checks both that the Docker command exists and that the Docker Engine
        can be reached.

    A PC can have the Docker command installed while Docker Desktop/Engine is
    not running yet. In that case, docker info fails, and Sentinel knows Docker
    is not ready for scanning.
    """

    try:
        result = subprocess.run(
            ["docker", "info"],

            # Hide command output because this function only needs True/False.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,

            # Keep this short so the UI does not freeze for too long.
            timeout=5,
        )

        # Docker is considered available only if docker info exits successfully.
        return result.returncode == 0

    except FileNotFoundError:
        # The docker command does not exist on this machine.
        # This usually means Docker Desktop is not installed.
        return False

    except subprocess.TimeoutExpired:
        # Docker command exists but did not respond quickly.
        # Sentinel treats this as unavailable for now.
        return False

    except Exception:
        # Any unexpected Docker check failure should not crash the app.
        # The scan router can fall back to local scanning if needed.
        return False


def start_docker_desktop() -> bool:
    """Attempt to start Docker Desktop on Windows.

    This does not guarantee Docker Engine is ready immediately.
    Docker Desktop can take several seconds to fully start.

    This function only answers:
        Did Sentinel find Docker Desktop and successfully launch the process?
    """

    for docker_path in DOCKER_DESKTOP_PATHS:
        path = Path(docker_path)

        # Only try to launch Docker Desktop if the executable exists.
        if path.exists():
            try:
                subprocess.Popen(
                    [str(path)],

                    # Hide Docker startup output.
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,

                    # shell=False is safer because we are launching a known executable
                    # directly, not passing a command through the shell.
                    shell=False,
                )

                return True

            except Exception:
                # If launching Docker Desktop fails, report failure cleanly.
                return False

    # Docker Desktop was not found in any known install path.
    return False


def wait_for_docker(timeout_seconds: int = 60) -> bool:
    """Wait for Docker Engine to become available.

    Starting Docker Desktop is not instant.
    The desktop app can open before the Docker Engine is ready to accept commands.

    Sentinel waits and checks repeatedly instead of trying to scan immediately.
    """

    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        if is_docker_available():
            return True

        # Wait a few seconds between checks so Sentinel does not spam docker info.
        time.sleep(3)

    # Docker did not become ready before the timeout.
    return False


def ensure_docker_available() -> tuple[bool, str]:
    """Make sure Docker is ready for scanning if possible.

    This is the main function used by scan_router.py.

    It returns:
        (True, message)
            Docker is available and can be used.

        (False, message)
            Docker is unavailable and Sentinel should either fall back to
            Local Scan Mode or return a Docker-required error.

    The message is important because the UI can explain what happened:
    - Docker was already running.
    - Docker Desktop was started successfully.
    - Docker Desktop was not found.
    - Docker started but did not become ready in time.
    """

    # First check whether Docker is already ready.
    # This is the fastest path and avoids launching Docker unnecessarily.
    if is_docker_available():
        return True, "Docker is already running."

    # Docker is not ready, so try to start Docker Desktop.
    # This helps the app feel more automatic for users.
    started = start_docker_desktop()

    if not started:
        return False, "Docker Desktop could not be found on this computer."

    # Docker Desktop was launched, but the engine may still need time to start.
    if wait_for_docker(timeout_seconds=60):
        return True, "Docker Desktop was started successfully."

    # Docker Desktop opened, but Docker Engine never became usable in time.
    # Auto Mode can fall back to local scanning, while Docker-only mode can show
    # this as an error.
    return False, "Docker Desktop was started, but Docker Engine did not become ready in time."