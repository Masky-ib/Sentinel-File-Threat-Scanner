"""Docker availability checks for Sentinel.

This module handles Docker startup, readiness checks, and Sentinel's custom
Docker scanner image setup.

Sentinel uses Docker for sandboxed scanning when Docker mode or Auto Mode is
selected. However, Docker can fail for three different reasons:

1. Docker is not installed.
2. Docker Desktop is installed but not running.
3. Docker is running, but Sentinel's custom scanner image has not been built yet.

This module handles all three as cleanly as possible.
"""

import subprocess
import time
from pathlib import Path


# Name of Sentinel's custom Docker image.
#
# This is the image used by docker_scanner.py when it runs Sentinel's rule-based
# scanner inside a container.
SENTINEL_SCANNER_IMAGE = "sentinel-scanner"


# The Dockerfile used to build Sentinel's scanner image.
#
# This path is relative to the project root.
SENTINEL_DOCKERFILE = Path("docker_scanner_image") / "Dockerfile"


# Known Docker Desktop installation paths on Windows.
#
# For this MVP, Sentinel checks the default Docker Desktop location.
# More paths can be added later if needed.
DOCKER_DESKTOP_PATHS = [
    r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
]


def _project_root() -> Path:
    """Return the main Sentinel project folder.

    docker_check.py lives inside:
        backend/docker_check.py

    parents[1] moves from:
        backend/
    back to:
        sentinel_file_scanner_v4/

    Docker builds must run from the project root because the Dockerfile copies:
        backend/
        docker_scanner_image/scanner_runner.py
    """

    return Path(__file__).resolve().parents[1]


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

                    # shell=False is safer because we are launching a known
                    # executable directly, not passing a command through the shell.
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


def sentinel_scanner_image_exists() -> bool:
    """Check whether Sentinel's custom scanner Docker image already exists.

    This uses:
        docker image inspect sentinel-scanner

    Why this matters:
        On the developer machine, the image may already exist because it was
        built manually.

        On another user's machine, the image may not exist yet. Sentinel needs
        to detect that and build it automatically.
    """

    try:
        result = subprocess.run(
            ["docker", "image", "inspect", SENTINEL_SCANNER_IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

        return result.returncode == 0

    except Exception:
        return False


def build_sentinel_scanner_image() -> tuple[bool, str]:
    """Build Sentinel's custom Docker scanner image if possible.

    This runs the equivalent of:

        docker build -t sentinel-scanner -f docker_scanner_image/Dockerfile .

    The build context is the project root because the Dockerfile needs access to:
        backend/
        docker_scanner_image/scanner_runner.py

    Returns:
        (True, message)
            The image was built successfully.

        (False, message)
            The image could not be built.
    """

    project_root = _project_root()
    dockerfile_path = project_root / SENTINEL_DOCKERFILE

    # If the Dockerfile is missing, Sentinel cannot build the scanner image.
    # This can happen if only the .exe is copied without the project support files.
    if not dockerfile_path.exists():
        return (
            False,
            f"Sentinel Dockerfile was not found at: {dockerfile_path}",
        )

    try:
        result = subprocess.run(
            [
                "docker",
                "build",
                "-t",
                SENTINEL_SCANNER_IMAGE,
                "-f",
                str(dockerfile_path),
                str(project_root),
            ],
            capture_output=True,
            text=True,

            # Docker builds may take time the first time because Python base
            # images may need to be downloaded.
            timeout=300,
        )

        if result.returncode == 0:
            return True, "Sentinel scanner Docker image was built successfully."

        output = (result.stderr or result.stdout or "").strip()

        return (
            False,
            f"Sentinel scanner Docker image build failed: {output or 'Unknown Docker build error.'}",
        )

    except subprocess.TimeoutExpired:
        return (
            False,
            "Sentinel scanner Docker image build timed out.",
        )

    except Exception as error:
        return (
            False,
            f"Sentinel scanner Docker image build failed: {error}",
        )


def ensure_sentinel_scanner_image() -> tuple[bool, str]:
    """Make sure Sentinel's custom scanner Docker image exists.

    Docker can be running but still not have the sentinel-scanner image.

    This function checks for the image and builds it automatically if missing.
    """

    if sentinel_scanner_image_exists():
        return True, "Sentinel scanner Docker image is already available."

    built, message = build_sentinel_scanner_image()

    if built:
        return True, message

    return False, message


def ensure_docker_available() -> tuple[bool, str]:
    """Make sure Docker and Sentinel's scanner image are ready if possible.

    This is the main function used by scan_router.py.

    It returns:
        (True, message)
            Docker is available and Sentinel's scanner image is ready.

        (False, message)
            Docker is unavailable or the Sentinel scanner image could not be built.

    The message is important because the UI can explain what happened:
    - Docker was already running.
    - Docker Desktop was started successfully.
    - Docker Desktop was not found.
    - Docker started but did not become ready in time.
    - Sentinel's scanner image was missing and had to be built.
    - Sentinel's scanner image could not be built.
    """

    docker_status_message = ""

    # First check whether Docker is already ready.
    # This is the fastest path and avoids launching Docker unnecessarily.
    if is_docker_available():
        docker_status_message = "Docker is already running."

    else:
        # Docker is not ready, so try to start Docker Desktop.
        # This helps the app feel more automatic for users.
        started = start_docker_desktop()

        if not started:
            return False, "Docker Desktop could not be found on this computer."

        # Docker Desktop was launched, but the engine may still need time to start.
        if wait_for_docker(timeout_seconds=60):
            docker_status_message = "Docker Desktop was started successfully."

        else:
            # Docker Desktop opened, but Docker Engine never became usable in time.
            # Auto Mode can fall back to local scanning, while Docker-only mode can
            # show this as an error.
            return (
                False,
                "Docker Desktop was started, but Docker Engine did not become ready in time.",
            )

    # At this point Docker Engine is available.
    # Now make sure Sentinel's custom scanner image exists.
    image_ready, image_message = ensure_sentinel_scanner_image()

    if not image_ready:
        return False, image_message

    return True, f"{docker_status_message} {image_message}"