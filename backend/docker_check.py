import subprocess
import time
from pathlib import Path


DOCKER_DESKTOP_PATHS = [
    r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
]


def is_docker_available() -> bool:
    """
    Checks whether Docker is installed and Docker Engine is running.
    """

    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

        return result.returncode == 0

    except FileNotFoundError:
        return False

    except subprocess.TimeoutExpired:
        return False

    except Exception:
        return False


def start_docker_desktop() -> bool:
    """
    Attempts to start Docker Desktop on Windows.
    """

    for docker_path in DOCKER_DESKTOP_PATHS:
        path = Path(docker_path)

        if path.exists():
            try:
                subprocess.Popen(
                    [str(path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                )
                return True
            except Exception:
                return False

    return False


def wait_for_docker(timeout_seconds: int = 60) -> bool:
    """
    Waits for Docker Engine to become available.
    """

    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        if is_docker_available():
            return True

        time.sleep(3)

    return False


def ensure_docker_available() -> tuple[bool, str]:
    """
    Checks Docker. If Docker Desktop is installed but closed, tries to start it.

    Returns:
        (True, message) if Docker is available.
        (False, message) if Docker is unavailable.
    """

    if is_docker_available():
        return True, "Docker is already running."

    started = start_docker_desktop()

    if not started:
        return False, "Docker Desktop could not be found on this computer."

    if wait_for_docker(timeout_seconds=60):
        return True, "Docker Desktop was started successfully."

    return False, "Docker Desktop was started, but Docker Engine did not become ready in time."