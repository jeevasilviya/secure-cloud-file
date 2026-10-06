import os
import subprocess
from pathlib import Path

from cryptography.fernet import Fernet


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_clamav_scanner_path() -> str:
    configured = os.getenv("CLAMAV_SCANNER_PATH")
    if configured:
        return configured

    candidates = [
        r"C:\Program Files\ClamAV\clamscan.exe",
        r"C:\Program Files\ClamAV\clamdscan.exe",
        str(PROJECT_ROOT / "clamav" / "clamscan.exe"),
    ]

    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    return candidates[0]


def get_clamav_database_dir() -> str:
    configured = os.getenv("CLAMAV_DATABASE_DIR")
    if configured:
        return configured

    candidates = [
        str(PROJECT_ROOT / "clamav" / "db"),
        r"C:\Program Files\ClamAV\database",
    ]

    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    return candidates[0]


def scan_file(file_path: str | Path) -> dict:
    path = Path(file_path)

    if not path.exists():
        return {
            "status": "error",
            "message": "File not found",
        }

    scanner_path = Path(get_clamav_scanner_path())
    if not scanner_path.exists():
        return {
            "status": "error",
            "message": "ClamAV scanner is not installed or not configured",
        }

    database_dir = Path(get_clamav_database_dir())
    if not database_dir.exists():
        return {
            "status": "error",
            "message": "ClamAV database directory is missing",
        }

    command = [
        str(scanner_path),
        "--database",
        str(database_dir),
        "--no-summary",
        "--infected",
        "--stdout",
        str(path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "Virus scanner timed out",
        }

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode == 0:
        return {
            "status": "clean",
            "message": stdout or "File passed ClamAV scan",
        }

    if result.returncode == 1:
        return {
            "status": "infected",
            "message": stdout or "Malware detected by ClamAV",
        }

    return {
        "status": "error",
        "message": stderr or stdout or "Virus scanner reported an error",
    }


def get_fernet() -> Fernet:
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY is required. Set a persistent Fernet key in the environment before starting the application."
        )

    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError(
            "ENCRYPTION_KEY is invalid. It must be a valid base64-encoded Fernet key."
        ) from exc


FERNET = get_fernet()


def encrypt_bytes(data: bytes) -> bytes:
    return FERNET.encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return FERNET.decrypt(data)
