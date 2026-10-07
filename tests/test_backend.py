import importlib
import logging
import os
import subprocess
import sys
import tempfile
import unittest
import atexit
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_ENCRYPTION_KEY = Fernet.generate_key().decode("ascii")
os.environ["ENCRYPTION_KEY"] = TEST_ENCRYPTION_KEY
os.environ["SECRET_KEY"] = "test-only-jwt-secret-not-for-production"

BOOTSTRAP_TEMP_DIR = tempfile.TemporaryDirectory()
atexit.register(BOOTSTRAP_TEMP_DIR.cleanup)
os.environ["UPLOAD_DIR"] = str(Path(BOOTSTRAP_TEMP_DIR.name) / "uploads")

from backend import database as database_module  # noqa: E402

BOOTSTRAP_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
database_module.engine = BOOTSTRAP_ENGINE
atexit.register(BOOTSTRAP_ENGINE.dispose)

from backend import models, security  # noqa: E402
from backend.database import Base, get_db  # noqa: E402
from backend.main import app  # noqa: E402

logging.getLogger("secure_cloud").handlers = [logging.NullHandler()]


class BackendTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.addCleanup(self.engine.dispose)
        self.session_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )

        def override_get_db():
            db = self.session_factory()
            try:
                yield db
            finally:
                db.close()

        self.previous_upload_dir = app_module.UPLOAD_DIR
        app_module.UPLOAD_DIR = Path(self.temp_dir.name) / "uploads"
        app_module.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self._restore_upload_dir)

        app.dependency_overrides[get_db] = override_get_db
        self.addCleanup(app.dependency_overrides.clear)

        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def _restore_upload_dir(self):
        app_module.UPLOAD_DIR = self.previous_upload_dir

    def register_and_login(self, username):
        response = self.client.post(
            "/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": "StrongTestPassword!123",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        login = self.client.post(
            "/login",
            json={
                "username": username,
                "password": "StrongTestPassword!123",
            },
        )
        self.assertEqual(login.status_code, 200, login.text)
        return login.json()["access_token"]

    def upload_clean_file(self, token, filename="notes.txt", content=b"test content"):
        with patch.object(
            app_module,
            "scan_file",
            return_value={"status": "clean", "message": "mocked clean result"},
        ):
            return self.client.post(
                "/upload",
                files={"file": (filename, content, "text/plain")},
                headers={"Authorization": f"Bearer {token}"},
            )


# Keep the production logger from writing test-generated audit entries to the
# project log file; these tests validate route results rather than log output.
from backend import main as app_module  # noqa: E402


class AuthenticationTests(BackendTestCase):
    def test_user_registration(self):
        response = self.client.post(
            "/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "StrongTestPassword!123",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["username"], "newuser")
        self.assertNotIn("password", response.json())

    def test_login_returns_usable_jwt(self):
        token = self.register_and_login("loginuser")
        response = self.client.get(
            "/profile",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["username"], "loginuser")

    def test_protected_route_rejects_missing_token(self):
        response = self.client.get("/profile")
        self.assertEqual(response.status_code, 401, response.text)


class FileRouteTests(BackendTestCase):
    def test_authenticated_user_can_upload_file(self):
        token = self.register_and_login("uploader")
        response = self.upload_clean_file(token)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["filename"], "notes.txt")

    def test_upload_creates_owned_metadata(self):
        token = self.register_and_login("metadataowner")
        response = self.upload_clean_file(token, content=b"metadata payload")
        self.assertEqual(response.status_code, 200, response.text)

        with self.session_factory() as db:
            record = db.query(models.FileRecord).filter_by(
                id=response.json()["file_id"]
            ).one()
            self.assertEqual(record.owner_id, 1)
            self.assertEqual(record.original_filename, "notes.txt")
            self.assertEqual(record.file_size, len(b"metadata payload"))
            self.assertEqual(record.encryption_status, "encrypted")
            self.assertEqual(record.malware_status, "clean")

    def test_uploaded_file_is_encrypted_on_disk(self):
        token = self.register_and_login("encryptedowner")
        plaintext = b"plain content must not be stored"
        response = self.upload_clean_file(token, content=plaintext)
        self.assertEqual(response.status_code, 200, response.text)

        with self.session_factory() as db:
            record = db.query(models.FileRecord).filter_by(
                id=response.json()["file_id"]
            ).one()
            encrypted_bytes = Path(record.file_path).read_bytes()

        self.assertNotEqual(encrypted_bytes, plaintext)
        self.assertEqual(security.decrypt_bytes(encrypted_bytes), plaintext)

    def test_owner_can_download_original_plaintext(self):
        token = self.register_and_login("downloadowner")
        plaintext = b"download this exact content"
        upload = self.upload_clean_file(token, content=plaintext)
        self.assertEqual(upload.status_code, 200, upload.text)

        response = self.client.get(
            f"/download/{upload.json()['file_id']}",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, plaintext)

    def test_another_user_cannot_download_file(self):
        owner_token = self.register_and_login("fileowner")
        upload = self.upload_clean_file(owner_token)
        self.assertEqual(upload.status_code, 200, upload.text)

        other_token = self.register_and_login("otheruser")
        response = self.client.get(
            f"/download/{upload.json()['file_id']}",
            headers={"Authorization": f"Bearer {other_token}"},
        )

        self.assertEqual(response.status_code, 403, response.text)

    def test_owner_can_delete_file_and_it_cannot_be_downloaded(self):
        token = self.register_and_login("deleteowner")
        upload = self.upload_clean_file(token)
        self.assertEqual(upload.status_code, 200, upload.text)
        file_id = upload.json()["file_id"]

        with self.session_factory() as db:
            record = db.query(models.FileRecord).filter_by(id=file_id).one()
            stored_path = Path(record.file_path)

        response = self.client.delete(
            f"/files/{file_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(stored_path.exists())

        download = self.client.get(
            f"/download/{file_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(download.status_code, 404, download.text)

    def test_path_traversal_filename_is_rejected(self):
        token = self.register_and_login("pathuser")
        with patch.object(
            app_module,
            "scan_file",
            return_value={"status": "clean", "message": "mocked clean result"},
        ):
            response = self.client.post(
                "/upload",
                files={"file": ("../outside.txt", b"content", "text/plain")},
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["detail"], "Invalid filename")

    def test_dangerous_file_extension_is_rejected(self):
        token = self.register_and_login("extensionuser")
        response = self.upload_clean_file(
            token,
            filename="program.exe",
            content=b"not an executable",
        )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["detail"], "File type is not allowed")

    def test_upload_allows_skipped_malware_scan(self):
        token = self.register_and_login("skippedscanuser")

        with patch.object(
            app_module,
            "scan_file",
            return_value={"status": "skipped", "message": "ClamAV not installed; scan skipped"},
        ):
            response = self.client.post(
                "/upload",
                files={"file": ("notes.txt", b"test content", "text/plain")},
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["filename"], "notes.txt")

    def test_oversized_file_is_rejected(self):
        token = self.register_and_login("largefileuser")
        original_limit = app_module.MAX_FILE_SIZE
        app_module.MAX_FILE_SIZE = 8
        self.addCleanup(setattr, app_module, "MAX_FILE_SIZE", original_limit)

        response = self.upload_clean_file(
            token,
            filename="large.txt",
            content=b"more than eight bytes",
        )

        self.assertEqual(response.status_code, 413, response.text)


class EncryptionTests(unittest.TestCase):
    def test_encryption_decryption_round_trip(self):
        plaintext = b"encryption test payload"
        ciphertext = security.encrypt_bytes(plaintext)

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(security.decrypt_bytes(ciphertext), plaintext)

    def test_encrypted_data_survives_module_reinitialization_with_same_key(self):
        plaintext = b"survives security module reinitialization"
        ciphertext = security.encrypt_bytes(plaintext)

        reloaded_security = importlib.reload(security)

        self.assertEqual(reloaded_security.decrypt_bytes(ciphertext), plaintext)

    def test_missing_encryption_key_fails_safely(self):
        env = os.environ.copy()
        env.pop("ENCRYPTION_KEY", None)
        result = subprocess.run(
            [sys.executable, "-c", "import backend.security"],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENCRYPTION_KEY is required", result.stderr)

    def test_invalid_encryption_key_fails_safely(self):
        env = os.environ.copy()
        env["ENCRYPTION_KEY"] = "not-a-valid-fernet-key"
        result = subprocess.run(
            [sys.executable, "-c", "import backend.security"],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ENCRYPTION_KEY is invalid", result.stderr)


class ClamAVMockTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.scanner = self.root / "clamscan.exe"
        self.database = self.root / "db"
        self.sample = self.root / "sample.txt"
        self.scanner.touch()
        self.database.mkdir()
        self.sample.write_text("harmless test data", encoding="utf-8")

        self.scanner_patch = patch.object(
            security, "get_clamav_scanner_path", return_value=str(self.scanner)
        )
        self.database_patch = patch.object(
            security, "get_clamav_database_dir", return_value=str(self.database)
        )
        self.scanner_patch.start()
        self.database_patch.start()
        self.addCleanup(self.scanner_patch.stop)
        self.addCleanup(self.database_patch.stop)

    @patch("backend.security.subprocess.run")
    def test_clean_scanner_result(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout="sample.txt: OK",
            stderr="",
        )

        result = security.scan_file(self.sample)

        self.assertEqual(result["status"], "clean")
        run.assert_called_once()
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("backend.security.subprocess.run")
    def test_infected_scanner_result(self, run):
        run.return_value = SimpleNamespace(
            returncode=1,
            stdout="sample.txt: Eicar-Test-Signature FOUND",
            stderr="",
        )

        result = security.scan_file(self.sample)

        self.assertEqual(result["status"], "infected")
        self.assertIn("FOUND", result["message"])

    @patch("backend.security.subprocess.run")
    def test_scanner_error_result(self, run):
        run.return_value = SimpleNamespace(
            returncode=2,
            stdout="",
            stderr="scanner error",
        )

        result = security.scan_file(self.sample)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["message"], "scanner error")


if __name__ == "__main__":
    unittest.main()
