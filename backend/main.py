import logging
import mimetypes
import os
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from . import models
from .auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from .database import Base, engine, get_db
from .schemas import LoginRequest, UserCreate, UserResponse
from .security import decrypt_bytes, encrypt_bytes, scan_file


BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(BASE_DIR / "uploads")))
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(10 * 1024 * 1024)))
DISALLOWED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
    ".msi",
    ".apk",
    ".sh",
    ".bash",
    ".lnk",
}


logger = logging.getLogger("secure_cloud")
logger.setLevel(logging.INFO)
if not logger.handlers:
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    handler = logging.FileHandler(log_dir / "security.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)


app = FastAPI(
    title="Cloud Secure File Vault",
    description="Secure cloud file storage application",
    version="1.0.0",
)

Base.metadata.create_all(bind=engine)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def validate_filename(filename: str | None) -> str:
    if filename is None or not filename.strip():
        raise HTTPException(status_code=400, detail="Invalid filename")

    cleaned = filename.strip()
    if "/" in cleaned or "\\" in cleaned:
        raise HTTPException(status_code=400, detail="Invalid filename")

    safe_name = os.path.basename(cleaned)
    if not safe_name or safe_name in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid filename")

    extension = Path(safe_name).suffix.lower()
    if extension in DISALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type is not allowed")

    return safe_name


@app.get("/")
def home():
    return {"message": "Cloud Secure File Vault API is running", "status": "success"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_username = db.query(models.User).filter(models.User.username == user.username).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = models.User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password),
        role="owner",
        is_active=True,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info("User registered successfully: %s", new_user.username)
    return new_user


@app.post("/login")
def login_user(login: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == login.username).first()
    if not user:
        logger.warning("Failed login attempt for username: %s", login.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not verify_password(login.password, user.password_hash):
        logger.warning("Failed login attempt for username: %s", login.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.is_active:
        logger.warning("Inactive account login blocked: %s", user.username)
        raise HTTPException(status_code=403, detail="User account is inactive")

    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
        }
    )
    logger.info("Successful login: %s", user.username)
    return {"message": "Login successful", "access_token": access_token, "token_type": "bearer"}


@app.post("/logout")
def logout_user():
    return {"message": "Logout successful"}


@app.get("/profile")
def get_profile(current_user: dict = Depends(get_current_user)):
    return {
        "message": "You are authenticated",
        "user_id": current_user.get("sub"),
        "username": current_user.get("username"),
        "role": current_user.get("role"),
    }


@app.post("/upload")
def upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = current_user.get("sub")
    if not user_id:
        logger.warning("Upload rejected: missing user in token")
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    safe_filename = validate_filename(file.filename)
    file_content = file.file.read()
    if not file_content:
        raise HTTPException(status_code=400, detail="File upload failed")

    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File size exceeds the 10 MB limit")

    user_upload_dir = UPLOAD_DIR / str(user_id)
    user_upload_dir.mkdir(parents=True, exist_ok=True)

    temp_file = user_upload_dir / f"{uuid.uuid4().hex}.tmp"
    temp_file.write_bytes(file_content)

    try:
        scan_result = scan_file(temp_file)
        if scan_result["status"] == "infected":
            logger.warning("Malware detected for user %s file %s", user_id, safe_filename)
            raise HTTPException(status_code=400, detail="Malware detected. The file was rejected.")

        if scan_result["status"] != "clean":
            logger.error("ClamAV error for user %s file %s: %s", user_id, safe_filename, scan_result.get("message"))
            raise HTTPException(status_code=503, detail="Virus scanner unavailable.")
    finally:
        if temp_file.exists():
            temp_file.unlink()

    stored_extension = Path(safe_filename).suffix.lower()
    stored_name = f"{uuid.uuid4().hex}{stored_extension}"
    encrypted_file_path = user_upload_dir / stored_name
    encrypted_file_path.write_bytes(encrypt_bytes(file_content))

    mime_type = file.content_type or mimetypes.guess_type(safe_filename)[0] or "application/octet-stream"
    metadata = models.FileRecord(
        owner_id=int(user_id),
        original_filename=safe_filename,
        stored_filename=stored_name,
        file_path=str(encrypted_file_path),
        file_size=len(file_content),
        mime_type=mime_type,
        encryption_status="encrypted",
        malware_status="clean",
        is_deleted=False,
    )
    db.add(metadata)
    db.commit()
    db.refresh(metadata)

    logger.info("File uploaded successfully for user %s: file_id=%s", user_id, metadata.id)
    return {
        "message": "File uploaded successfully",
        "file_id": metadata.id,
        "filename": safe_filename,
        "size_bytes": len(file_content),
        "owner_id": user_id,
    }


@app.get("/files")
def list_user_files(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = int(current_user.get("sub"))
    files = (
        db.query(models.FileRecord)
        .filter(models.FileRecord.owner_id == user_id, models.FileRecord.is_deleted.is_(False))
        .order_by(models.FileRecord.upload_timestamp.desc())
        .all()
    )
    return [
        {
            "id": record.id,
            "filename": record.original_filename,
            "size_bytes": record.file_size,
            "uploaded_at": record.upload_timestamp.isoformat() if record.upload_timestamp else None,
            "malware_status": record.malware_status,
            "encryption_status": record.encryption_status,
        }
        for record in files
    ]


@app.get("/download/{file_id}")
def download_file(file_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = int(current_user.get("sub"))
    record = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not record or record.is_deleted:
        logger.warning("Unauthorized file download attempt: user %s file_id=%s", user_id, file_id)
        raise HTTPException(status_code=404, detail="File not found.")

    if record.owner_id != user_id:
        logger.warning("Authorization failure: user %s attempted access to file %s owned by %s", user_id, file_id, record.owner_id)
        raise HTTPException(status_code=403, detail="You are not authorized to access this file.")

    file_path = Path(record.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found.")

    try:
        decrypted = decrypt_bytes(file_path.read_bytes())
    except Exception:
        logger.exception("Failed to decrypt file for user %s file_id=%s", user_id, file_id)
        raise HTTPException(status_code=500, detail="File could not be decrypted.")

    logger.info("File download by user %s: file_id=%s", user_id, file_id)
    return Response(
        content=decrypted,
        media_type=record.mime_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{record.original_filename}"'},
    )


@app.delete("/files/{file_id}")
def delete_file(file_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = int(current_user.get("sub"))
    record = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not record or record.is_deleted:
        raise HTTPException(status_code=404, detail="File not found.")

    if record.owner_id != user_id:
        logger.warning("Authorization failure: user %s attempted deletion of file %s owned by %s", user_id, file_id, record.owner_id)
        raise HTTPException(status_code=403, detail="You are not authorized to delete this file.")

    file_path = Path(record.file_path)
    if file_path.exists():
        file_path.unlink()

    record.is_deleted = True
    record.malware_status = "deleted"
    db.commit()
    logger.info("File deleted by user %s: file_id=%s", user_id, file_id)
    return {"message": "File deleted successfully", "file_id": file_id}
