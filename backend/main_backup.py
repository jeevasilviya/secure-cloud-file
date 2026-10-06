import os
import shutil

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from . import models
from .schemas import UserCreate, UserResponse, LoginRequest
from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)
app = FastAPI(
    title="Cloud Secure File Vault",
    description="Secure cloud file storage application",
    version="1.0.0"
)


# Create database tables
Base.metadata.create_all(bind=engine)


# --------------------------------------------------
# Home
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "Cloud Secure File Vault API is running",
        "status": "success"
    }


# --------------------------------------------------
# Health Check
# --------------------------------------------------

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


# --------------------------------------------------
# User Registration
# --------------------------------------------------

@app.post("/register", response_model=UserResponse)
def register_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):

    # Check if username already exists
    existing_username = (
        db.query(models.User)
        .filter(models.User.username == user.username)
        .first()
    )

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    # Check if email already exists
    existing_email = (
        db.query(models.User)
        .filter(models.User.email == user.email)
        .first()
    )

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # Hash password
    hashed_password = hash_password(user.password)

    # Create new user
    new_user = models.User(
        username=user.username,
        email=user.email,
        password_hash=hashed_password,
        role="owner",
        is_active=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


# --------------------------------------------------
# User Login
# --------------------------------------------------

@app.post("/login")
def login_user(
    login: LoginRequest,
    db: Session = Depends(get_db)
):

    # Find user by username
    user = (
        db.query(models.User)
        .filter(models.User.username == login.username)
        .first()
    )

    # Invalid username
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Verify password
    if not verify_password(
        login.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Check whether account is active
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )

    # Create JWT access token
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role
        }
    )

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer"
    }

# --------------------------------------------------
# Protected User Profile
# --------------------------------------------------

@app.get("/profile")
def get_profile(
    current_user: dict = Depends(get_current_user)
):
    return {
        "message": "You are authenticated",
        "user_id": current_user.get("sub"),
        "username": current_user.get("username"),
        "role": current_user.get("role")
    }
# --------------------------------------------------
# Secure File Upload
# --------------------------------------------------

UPLOAD_DIR = "uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    # Create a safe filename
    safe_filename = os.path.basename(file.filename)

    # Prevent empty filenames
    if not safe_filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename"
        )

    # Create user-specific folder
    user_id = current_user.get("sub")
    user_folder = os.path.join(
        UPLOAD_DIR,
        str(user_id)
    )

    os.makedirs(user_folder, exist_ok=True)

    # Final file location
    file_path = os.path.join(
        user_folder,
        safe_filename
    )

    # Save file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "message": "File uploaded successfully",
        "filename": safe_filename,
        "owner_id": user_id
    }