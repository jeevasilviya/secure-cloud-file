# Cloud Secure Vault

A secure cloud file storage application designed to protect
user files using authentication, access control, encryption,
malware scanning, and security monitoring.

## Project Objective

The main objective of this project is to design and demonstrate
a secure cloud application where users can upload and manage
different types of files securely.

## Security Features

- Identity and Access Management (IAM)
- User Authentication
- Role-Based Access Control (RBAC)
- Secure File Upload
- File Type and Size Validation
- Malware Scanning
- File Encryption
- Secure Cloud Storage
- Secure File Sharing
- Temporary Download Links
- File Integrity Verification
- Security Monitoring
- Audit Logging
- Suspicious Activity Detection
- VM Security
- Network Security

## Technologies

- Python
- FastAPI
- PostgreSQL
- AWS S3
- AWS EC2
- Docker
- Nginx
- ClamAV
- AES-256 Encryption
- JWT Authentication

## Project Architecture

User
↓
HTTPS
↓
Nginx
↓
FastAPI Backend
↓
Authentication & Authorization
↓
File Security
↓
Encryption
↓
AWS S3
↓
Security Monitoring