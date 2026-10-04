from fastapi import FastAPI

app = FastAPI(
    title="Cloud Secure File Vault",
    description="Secure cloud file storage application",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "Cloud Secure File Vault API is running",
        "status": "success"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }