"""
OpenWatch Application Configuration
FIPS-compliant security settings and environment configuration
"""
import os
from typing import Optional, List
from pydantic import validator
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with FIPS compliance"""
    
    # Application
    app_name: str = "OpenWatch"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # Security
    secret_key: str
    algorithm: str = "RS256"  # FIPS-approved RSA signature
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # Database (with TDE support)
    database_url: str
    database_ssl_mode: str = "require"
    database_ssl_cert: Optional[str] = None
    database_ssl_key: Optional[str] = None
    database_ssl_ca: Optional[str] = None
    
    # Redis/Celery (secure configuration)
    redis_url: str = "redis://localhost:6379"
    redis_ssl: bool = False  # Disabled for Docker development
    redis_ssl_cert: Optional[str] = None
    redis_ssl_key: Optional[str] = None
    redis_ssl_ca: Optional[str] = None
    
    # OpenSCAP
    openscap_timeout: int = 3600  # 1 hour max scan time
    max_concurrent_scans: int = 5
    scap_content_dir: str = os.getenv("SCAP_CONTENT_DIR", "/app/data/scap")
    scan_results_dir: str = os.getenv("SCAN_RESULTS_DIR", "/app/data/results")
    
    # FIPS Configuration
    fips_mode: bool = True
    master_key: str  # For credential encryption
    
    # TLS/HTTPS
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None
    tls_ca_file: Optional[str] = None
    require_https: bool = True
    
    # Allowed hosts for CORS
    allowed_origins: List[str] = ["https://localhost:3001"]
    
    # File upload limits
    max_upload_size: int = 100 * 1024 * 1024  # 100MB
    allowed_file_types: List[str] = [".xml", ".zip", ".bz2", ".gz"]
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    audit_log_file: str = "/app/logs/audit.log"
    
    @validator("secret_key")
    def secret_key_must_be_strong(cls, v):
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        return v
    
    @validator("master_key")
    def master_key_must_be_strong(cls, v):
        if len(v) < 32:
            raise ValueError("Master key must be at least 32 characters long")
        return v
    
    @validator("allowed_origins")
    def validate_origins(cls, v):
        for origin in v:
            if not origin.startswith(("https://", "http://localhost")):
                raise ValueError("All origins must use HTTPS (except localhost)")
        return v
    
    class Config:
        env_file = ".env"
        env_prefix = "OPENWATCH_"
        extra = "allow"  # Allow extra fields from environment


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings"""
    return Settings()


# Security middleware configuration
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}

# FIPS-approved cipher suites for TLS
FIPS_TLS_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256"
]