"""
OpenWatch Application Configuration
FIPS-compliant security settings and environment configuration
"""

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with FIPS compliance"""

    # Application
    app_name: str = "OpenWatch"
    app_version: str = "1.2.0"
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

    # MongoDB Configuration
    mongodb_url: str = Field(
        default="mongodb://openwatch:secure_password@mongodb:27017/openwatch_rules?authSource=admin",
        description="MongoDB connection string for compliance rules",
    )
    mongodb_database: str = Field(default="openwatch_rules", description="MongoDB database name")
    mongodb_min_pool_size: int = Field(default=10)
    mongodb_max_pool_size: int = Field(default=100)
    mongodb_ssl: bool = Field(default=False)  # Disable SSL for development
    mongodb_ssl_cert: Optional[str] = Field(default=None)
    mongodb_ssl_ca: Optional[str] = Field(default=None)

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

    # Allowed hosts for CORS (configurable via environment)
    allowed_origins: List[str] = Field(
        default_factory=lambda: os.getenv("OPENWATCH_ALLOWED_ORIGINS", "https://localhost:3001").split(",")
    )

    # Container Runtime Configuration
    container_runtime: str = Field(default="auto", description="Container runtime to use (docker, podman, auto)")
    container_socket: Optional[str] = Field(default=None, description="Custom container socket path")

    # File upload limits
    max_upload_size: int = 100 * 1024 * 1024  # 100MB
    allowed_file_types: List[str] = [".xml", ".zip", ".bz2", ".gz"]

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    audit_log_file: str = "/app/logs/audit.log"

    # Feature Flags
    # NOTE: All feature flags have been removed as their corresponding refactorings are complete:
    # - OW-REFACTOR-001B (QueryBuilder): Completed, all SQL operations use QueryBuilder
    # - OW-REFACTOR-002 (Repository Pattern): Completed, all MongoDB operations use repositories

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

    @validator("mongodb_url")
    def validate_mongodb_url(cls, v):
        if not v.startswith("mongodb://"):
            raise ValueError("MongoDB URL must start with mongodb://")
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
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

# FIPS-approved cipher suites for TLS
FIPS_TLS_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
]
