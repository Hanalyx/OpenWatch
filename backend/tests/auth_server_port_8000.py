#!/usr/bin/env python3
"""
Minimal auth server for port 8000 to fix login issues
Focuses only on providing working /api/auth/login endpoint
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
from app.database import SessionLocal
from app.auth import pwd_context, jwt_manager
from sqlalchemy import text
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="OpenWatch Auth API", description="Authentication endpoints")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "https://localhost:3000", "https://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else "unknown"

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate user with username/password"""
    client_ip = get_client_ip(http_request)
    
    db = SessionLocal()
    try:
        logger.info(f"Login attempt for user: {request.username} from {client_ip}")
        
        # Get user from database (without MFA columns that don't exist)
        result = db.execute(text("""
            SELECT id, username, email, hashed_password, role, is_active, 
                   failed_login_attempts, locked_until, last_login
            FROM users 
            WHERE username = :username
        """), {"username": request.username})
        
        user = result.fetchone()
        if not user:
            logger.warning(f"Login failed: user not found - {request.username}")
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
        
        # Check if user is active
        if not user.is_active:
            logger.warning(f"Login failed: account deactivated - {request.username}")
            raise HTTPException(
                status_code=401,
                detail="Account is deactivated"
            )
        
        # Check if account is locked
        if user.locked_until:
            from datetime import datetime
            if user.locked_until > datetime.utcnow():
                logger.warning(f"Login failed: account locked - {request.username}")
                raise HTTPException(
                    status_code=401,
                    detail="Account is temporarily locked"
                )
        
        # Verify password
        if not pwd_context.verify(request.password, user.hashed_password):
            logger.warning(f"Login failed: invalid password - {request.username}")
            
            # Increment failed login attempts
            failed_attempts = user.failed_login_attempts + 1
            locked_until = None
            
            # Lock account after 5 failed attempts for 30 minutes
            if failed_attempts >= 5:
                from datetime import datetime, timedelta
                locked_until = datetime.utcnow() + timedelta(minutes=30)
            
            db.execute(text("""
                UPDATE users 
                SET failed_login_attempts = :attempts, locked_until = :locked_until
                WHERE id = :user_id
            """), {
                "attempts": failed_attempts,
                "locked_until": locked_until,
                "user_id": user.id
            })
            db.commit()
            
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
        
        # Reset failed login attempts and update last login
        db.execute(text("""
            UPDATE users 
            SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
            WHERE id = :user_id
        """), {"user_id": user.id})
        db.commit()
        
        user_data = {
            "sub": user.username,
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "mfa_enabled": False  # MFA not available in current schema
        }
        
        # Generate tokens
        access_token = jwt_manager.create_access_token(user_data)
        refresh_token = jwt_manager.create_refresh_token(user_data)
        
        logger.info(f"Login successful for user: {request.username}")
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=1800,  # 30 minutes
            user=user_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Authentication service error")
    finally:
        db.close()

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": "auth"}

@app.get("/api/health") 
async def api_health():
    """API health check"""
    return {"status": "healthy", "api": "auth"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)