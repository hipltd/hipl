import os
from datetime import datetime
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import asyncpg 
import bcrypt
from passlib.context import CryptContext
import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from tools.siteflare_audit import scrape_website, generate_scorecard
from tools.local_audit import audit_local, generate_local_scorecard
# ------------------------------------------------------------- #

load_dotenv()
API_KEY = os.environ.get('GOOGLE_API_KEY')
db_username = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_name = os.getenv('DB_NAME')
JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-fallback-key")
MASTER_USER_ID = os.environ.get("MASTER_USER_ID", None)

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests. Please wait a minute before running another audit."}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000", "http://127.0.0.1:8000"],  
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

class AuthRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=6, max_length=12)

class URLRequest(BaseModel):
    url: str

class LocalRequest(BaseModel):
    query: str
    visitor_hash: str 
# ------------------------------------------------------------- #

async def get_optional_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

@app.on_event("startup")
async def init_db():
    connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
    
    await connection.execute("""
        CREATE TABLE IF NOT EXISTS anonymous_limits (
            ip_address VARCHAR PRIMARY KEY, 
            scan_count INTEGER DEFAULT 1, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    await connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, 
            email VARCHAR UNIQUE,
            password_hash VARCHAR, 
            daily_scans_used INTEGER DEFAULT 0,
            lifetime_scans_used INTEGER DEFAULT 0,
            last_scan_date DATE DEFAULT CURRENT_DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    await connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY, 
            user_id INTEGER REFERENCES users(id),
            tool_used VARCHAR, 
            target_query VARCHAR, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    await connection.close()

@app.post("/api/register")
async def register_user(body: AuthRequest):
    hashed_password = pwd_context.hash(body.password)
    try: 
        connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
        try:
            record = await connection.fetchrow(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
                body.email, hashed_password
            )
            token = jwt.encode({"sub": str(record["id"])}, JWT_SECRET, algorithm="HS256")
            return {"access_token": token}
        except asyncpg.exceptions.UniqueViolationError:
            return {"error": "An account with this email already exists."}
        finally:
            await connection.close()
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}

@app.post("/api/login")
async def login_user(body: AuthRequest):
    try:
        connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
        try:
            record = await connection.fetchrow(
                "SELECT id, password_hash, daily_scans_used, lifetime_scans_used FROM users WHERE email = $1", body.email
            )
            if not record or not pwd_context.verify(body.password, record["password_hash"]):
                return JSONResponse(status_code=401, content={"error": "Invalid credentials."})
            
            token = jwt.encode({"sub": str(record["id"])}, JWT_SECRET, algorithm="HS256")
            return {
                "access_token": token, 
                "daily_used": record["daily_scans_used"],
                "lifetime_used": record["lifetime_scans_used"]
            }
        finally:
            await connection.close()
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}

# ------------------------------------------------------------- #
# Shared Rate Limit Enforcer
# ------------------------------------------------------------- #
async def enforce_rate_limits(connection, user_id, visitor_hash):
    if user_id:
        uid = int(user_id)
        is_master = (str(user_id) == str(MASTER_USER_ID))
        
        if not is_master:
            user = await connection.fetchrow(
                "SELECT daily_scans_used, lifetime_scans_used, last_scan_date FROM users WHERE id = $1", uid
            )
            
            current_date = datetime.utcnow().date()
            db_date = user["last_scan_date"]
            
            daily_used = user["daily_scans_used"]
            if db_date < current_date:
                daily_used = 0 
                await connection.execute("UPDATE users SET daily_scans_used = 0, last_scan_date = $1 WHERE id = $2", current_date, uid)
                
            if user["lifetime_scans_used"] >= 6:
                return {"error": "You have reached your 6 lifetime scans limit. Premium upgrades coming soon!"}
            if daily_used >= 3:
                return {"error": "You have exhausted your 3 daily scans. Your limit resets at midnight UTC."}
                
        return {"authorized": True, "type": "user", "uid": uid}
    else:
        anon_record = await connection.fetchrow("SELECT scan_count FROM anonymous_limits WHERE ip_address = $1", visitor_hash)
        if anon_record and anon_record["scan_count"] >= 2:
            return {"require_signup": True, "error": "You've reached your 2 free anonymous audits. Please sign in to continue."}
        
        return {"authorized": True, "type": "anon"}

async def update_usage_logs(connection, auth_status, tool_name, query, visitor_hash):
    if auth_status["type"] == "user":
        await connection.execute(
            "UPDATE users SET daily_scans_used = daily_scans_used + 1, lifetime_scans_used = lifetime_scans_used + 1 WHERE id = $1", 
            auth_status["uid"]
        )
        await connection.execute(
            "INSERT INTO audit_logs (user_id, tool_used, target_query) VALUES ($1, $2, $3)", 
            auth_status["uid"], tool_name, query
        )
    else:
        await connection.execute(
            """
            INSERT INTO anonymous_limits (ip_address, scan_count)
            VALUES ($1, 1)
            ON CONFLICT (ip_address)
            DO UPDATE SET scan_count = anonymous_limits.scan_count + 1
            """, 
            visitor_hash
        )

# ------------------------------------------------------------- #
# Endpoints
# ------------------------------------------------------------- #

@app.post("/api/local")
@limiter.limit("5/minute")
async def run_local_audit(request: Request, body: LocalRequest, user_id: str = Depends(get_optional_user)):
    try:
        connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
        
        auth_check = await enforce_rate_limits(connection, user_id, body.visitor_hash)
        if "error" in auth_check:
            await connection.close()
            return auth_check

        raw_data = await audit_local(body.query)
        if "error" in raw_data:
            await connection.close()
            return {"error": raw_data["error"]}

        scorecard = generate_local_scorecard(raw_data)
        await update_usage_logs(connection, auth_check, "LocalScore", body.query, body.visitor_hash)
        
        await connection.close()
        return {"scorecard": scorecard}
    
    except Exception as e:
        return {"error": f"An unexpected error occurred during the local audit: {str(e)}."}


@app.post("/api/audit")
@limiter.limit("5/minute")
async def run_audit(request: Request, body: URLRequest, user_id: str = Depends(get_optional_user)):
    try:
        raw_results = await scrape_website(body.url)
        if "error" in raw_results:
            return {"error": raw_results["error"]}
            
        final_scorecard = generate_scorecard(raw_results)
        
        return {
            "scorecard": final_scorecard,
            "raw_metrics": raw_results
        }

    except Exception as e:
        return {"error": f"An unexpected error occurred during the website audit: {str(e)}."}