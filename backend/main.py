# importing libraries

import os
import asyncio
import ipaddress
import re
import socket
import httpx 
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from protego import Protego
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request, Depends, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
import asyncpg 
from passlib.context import CryptContext
import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from tools.siteflare_audit import scrape_website, generate_scorecard
from tools.local_audit import audit_local, generate_local_scorecard
# ------------------------------------------------------------- #

# GLOBAL SCOPE BEGINS-------------------------------------------#

# loading the API KEY
load_dotenv()
API_KEY = os.environ.get('GOOGLE_API_KEY')
# ------------------------------------------------------------- #

# loading the db credentials
load_dotenv()
db_username = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_name = os.getenv('DB_NAME')
JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-fallback-key")
MASTER_USER_ID=os.environ.get("MASTER_USER_ID", None)
# ------------------------------------------------------------- #

# initializing the fastapi app 
app = FastAPI()
# ------------------------------------------------------------- #

# global crypto setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# ------------------------------------------------------------- #

# global user class 
class AuthRequest(BaseModel):
    email: str
    password: str
# ------------------------------------------------------------- #

# creating an HTTPBearer instance 
security = HTTPBearer(auto_error=False)
# GLOBAL SCOPE ENDS---------------------------------------------#

# dependency function
async def get_optional_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    else:
        credential = credentials.credentials

    try:
        payload = jwt.decode(credential, JWT_SECRET, algorithms=["HS256"])

        return payload.get("sub")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")
# ------------------------------------------------------------- #

# registration endpoint 
@app.post("/api/register")
async def register_user(body: AuthRequest):
    hashed_password = pwd_context.hash(body.password)

    try: 
        connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")

        try:
            record = await connection.fetchrow(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, scans_remaining",
                body.email,
                hashed_password
            )

            new_user_id = record["id"]
            token = jwt.encode({"sub": str(new_user_id)}, JWT_SECRET, algorithm="HS256")

            return {"access_token": token}
        except asyncpg.exceptions.UniqueViolationError:
            return {"error": "An account with this email already exists."}
        finally:
            await connection.close()
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}
# ------------------------------------------------------------- #

# login endpoint
@app.post("/api/login")
async def login_user(body: AuthRequest):
    try:
        connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")

        try:
            record = await connection.fetchrow(
                "SELECT id, password_hash, scans_remaining FROM users WHERE email = $1", body.email
            )

            if not record:
                return JSONResponse(status_code=401, content={"error": "Invalid credentials."})

            if not pwd_context.verify(body.password, record["password_hash"]):
                return JSONResponse(status_code=401, content={"error": "Invalid credentials."})
            token = jwt.encode({"sub": str(record["id"])}, JWT_SECRET, algorithm="HS256")

            return {"access_token": token, "scans_remaining": record["scans_remaining"]}
        
        finally:
            await connection.close()
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}
# ------------------------------------------------------------- #

# initializing the user_scan db
@app.on_event("startup")
async def init_db():
    connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
    # ------------------------------------------------------------- #

    # anonymous_limits table
    await connection.execute("""
        CREATE TABLE IF NOT EXISTS anonymous_limits 
        (ip_address VARCHAR PRIMARY KEY, scan_count INTEGER DEFAULT 1, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
    """)
    # ------------------------------------------------------------- #

    # users table
    await connection.execute("""
        CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email VARCHAR UNIQUE,
        password_hash VARCHAR, scans_remaining INTEGER DEFAULT 5, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
    """)
    # ------------------------------------------------------------- #

    # audit_logs table 

    await connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id),
        tool_used VARCHAR, target_query VARCHAR, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # ------------------------------------------------------------- #

    # closing connection 
    await connection.close()
# ------------------------------------------------------------- #

# introducing the limiter 
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Custom Exception Handler to return a clean JSON error on HTTP 429
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests. Please wait a minute before running another audit."}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str
# ------------------------------------------------------------- #

# api endpoint for local score
class LocalRequest(BaseModel):
    query: str
    visitor_hash: str 

@app.post("/api/local")
@limiter.limit("5/minute")
async def run_local_audit(request: Request, body: LocalRequest, user_id: str = Depends(get_optional_user)):
    try:
        # ------------------------------------------------------------- #

        # opening database connection 
        connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
        # ------------------------------------------------------------- #

        # authenticated user branch 
        
        if user_id:
            uid = int(user_id)

            is_master = (str(user_id) == str(MASTER_USER_ID))

            if not is_master:
                user_record = await connection.fetchrow("SELECT scans_remaining FROM users WHERE id = $1", uid)
        # ------------------------------------------------------------- #

        # block if no scans remain 
                if user_record and user_record["scans_remaining"] < 1:
                    await connection.close()
                    return {"error": "You've exhausted your free authenticated scans. Premium upgrades coming soon!"}
        # ------------------------------------------------------------- #

        # run the audit if scans remaining
            raw_data = await audit_local(body.query)
            if "error" in raw_data:
                await connection.close()
                return {"error": raw_data["error"]}

            scorecard = generate_local_scorecard(raw_data)
        # ------------------------------------------------------------- #

        # deduct the scan and update 

            await connection.execute("UPDATE users SET scans_remaining = scans_remaining - 1 WHERE id = $1", uid)
            await connection.execute(
                "INSERT INTO audit_logs (user_id, tool_used, target_query) VALUES ($1, $2, $3)", uid, "LocalScore", body.query
            )
        # ------------------------------------------------------------- #
        
        # anonymous user branch 
        else:
            anon_record = await connection.fetchrow("SELECT scan_count FROM anonymous_limits WHERE ip_address = $1", 
                body.visitor_hash
            )
        # ------------------------------------------------------------- #
        
        # 2-scan limit check 
            if anon_record and anon_record["scan_count"] >= 2:
                await connection.close()
                return {
                    "require_signup": True,
                    "error": "You've reached your 2 free anonymous audits. Please sign in to continue."
                }
        # ------------------------------------------------------------- #

        # run the audit         
            raw_data = await audit_local(body.query)
            if "error" in raw_data:
                await connection.close()
                return {"error": raw_data["error"]}

            scorecard = generate_local_scorecard(raw_data)
        # ------------------------------------------------------------- #

        # update anon score count
            await connection.execute(
                """
                INSERT INTO anonymous_limits (ip_address, scan_count)
                VALUES ($1, 1)
                ON CONFLICT (ip_address)
                DO UPDATE SET scan_count = anonymous_limits.scan_count + 1
                """, 
                body.visitor_hash
            )
        # ------------------------------------------------------------- #

        # closing connection and return 
        await connection.close()
        return {"scorecard": scorecard}
    
    except Exception as e:
        return {"error": f"An unexpected error occurred during the local audit: {str(e)}."}
# ------------------------------------------------------------- #

# api endpoint 
@app.post("/api/audit")
@limiter.limit("5/minute")
async def run_audit(request: Request, body: URLRequest):
    # 1. Run the massive scraping engine
    raw_results = await scrape_website(body.url)
    
    # 2. Check if the scraper caught an invalid URL or SSRF attempt
    if "error" in raw_results:
        return {"error": raw_results["error"]}
        
    # 3. Pass the raw data into the grading engine
    final_scorecard = generate_scorecard(raw_results)
    
    # 4. Return the formatted data to the React UI
    return {
        "scorecard": final_scorecard,
        "raw_metrics": raw_results
    }
# ------------------------------------------------------------- #