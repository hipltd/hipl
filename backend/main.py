import os
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import asyncpg 

from tools.siteflare_audit import scrape_website, generate_scorecard
from tools.local_audit import audit_local, generate_local_scorecard
# ------------------------------------------------------------- #

load_dotenv()
db_username = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_name = os.getenv('DB_NAME')

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
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ],  
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

class LocalRequest(BaseModel):
    query: str
    visitor_hash: str 
# ------------------------------------------------------------- #

@app.on_event("startup")
async def init_db():
    connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
    
    # Simple table to track anonymous daily usage
    await connection.execute("""
        CREATE TABLE IF NOT EXISTS anonymous_limits (
            visitor_hash VARCHAR PRIMARY KEY, 
            scan_count INTEGER DEFAULT 0, 
            last_scan_date DATE DEFAULT CURRENT_DATE
        )
    """)
    await connection.close()

# ------------------------------------------------------------- #
# ShopScore Endpoint (2 Scans / Day Limit)
# ------------------------------------------------------------- #
@app.post("/api/local")
@limiter.limit("5/minute")
async def run_local_audit(request: Request, body: LocalRequest):
    try:
        connection = await asyncpg.connect(f"postgresql://{db_username}:{db_password}@localhost:5432/{db_name}")
        current_date = datetime.utcnow().date()

        record = await connection.fetchrow(
            "SELECT scan_count, last_scan_date FROM anonymous_limits WHERE visitor_hash = $1",
            body.visitor_hash
        )

        if record:
            scan_count = record["scan_count"]
            last_date = record["last_scan_date"]

            # Reset limit if calendar date has advanced
            if last_date < current_date:
                scan_count = 0
                await connection.execute(
                    "UPDATE anonymous_limits SET scan_count = 0, last_scan_date = $1 WHERE visitor_hash = $2",
                    current_date, body.visitor_hash
                )

            if scan_count >= 2:
                await connection.close()
                return {"error": "You've reached your 2 free daily ShopScore audits. Limit resets at midnight UTC!"}
        else:
            # First time seeing this visitor_hash
            await connection.execute(
                "INSERT INTO anonymous_limits (visitor_hash, scan_count, last_scan_date) VALUES ($1, 0, $2)",
                body.visitor_hash, current_date
            )

        # Run the Places API audit
        raw_data = await audit_local(body.query)
        if "error" in raw_data:
            await connection.close()
            return {"error": raw_data["error"]}

        scorecard = generate_local_scorecard(raw_data)

        # Increment scan count on success
        await connection.execute(
            "UPDATE anonymous_limits SET scan_count = scan_count + 1 WHERE visitor_hash = $1",
            body.visitor_hash
        )
        
        await connection.close()
        return {"scorecard": scorecard}
    
    except Exception as e:
        return {"error": f"An unexpected error occurred during the local audit: {str(e)}."}

# ------------------------------------------------------------- #
# SiteFlare Endpoint (Completely Free & Unrestricted)
# ------------------------------------------------------------- #
@app.post("/api/audit")
@limiter.limit("5/minute")
async def run_audit(request: Request, body: URLRequest):
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