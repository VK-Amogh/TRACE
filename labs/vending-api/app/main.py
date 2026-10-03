"""Vending API — Reference intentionally vulnerable lab target for TRACE."""

import sqlite3
from typing import Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Header, Query
from pydantic import BaseModel
import httpx

app = FastAPI(title="Vending Lab API", version="1.0.0")

# In-memory database simulation for fast offline testing
USERS = {
    "user-a": {"id": "user-a", "role": "user", "is_admin": False, "name": "Alice"},
    "user-b": {"id": "user-b", "role": "user", "is_admin": False, "name": "Bob"},
    "admin": {"id": "admin", "role": "admin", "is_admin": True, "name": "Administrator"},
}

ORDERS = {
    "order-101": {"id": "order-101", "user_id": "user-a", "product": "Espresso", "total": 4.50},
    "order-102": {"id": "order-102", "user_id": "user-b", "product": "Mocha", "total": 5.25},
}

PRODUCTS = {
    "1": {"id": "1", "name": "Espresso", "price": 4.50},
    "2": {"id": "2", "name": "Mocha", "price": 5.25},
    "3": {"id": "3", "name": "Cold Brew", "price": 6.00},
}


# --- Models ---
class LoginRequest(BaseModel):
    username: str
    password: str


class RefundRequest(BaseModel):
    order_id: str
    amount: float
    reason: Optional[str] = "Customer request"


class UrlFetchRequest(BaseModel):
    url: str


def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    return USERS.get(token)


# --- Endpoints ---

@app.post("/api/auth/login")
def login(req: LoginRequest):
    """Authenticate synthetic test users with password 'local-test-password'."""
    if req.password == "local-test-password" and req.username in USERS:
        return {
            "access_token": req.username,  # username serves as test token
            "token_type": "bearer",
            "user": USERS[req.username],
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/products")
def list_products():
    return list(PRODUCTS.values())


@app.get("/api/products/{id}")
def get_product(id: str):
    product = PRODUCTS.get(id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


# VULNERABILITY 1: BOLA (Broken Object Level Authorization)
# Missing check that order.user_id == current_user.id
@app.get("/api/orders/{id}")
def get_order(id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    order = ORDERS.get(id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # Intentional flaw: returns order regardless of whether current_user owns it!
    return order


# VULNERABILITY 2: BFLA (Broken Function Level Authorization)
# Checks if user is authenticated, but fails to enforce admin role properly
@app.post("/api/admin/refund")
def process_refund(req: RefundRequest, current_user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    # Intentional flaw: allows any authenticated user to process refunds!
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {
        "status": "refund_approved",
        "order_id": req.order_id,
        "amount": req.amount,
        "processed_by": current_user["id"],
    }


# VULNERABILITY 3: SSRF (Server-Side Request Forgery)
# Server directly fetches user-supplied URL without boundary validation
@app.post("/api/fetch-url")
def fetch_url(req: UrlFetchRequest):
    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(req.url)
            return {"status": resp.status_code, "content": resp.text[:1000]}
    except Exception as e:
        return {"status": 500, "error": str(e)}


# VULNERABILITY 4: Mass Assignment
# Directly unpacks unconstrained client dictionary into user object
@app.patch("/api/users/{id}")
def update_user(id: str, payload: Dict[str, Any], current_user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    user = USERS.get(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Intentional flaw: updates any field including role and is_admin
    user.update(payload)
    return {"status": "updated", "user": user}


# VULNERABILITY 5: Dynamic Query / Injection Indicator
@app.get("/api/search")
def search(q: str = Query("")):
    # Intentional flaw: dynamic string handling simulating raw SQL query failure
    if "'" in q or '"' in q:
        raise HTTPException(
            status_code=500,
            detail="sqlite3.OperationalError: unrecognized token: syntax error near " + q,
        )
    return {"query": q, "results": [p for p in PRODUCTS.values() if q.lower() in p["name"].lower()]}


@app.get("/health")
def health():
    return {"status": "ok", "app": "vending-api"}
