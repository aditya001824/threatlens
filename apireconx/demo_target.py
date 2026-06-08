from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field


app = FastAPI(title="APIRECON-X Demo Target", version="0.1.0")


USERS = {
    "1": {"id": "1", "email": "alice@example.test", "role": "user", "api_token": "alice-secret-token"},
    "2": {"id": "2", "email": "bob@example.test", "role": "user", "api_token": "bob-secret-token"},
}

COUPONS: dict[str, int] = {}


class LoginRequest(BaseModel):
    username: str = "alice"
    password: str = "password"


class TransferRequest(BaseModel):
    sender: str = "1"
    receiver: str = "2"
    amount: int = Field(default=10)


class CouponRequest(BaseModel):
    user_id: str = "1"
    code: str = "SAVE10"
    discount: int = 10


class ProfileUpdate(BaseModel):
    email: str = "alice@example.test"
    role: str | None = None
    is_admin: bool | None = None


def _principal(authorization: str | None) -> dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.replace("Bearer ", "")
    if token == "user-1":
        return USERS["1"]
    if token == "user-2":
        return USERS["2"]
    if token == "admin":
        return {"id": "0", "email": "admin@example.test", "role": "admin"}
    raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/login", tags=["auth"])
def login(payload: LoginRequest) -> dict[str, Any]:
    if payload.username == "admin":
        return {"access_token": "admin", "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
    return {"access_token": "user-1", "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}


@app.get("/users/{user_id}", tags=["users"])
def get_user(user_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _principal(authorization)
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.patch("/users/{user_id}", tags=["users"])
def update_user(user_id: str, payload: ProfileUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _principal(authorization)
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    update = payload.model_dump(exclude_none=True)
    user.update(update)
    return user


@app.get("/admin/users", tags=["admin"])
def admin_users(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    # Intentionally flawed for local scanner validation: any valid token can reach this.
    _principal(authorization)
    return list(USERS.values())


@app.post("/transfer", tags=["payments"])
def transfer(payload: TransferRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _principal(authorization)
    # Intentionally flawed: accepts negative and huge amounts.
    return {"status": "queued", "sender": payload.sender, "receiver": payload.receiver, "amount": payload.amount}


@app.post("/coupon/apply", tags=["commerce"])
def apply_coupon(payload: CouponRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _principal(authorization)
    COUPONS[payload.user_id] = COUPONS.get(payload.user_id, 0) + payload.discount
    return {"user_id": payload.user_id, "total_discount": COUPONS[payload.user_id], "applied": True}


@app.post("/webhook/test", tags=["integrations"])
def webhook_test(callback_url: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _principal(authorization)
    return {"accepted": True, "callback_url": callback_url}


def custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
    }
    schema["security"] = [{"bearerAuth": []}]
    for method_spec in schema.get("paths", {}).get("/login", {}).values():
        if isinstance(method_spec, dict):
            method_spec["security"] = []
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi
