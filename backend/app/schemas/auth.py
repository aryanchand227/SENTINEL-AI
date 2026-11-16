"""
SENTINEL AI — Authentication API Schemas.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    role: str
    display_name: str


class UserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    email: str
    display_name: str
    role: str
    is_active: bool
