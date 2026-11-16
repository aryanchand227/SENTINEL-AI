"""SENTINEL AI — API v1 router aggregation."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.routes import auth, conversations, health, providers, queries, reports

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(conversations.router, prefix="", tags=["conversations"])
api_router.include_router(queries.router, prefix="/queries", tags=["queries"])
api_router.include_router(providers.router, prefix="/providers", tags=["providers"])
api_router.include_router(reports.router, prefix="", tags=["reports"])
