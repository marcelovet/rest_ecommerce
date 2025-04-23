from fastapi import APIRouter

from .endpoints import auth

user_router = APIRouter(prefix="/users", tags=["users"])
api_router = APIRouter()
api_router.include_router(auth.auth_router)
