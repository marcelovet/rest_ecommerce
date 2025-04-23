from fastapi import FastAPI

from .celery_app import create_celery
from .config import settings as st


def create_app() -> FastAPI:
    app = FastAPI(
        title="Ecommerce API",
        version=st.API_VERSION,
        openapi_url=f"{st.API_VERSION_PREFIX}/openapi.json",
    )
    app.celery_app = create_celery()  # type: ignore[attr-defined]

    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # TODO: change to only allow frontend
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from app.api.router import api_router

    app.include_router(api_router, prefix=st.API_VERSION_PREFIX)

    @app.get("/")
    async def root():
        return {"message": "FastAPI Ecommerce backend"}

    return app
