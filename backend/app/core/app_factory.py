from fastapi import FastAPI


def create_app() -> FastAPI:
    from contextlib import asynccontextmanager

    from app.security import IPSecurityManager
    from app.services.jwt_service.token_utils import TokenLogger
    from app.services.jwt_service.token_utils import TokenSecurityMiddleware

    from .celery_app import create_celery
    from .config import settings as st

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        TokenLogger.initialize(
            max_batch_size=getattr(st, "TOKEN_LOG_BATCH_SIZE", 10),
            flush_interval=getattr(st, "TOKEN_LOG_FLUSH_INTERVAL", 5.0),
            start_background_task=True,
        )

        await IPSecurityManager.initialize(
            redis_url=st.REDIS_URL,
            geo_city_db_path=st.GEOIP_CITY_DB_PATH,
            geo_asn_db_path=st.GEOIP_ASN_DB_PATH,
            api_keys={
                "abuseipdb": st.ABUSEIPDB_API_KEY,
            },
        )

        yield

        await TokenLogger.shutdown()
        await IPSecurityManager.shutdown()

    app = FastAPI(
        title="Ecommerce API",
        version=st.API_VERSION,
        openapi_url=f"{st.API_VERSION_PREFIX}/openapi.json",
        lifespan=lifespan,
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
    app.add_middleware(
        TokenSecurityMiddleware,
        token_endpoints_io=None,
        token_endpoints_i=None,
        token_endpoints_o=None,
        excluded_paths=None,
    )

    from app.api.router import api_router

    app.include_router(api_router, prefix=st.API_VERSION_PREFIX)

    @app.get("/")
    async def root():
        return {"message": "FastAPI Ecommerce backend"}

    return app
