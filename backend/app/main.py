from celery import Celery
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings as st

app = FastAPI(
    title="Ecommerce API",
    version=st.API_VERSION,
    openapi_url=f"{st.API_VERSION_PREFIX}/openapi.json",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: change to only allow frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

celery = Celery(
    __name__,
    broker=st.REDIS_URL,
    backend=st.REDIS_URL,
)


@app.get("/")
async def root():
    return {"message": "FastAPI Ecommerce backend"}


@celery.task
def divide(x, y):
    import time

    time.sleep(5)
    return x / y
