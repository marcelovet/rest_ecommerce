from celery import Celery

from app.core.config import settings


def create_celery():
    celery_app = Celery("ecommerce_fastapi")
    celery_app.config_from_object(settings, namespace="CELERY")  # type: ignore[call-arg]
    packages = [
        "services",
    ]
    celery_app.autodiscover_tasks(
        packages=["app." + package for package in packages],
    )

    return celery_app
