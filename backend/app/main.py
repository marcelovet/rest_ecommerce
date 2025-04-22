from app.core.app_factory import create_app

app = create_app()
celery = app.celery_app
