from celery import Celery
from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "netdog",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    worker_prefetch_multiplier=1,
)

# Import tasks to register them with Celery
# This must happen after celery_app is created
from app import tasks  # noqa: E402, F401
