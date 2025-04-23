from celery import shared_task


@shared_task(
    bind=True,
    # autoretry_for=(ConnectionError, SMTPException),
    retry_kwargs={"max_retries": 5},
    retry_backoff=5,
    retry_jitter=True,
)
def send_verification_email(self, msg):
    return True
