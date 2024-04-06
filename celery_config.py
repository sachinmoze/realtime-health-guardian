# celery_config.py

broker_url = 'redis://localhost:6379/0'
result_backend = 'redis://localhost:6379/0'


# celery_config.py

from celery.schedules import crontab

beat_schedule = {
    'fetch-heart-rate-every-5-minutes': {
        'task': 'tasks.fetch_and_store_heart_rate',
        'schedule': crontab(minute='*/5'),
    },
}
