# tasks.py

from celery import shared_task
from datetime import datetime
#from your_module import get_heart_rate_data

def get_heart_rate_data():
    # Your function to fetch and store heart rate data
    return datetime.now()

@shared_task
def fetch_and_store_heart_rate():
    # Call your function to fetch and store heart rate data
    date=get_heart_rate_data()
    print(f'Fetched and stored heart rate data at {date}')
