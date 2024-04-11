from collections import defaultdict
from datetime import datetime

def calculate_average_heart_rate(data):
    # Initialize a dictionary to store heart rates for each day
    daily_heart_rates = defaultdict(list)

    # Iterate over the data and store heart rates for each day
    for entry in data:
        # Parse the starttime string to get the date
        starttime = datetime.strptime(entry['starttime'], '%Y-%m-%d %H:%M:%S')
        # Extract the date
        date = starttime.day
        # Add the heart rate to the list for the corresponding day
        daily_heart_rates[date].append(entry['heart_rate'])

    # Compute the average heart rate for each day
    average_heart_rates = {}
    for date, heart_rates in daily_heart_rates.items():
        average_heart_rates[date] = sum(heart_rates) / len(heart_rates)

    return average_heart_rates

# Example usage:
data = [
    {'heart_rate': 98.0, 'starttime': '2024-04-10 20:00:59'},
    {'heart_rate': 112.0, 'starttime': '2024-04-10 20:01:59'},
    {'heart_rate': 84.0, 'starttime': '2024-04-11 07:17:59'},
    {'heart_rate': 94.0, 'starttime': '2024-04-11 07:18:59'},
    {'heart_rate': 112.0, 'starttime': '2024-04-11 07:19:59'},
    {'heart_rate': 116.0, 'starttime': '2024-04-11 07:20:59'},
    {'heart_rate': 95.0, 'starttime': '2024-04-11 07:21:59'},
    {'heart_rate': 107.0, 'starttime': '2024-04-11 07:22:59'},
    {'heart_rate': 94.0, 'starttime': '2024-04-11 07:23:59'},
    {'heart_rate': 69.0, 'starttime': '2024-04-11 07:24:59'},
    {'heart_rate': 72.0, 'starttime': '2024-04-11 07:25:59'},
    {'heart_rate': 76.0, 'starttime': '2024-04-11 07:26:59'},
    {'heart_rate': 79.0, 'starttime': '2024-04-11 07:27:59'},
    {'heart_rate': 77.0, 'starttime': '2024-04-11 07:28:59'},
    {'heart_rate': 73.0, 'starttime': '2024-04-11 07:29:59'},
    {'heart_rate': 95.0, 'starttime': '2024-04-11 07:34:59'},
    {'heart_rate': 103.0, 'starttime': '2024-04-11 07:35:59'}
]

average_heart_rates = calculate_average_heart_rate(data)
print(average_heart_rates)
for date, average_heart_rate in average_heart_rates.items():
    print(f'{date}: {average_heart_rate}')
