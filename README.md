# HoneyTrap-DC01

Python honeypot simulating SSH, FTP and HTTP services to log 
unauthorised connection attempts. Built for a home lab / learning project.

## What it does

Listens on ports 22, 21 and 8080 simultaneously. Sends real-looking
service banners so scanners think they've found live infrastructure.
Every hit gets logged as JSON with geolocation, a threat level, and
attack classification. Flask dashboard at localhost:5000.

Started this because I wanted something I could actually run locally
and see real scanner traffic - most tutorials just show you the code
without showing what it catches.

## Stack
- Python 3.14, Flask, Requests
- ip-api.com for geolocation (free, no key needed)

## Run it

pip install -r requirements.txt
python honeypot.py
python dashboard.py

Dashboard : http://localhost:5000

## Structure

config.py      settings
honeypot.py    listener engine
dashboard.py   flask frontend
