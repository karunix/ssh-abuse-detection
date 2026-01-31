# ssh-abuse-detection
# SSH Abuse Detection

A lightweight Python tool for detecting SSH brute-force attacks from Linux authentication logs.

This project parses OpenSSH auth logs and identifies suspicious patterns such as repeated failed login attempts from a single source within a short time window.

## Features
- Parses standard Linux `auth.log` / `secure` files
- Detects SSH brute-force attempts
- Minimal dependencies
- Designed for server-side security monitoring

## Requirements
- Python 3.10+
- python-dateutil

## Installation

```bash
git clone git@github.com:karunix/ssh-abuse-detection.git
cd ssh-abuse-detection
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Usage
python main.py
Sample output:
    
    [!] Possible brute-force from 1.2.3.4 (5 attempts in 5 minutes)
    Project Structure
    ssh-abuse-detection/
    ├── main.py
    ├── requirements.txt
    ├── samples/
    │   └── auth.log
    └── ssh_abuse/
    ├── parser.py
    ├── detectors.py
    └── models.py
    Motivation
    This project was built to demonstrate practical log analysis and attack detection techniques commonly used in Linux server security and SOC environments.
    
    License
    MIT
    
    
