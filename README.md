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
```bash
python main.py --log /var/log/auth.log

## Optional Arguments:
--threshold   Number of failed attempts (default: 5)
--window      Time window in minutes (default: 5)
    
    ## About the Author
    
    Built by a Linux systems and security practitioner with over 7 years of experience operating and securing production Ubuntu servers, including monitoring and maintaining online trading platforms.
    
