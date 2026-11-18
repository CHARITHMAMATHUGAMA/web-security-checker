# Web Security Checker

A small Python tool that performs basic, passive checks on a website's HTTPS security configuration.

## Features

- Checks whether the final URL uses HTTPS
- Checks for common HTTP security headers
- Checks cookie security attributes: Secure, HttpOnly, and SameSite
- Shows basic severity levels and recommendations
- Saves the results to `scan_report.txt`

## Requirements

- Python 3
- certifi

Install certifi:

```powershell
py -m pip install certifi