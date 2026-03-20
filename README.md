# Email Threat Detector

A beginner-friendly cybersecurity project that analyzes suspicious email content by checking:
- malicious or suspicious links in email text
- risky attachment names
- simple file-based indicators
- an overall risk score and verdict

This project was built as an educational prototype to understand phishing detection and suspicious attachment analysis using rule-based methods.

---

## Features

- Extracts URLs from pasted email content
- Detects suspicious URL indicators such as:
  - IP-based URLs
  - long URLs
  - multiple subdomains
  - suspicious keywords
  - punycode/lookalike domains
  - URL shorteners
  - HTTP instead of HTTPS
- Detects suspicious attachment indicators such as:
  - dangerous file extensions
  - macro-enabled Office files
  - archive files
  - double extensions
  - suspicious words in file names
- Generates SHA256 hash for uploaded files
- Produces:
  - URL analysis
  - attachment analysis
  - final score
  - final verdict

---

## Tech Stack

- Python
- Flask
- HTML/CSS
- tldextract

---

## Project Structure

```text
email_threat_detector/
├── analyzer/
│   ├── __init__.py
│   ├── url_analyzer.py
│   ├── file_analyzer.py
│   └── scorer.py
├── templates/
│   └── index.html
├── uploads/
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
---

# How It Works
1. URL Analysis

The application extracts URLs from email text and checks for suspicious indicators such as:

IP address usage

suspicious keywords

unusually long URLs

many subdomains

shortened links

punycode domains

insecure HTTP links

2. Attachment Analysis

The uploaded file name is checked for:

dangerous extensions like .exe, .js, .bat

macro-enabled Office extensions like .docm, .xlsm

archive formats like .zip, .rar

double extensions like invoice.pdf.exe

suspicious keywords in the filename

3. Risk Scoring

The application combines the findings from URLs and attachments and generates:

total score

reasons for detection

final verdict

# Installation
1. Clone the repository
git clone <your-repository-url>
cd email_threat_detector
2. Create a virtual environment
python3 -m venv .venv
3. Activate the virtual environment
macOS / Linux
source .venv/bin/activate
4. Install dependencies
python3 -m pip install -r requirements.txt
5. Run the application
python3 app.py
6. Open in browser
http://127.0.0.1:5000

# Example Test Email
Subject: Urgent Account Verification Required

Dear Customer,

We detected unusual activity on your account and have temporarily limited access for your protection.

To restore full access, please verify your account immediately using the secure link below:

http://45.67.123.10/secure-login/verify-account

Failure to complete verification within 24 hours may result in permanent suspension of your account.

Thank you,
Security Support Team
Example suspicious attachment name
payment_invoice.docm

# Sample Detection Indicators
##URL indicators

Uses IP address instead of domain

Contains suspicious keywords such as login, verify, account

Uses HTTP instead of HTTPS

Very long URL

Contains multiple subdomains

Uses URL shortener

##File indicators

Dangerous extension detected

Macro-enabled Office file detected

Possible double extension detected

Suspicious word in filename

#Current Limitations

This project is a beginner-friendly prototype and has several limitations:

does not execute or sandbox files

does not inspect real Office macros

does not deeply parse PDFs

does not analyze email headers

does not integrate with live threat intelligence APIs

may generate false positives

should not be used as a production-grade security solution

#Future Improvements

Possible improvements for future versions:

MIME type validation

PDF link extraction

Office macro inspection

email header analysis

SPF / DKIM / DMARC checks

SQLite scan history

REST API support

Docker support

VirusTotal or threat intelligence API integration

improved UI and reporting dashboard

#Learning Goals of This Project

This project was built to practice:

Python project structure

Flask web development

cybersecurity rule-based detection

file hashing using SHA256

URL parsing and analysis

basic threat scoring logic

#Disclaimer

This project is intended for educational purposes only.
It is a rule-based prototype for learning cybersecurity concepts and does not guarantee detection of real malware or phishing attacks.

#Author

L.Praveena Ishadi
Undergraduate, Faculty of Information Technology
University of Moratuwa


