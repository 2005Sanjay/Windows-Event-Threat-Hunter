# Windows Event Threat Hunter

A Blue Team cybersecurity project developed in Python for monitoring and analyzing Windows Security Event Logs.

## Features

- Read Windows Security Event Logs
- Event Statistics Analysis
- Process Creation Monitoring
- Suspicious Process Detection
- Threat Report Generation
- Git Version Control Integration

## Technologies Used

- Python
- pywin32
- pandas
- matplotlib
- Git
- GitHub

## Project Structure

```text
Windows-Event-Threat-Hunter
│
├── src
│   ├── log_reader.py
│   ├── statistics.py
│   ├── process_monitor.py
│   ├── suspicious_process_detector.py
│   └── report_generator.py
│
├── reports
├── logs
├── screenshots
├── requirements.txt
└── README.md
```

## Sample Threat Report

```text
THREAT REPORT
========================================

Top Events:
5379 - Credential Manager Access
4798 - Group Enumeration
4624 - Successful Login

Risk Level: LOW
Recommendation: Continue Monitoring
```

## Author

Sanjay

## Version

v1.0