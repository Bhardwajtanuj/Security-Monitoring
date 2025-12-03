# 🛡️ Security Log Monitoring & Alert Automation System

A production-ready Python-based security log monitoring system that automatically detects anomalies, suspicious activities, and potential security threats in server logs.

## ✨ Features

### 🔍 Multi-Format Log Parsing
- **Apache Access Logs** - Parse HTTP access logs with IP, status codes, and URLs
- **Nginx Access Logs** - Support for Nginx log format
- **SSH Authentication Logs** - Track login attempts and authentication events
- **System Logs** - Parse system security logs
- **Auto-Detection** - Automatically detect log format

### 🚨 Advanced Anomaly Detection
- **IP Filtering** - Blacklist/whitelist based filtering
- **Brute Force Detection** - Identify repeated failed login attempts
- **High Request Rate Detection** - Detect potential DDoS or scraping attempts
- **Suspicious Status Codes** - Flag unusual HTTP error patterns
- **Sensitive Path Access** - Detect access to admin panels, config files, etc.

### 📧 Alert Management
- **Email Alerts** - SMTP-based email notifications
- **Webhook Integration** - Slack/Discord/custom webhook support
- **Alert Throttling** - Prevent alert flooding
- **Severity Levels** - Critical, High, Medium, Low classifications

### 📊 Comprehensive Reporting
- **Beautiful HTML Reports** - Professional, responsive HTML reports
- **JSON Export** - Machine-readable JSON format
- **Statistics Dashboard** - Visual breakdown of threats and activities
- **Anomaly Details** - Detailed information for each detected threat

## 🚀 Quick Start

### Installation

1. **Clone or download the project**
```bash
cd security_log_monitor
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

### Basic Usage

Run with default configuration:
```bash
python main.py
```

This will:
1. Parse all configured log files
2. Detect security anomalies
3. Generate an HTML report in the `reports/` directory

### Command-Line Options

```bash
# Use custom configuration file
python main.py -c path/to/config.json

# Skip sending alerts
python main.py --no-alerts

# Generate JSON report instead of HTML
python main.py --format json

# Enable verbose logging
python main.py -v
```

## 📁 Project Structure

```
security_log_monitor/
├── core/
│   ├── __init__.py
│   ├── log_parser.py          # Log parsing engine
│   ├── anomaly_detector.py    # Anomaly detection logic
│   ├── alert_manager.py       # Alert/notification system
│   └── report_generator.py    # Report generation
├── utils/
│   ├── __init__.py
│   └── utils.py               # Utility functions
├── config/
│   ├── config.json            # Main configuration
│   ├── blacklist.txt          # Blacklisted IPs
│   └── whitelist.txt          # Whitelisted IPs
├── sample_logs/
│   ├── apache_access.log      # Sample Apache logs
│   ├── ssh_auth.log           # Sample SSH logs
│   └── nginx_access.log       # Sample Nginx logs
├── reports/                   # Generated reports
├── tests/                     # Unit tests
├── main.py                    # Main entry point
└── requirements.txt           # Python dependencies
```

## ⚙️ Configuration

Edit `config/config.json` to customize the system:

### Log Sources
```json
{
  "log_sources": [
    {
      "name": "apache_access",
      "path": "sample_logs/apache_access.log",
      "type": "apache",
      "enabled": true
    }
  ]
}
```

### Anomaly Detection Settings
```json
{
  "anomaly_detection": {
    "failed_login_threshold": 5,
    "failed_login_window_seconds": 300,
    "request_rate_threshold": 100,
    "request_rate_window_seconds": 60
  }
}
```

### Email Alerts
```json
{
  "alerting": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "sender_email": "security@example.com",
      "sender_password": "your_password",
      "recipients": ["admin@example.com"]
    }
  }
}
```

### Webhook Alerts (Slack/Discord)
```json
{
  "alerting": {
    "webhook": {
      "enabled": true,
      "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    }
  }
}
```

## 🎯 Use Cases

### 1. Monitor Server Access Logs
Automatically detect suspicious access patterns, brute force attempts, and unauthorized access.

### 2. SSH Security Monitoring
Track failed SSH login attempts and identify potential brute force attacks.

### 3. Web Application Security
Monitor for SQL injection attempts, path traversal, and sensitive file access.

### 4. Compliance & Auditing
Generate detailed security reports for compliance requirements.

## 🔧 Customization

### Adding Custom Log Formats

Edit `core/log_parser.py` to add new log format patterns:

```python
CUSTOM_PATTERN = r'your_regex_pattern'

def _parse_custom(self, line: str, line_num: int):
    # Your parsing logic
    pass
```

### Custom Anomaly Detection Rules

Extend `core/anomaly_detector.py`:

```python
def _detect_custom_anomaly(self, log_entries):
    # Your detection logic
    pass
```

## 📊 Sample Output

### Console Summary
```
============================================================
SECURITY MONITORING SUMMARY
============================================================

Log Statistics:
  Total Entries: 1,234
  Unique IPs: 45

Anomaly Statistics:
  Total Anomalies: 12
  Affected IPs: 8

Severity Breakdown:
  CRITICAL: 3
  HIGH: 5
  MEDIUM: 4

Anomaly Types:
  Brute Force: 3
  Blacklisted IP: 2
  Sensitive Path Access: 4
  High Request Rate: 3
```

### HTML Report
Beautiful, responsive HTML reports with:
- Executive summary dashboard
- Detailed anomaly breakdown
- Color-coded severity indicators
- Statistics and charts

## 🧪 Testing

Run the system with sample logs:
```bash
python main.py
```

The sample logs include:
- ✅ Normal traffic patterns
- ⚠️ Brute force attempts
- 🚫 Blacklisted IP access
- 🔍 Sensitive path probing
- 📈 High request rates

## 📝 Requirements

- Python 3.7+
- requests library (for webhook alerts)

## 🔒 Security Best Practices

1. **Protect Configuration Files** - Keep credentials secure
2. **Regular Updates** - Update blacklists regularly
3. **Monitor Alerts** - Review critical alerts immediately
4. **Backup Reports** - Archive reports for compliance
5. **Test Regularly** - Validate detection rules with test data

## 🎓 Technical Details

### Supported Log Formats

| Format | Pattern | Fields Extracted |
|--------|---------|------------------|
| Apache | Common Log Format | IP, timestamp, method, URL, status, size |
| Nginx | Standard access log | IP, timestamp, method, URL, status, size |
| SSH | Auth log format | IP, timestamp, event type, user |
| System | Syslog format | Timestamp, level, message, IP (if present) |

### Detection Algorithms

- **Brute Force**: Sliding window algorithm tracking failed attempts
- **Rate Limiting**: Time-based request counting per IP
- **Pattern Matching**: Regex-based detection of suspicious patterns
- **Blacklist Checking**: O(1) hash-based IP lookup

## 🤝 Contributing

This is a portfolio/resume project demonstrating:
- Clean, modular Python architecture
- Security-focused development
- Production-ready code quality
- Comprehensive documentation

## 📄 License

This project is created for educational and portfolio purposes.

## 👤 Author

Created as part of a security automation portfolio project.

---

**⚡ Ready to secure your infrastructure? Run `python main.py` to get started!**
