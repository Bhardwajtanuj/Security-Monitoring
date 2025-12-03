# Security Log Monitor - Quick Reference Guide

## 🚀 Quick Start

```bash
# Navigate to project directory
cd "d:\resume\resume projects\security_log_monitor"

# Install dependencies
pip install -r requirements.txt

# Run the system
python main.py
```

## 📋 Common Commands

```bash
# Basic run (generates HTML report)
python main.py

# Skip alerts (for testing)
python main.py --no-alerts

# Generate JSON report
python main.py --format json

# Use custom config
python main.py -c path/to/config.json

# Verbose output
python main.py -v

# Run tests
python -m unittest discover tests/
```

## 📁 Important Files

| File | Purpose |
|------|---------|
| `main.py` | Main entry point |
| `config/config.json` | Main configuration |
| `config/blacklist.txt` | Blacklisted IPs |
| `config/whitelist.txt` | Whitelisted IPs |
| `reports/` | Generated reports |
| `sample_logs/` | Sample log files |

## ⚙️ Configuration Quick Tips

### Enable Email Alerts
Edit `config/config.json`:
```json
"email": {
  "enabled": true,
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "sender_email": "your-email@gmail.com",
  "sender_password": "your-app-password",
  "recipients": ["admin@example.com"]
}
```

### Enable Webhook (Slack)
```json
"webhook": {
  "enabled": true,
  "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
}
```

### Adjust Detection Thresholds
```json
"anomaly_detection": {
  "failed_login_threshold": 5,        // Number of failures
  "failed_login_window_seconds": 300, // Time window (5 min)
  "request_rate_threshold": 100,      // Requests per window
  "request_rate_window_seconds": 60   // Time window (1 min)
}
```

## 🎯 Expected Results with Sample Data

When you run the system with the included sample logs, you should see:

- **Total Entries**: ~89 log entries
- **Unique IPs**: ~15 different IP addresses
- **Anomalies Detected**: 12+ security events
- **Severity Breakdown**:
  - Critical: 2-3 (Brute force attacks)
  - High: 6-8 (Blacklisted IPs, sensitive paths)
  - Medium: 2-4 (Suspicious status codes)

## 📊 Report Location

After running, find your report at:
```
reports/security_report_YYYYMMDD_HHMMSS.html
```

Open it in any web browser to view the beautiful, interactive security report!

## 🔧 Customization

### Add Your Own Logs
1. Place log files in `sample_logs/` or any directory
2. Edit `config/config.json` to add log source:
```json
{
  "name": "my_custom_log",
  "path": "path/to/your/logfile.log",
  "type": "apache",  // or "nginx", "ssh", "auto"
  "enabled": true
}
```

### Add IPs to Blacklist
Edit `config/blacklist.txt`:
```
# Add one IP per line
192.168.1.100
203.0.113.45
```

## 🐛 Troubleshooting

**No anomalies detected?**
- Check that log files exist and are readable
- Verify blacklist/whitelist configuration
- Lower detection thresholds in config

**Email alerts not working?**
- Use app-specific password for Gmail
- Check SMTP settings
- Verify firewall allows SMTP traffic

**Import errors?**
- Install dependencies: `pip install -r requirements.txt`
- Ensure Python 3.7+ is installed

## 📚 Project Structure

```
security_log_monitor/
├── core/              # Core modules (4 files)
├── utils/             # Utilities
├── config/            # Configuration files
├── sample_logs/       # Sample data (3 files)
├── reports/           # Generated reports
├── tests/             # Unit tests
├── main.py            # Entry point
├── requirements.txt   # Dependencies
└── README.md          # Full documentation
```

## ✨ Key Features

✅ Multi-format log parsing (Apache, Nginx, SSH, System)  
✅ Brute force attack detection  
✅ IP blacklist/whitelist filtering  
✅ High request rate monitoring  
✅ Sensitive path access detection  
✅ Email & webhook alerts  
✅ Beautiful HTML reports  
✅ JSON export  
✅ CLI interface  
✅ Comprehensive documentation  

---

**Ready to secure your infrastructure!** 🛡️
