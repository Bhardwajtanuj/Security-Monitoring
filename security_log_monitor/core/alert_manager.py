"""
Alert Manager Module
Manages alert generation and notification delivery.
"""

import smtplib
import json
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
import requests


class AlertManager:
    """
    Manage security alerts and notifications.
    Supports email and webhook notifications with throttling.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AlertManager.
        
        Args:
            config: Configuration dictionary with email/webhook settings
        """
        self.config = config or {}
        self.logger = logging.getLogger('security_monitor.alert_manager')
        
        # Email configuration
        self.email_enabled = self.config.get('email', {}).get('enabled', False)
        self.smtp_server = self.config.get('email', {}).get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = self.config.get('email', {}).get('smtp_port', 587)
        self.sender_email = self.config.get('email', {}).get('sender_email', '')
        self.sender_password = self.config.get('email', {}).get('sender_password', '')
        self.recipient_emails = self.config.get('email', {}).get('recipients', [])
        
        # Webhook configuration
        self.webhook_enabled = self.config.get('webhook', {}).get('enabled', False)
        self.webhook_url = self.config.get('webhook', {}).get('url', '')
        
        # Throttling configuration
        self.throttle_enabled = self.config.get('throttling', {}).get('enabled', True)
        self.throttle_window = self.config.get('throttling', {}).get('window_seconds', 3600)  # 1 hour
        self.throttle_max_alerts = self.config.get('throttling', {}).get('max_alerts', 10)
        
        # Alert tracking
        self.sent_alerts = []
        self.alert_history = defaultdict(list)
        
    def send_alert(self, anomaly: Dict[str, Any]) -> bool:
        """
        Send alert for detected anomaly.
        
        Args:
            anomaly: Anomaly dictionary
            
        Returns:
            True if alert sent successfully
        """
        # Check throttling
        if self.throttle_enabled and self._is_throttled(anomaly):
            self.logger.info(f"Alert throttled for {anomaly.get('type')}")
            return False
        
        alert_data = self._create_alert_message(anomaly)
        success = False
        
        # Send email alert
        if self.email_enabled:
            success = self._send_email_alert(alert_data) or success
        
        # Send webhook alert
        if self.webhook_enabled:
            success = self._send_webhook_alert(alert_data) or success
        
        if success:
            self._track_alert(anomaly)
            self.sent_alerts.append({
                'anomaly': anomaly,
                'timestamp': datetime.now(),
                'alert_data': alert_data
            })
        
        return success
    
    def send_batch_alerts(self, anomalies: List[Dict[str, Any]]) -> int:
        """
        Send alerts for multiple anomalies.
        
        Args:
            anomalies: List of anomaly dictionaries
            
        Returns:
            Number of alerts sent successfully
        """
        sent_count = 0
        
        for anomaly in anomalies:
            if self.send_alert(anomaly):
                sent_count += 1
        
        self.logger.info(f"Sent {sent_count}/{len(anomalies)} alerts")
        return sent_count
    
    def send_summary_alert(self, anomalies: List[Dict[str, Any]], 
                          stats: Dict[str, Any]) -> bool:
        """
        Send summary alert with statistics.
        
        Args:
            anomalies: List of anomalies
            stats: Statistics dictionary
            
        Returns:
            True if sent successfully
        """
        subject = f"Security Alert Summary - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # Create summary message
        message = self._create_summary_message(anomalies, stats)
        
        alert_data = {
            'subject': subject,
            'message': message,
            'severity': 'info',
            'anomaly_count': len(anomalies),
            'stats': stats
        }
        
        success = False
        
        if self.email_enabled:
            success = self._send_email_alert(alert_data) or success
        
        if self.webhook_enabled:
            success = self._send_webhook_alert(alert_data) or success
        
        return success
    
    def _create_alert_message(self, anomaly: Dict[str, Any]) -> Dict[str, Any]:
        """Create formatted alert message."""
        severity = anomaly.get('severity', 'medium').upper()
        anomaly_type = anomaly.get('type', 'unknown').replace('_', ' ').title()
        ip = anomaly.get('ip_address', 'Unknown')
        description = anomaly.get('description', 'No description')
        count = anomaly.get('count', 0)
        
        subject = f"[{severity}] Security Alert: {anomaly_type}"
        
        message = f"""
Security Alert Detected
=======================

Severity: {severity}
Type: {anomaly_type}
IP Address: {ip}
Count: {count}

Description:
{description}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---
This is an automated alert from the Security Log Monitoring System.
"""
        
        return {
            'subject': subject,
            'message': message,
            'severity': anomaly.get('severity'),
            'anomaly': anomaly
        }
    
    def _create_summary_message(self, anomalies: List[Dict[str, Any]], 
                               stats: Dict[str, Any]) -> str:
        """Create summary message."""
        message = f"""
Security Monitoring Summary
===========================

Total Anomalies Detected: {stats.get('total_anomalies', 0)}
Unique IPs Involved: {stats.get('unique_ips', 0)}

Severity Breakdown:
"""
        
        for severity, count in stats.get('by_severity', {}).items():
            message += f"  - {severity.upper()}: {count}\n"
        
        message += "\nAnomaly Types:\n"
        for atype, count in stats.get('by_type', {}).items():
            message += f"  - {atype.replace('_', ' ').title()}: {count}\n"
        
        message += f"\nReport Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += "\n---\nThis is an automated summary from the Security Log Monitoring System.\n"
        
        return message
    
    def _send_email_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send email alert."""
        if not self.recipient_emails:
            self.logger.warning("No recipient emails configured")
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipient_emails)
            msg['Subject'] = alert_data['subject']
            
            msg.attach(MIMEText(alert_data['message'], 'plain'))
            
            # Connect to SMTP server
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.sender_password:
                    server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent: {alert_data['subject']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _send_webhook_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send webhook alert."""
        if not self.webhook_url:
            self.logger.warning("No webhook URL configured")
            return False
        
        try:
            payload = {
                'text': alert_data['subject'],
                'severity': alert_data.get('severity', 'info'),
                'message': alert_data['message'],
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook alert sent: {alert_data['subject']}")
                return True
            else:
                self.logger.error(f"Webhook returned status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    def _is_throttled(self, anomaly: Dict[str, Any]) -> bool:
        """Check if alert should be throttled."""
        anomaly_key = f"{anomaly.get('type')}_{anomaly.get('ip_address')}"
        now = datetime.now()
        
        # Clean old alerts from history
        self.alert_history[anomaly_key] = [
            ts for ts in self.alert_history[anomaly_key]
            if (now - ts).total_seconds() < self.throttle_window
        ]
        
        # Check if threshold exceeded
        if len(self.alert_history[anomaly_key]) >= self.throttle_max_alerts:
            return True
        
        return False
    
    def _track_alert(self, anomaly: Dict[str, Any]) -> None:
        """Track sent alert for throttling."""
        anomaly_key = f"{anomaly.get('type')}_{anomaly.get('ip_address')}"
        self.alert_history[anomaly_key].append(datetime.now())
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get statistics about sent alerts."""
        return {
            'total_alerts_sent': len(self.sent_alerts),
            'alerts_by_severity': self._count_by_field('severity'),
            'alerts_by_type': self._count_by_field('type')
        }
    
    def _count_by_field(self, field: str) -> Dict[str, int]:
        """Count alerts by field."""
        counts = defaultdict(int)
        for alert in self.sent_alerts:
            value = alert['anomaly'].get(field, 'unknown')
            counts[value] += 1
        return dict(counts)
