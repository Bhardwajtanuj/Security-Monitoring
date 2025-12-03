"""
Anomaly Detector Module
Detects suspicious activities and security anomalies in parsed logs.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Any
from collections import defaultdict
import logging

from utils.utils import validate_ip, is_private_ip, calculate_time_diff


class AnomalyDetector:
    """
    Detect security anomalies and suspicious activities in log data.
    Implements IP filtering, brute force detection, and traffic pattern analysis.
    """
    
    def __init__(self, 
                 blacklist: Optional[List[str]] = None,
                 whitelist: Optional[List[str]] = None,
                 failed_login_threshold: int = 5,
                 failed_login_window: int = 300,  # 5 minutes
                 request_rate_threshold: int = 100,
                 request_rate_window: int = 60):  # 1 minute
        """
        Initialize AnomalyDetector.
        
        Args:
            blacklist: List of blacklisted IP addresses
            whitelist: List of whitelisted IP addresses
            failed_login_threshold: Number of failed logins to trigger alert
            failed_login_window: Time window in seconds for failed login detection
            request_rate_threshold: Number of requests to trigger rate alert
            request_rate_window: Time window in seconds for request rate detection
        """
        self.blacklist = set(blacklist) if blacklist else set()
        self.whitelist = set(whitelist) if whitelist else set()
        self.failed_login_threshold = failed_login_threshold
        self.failed_login_window = failed_login_window
        self.request_rate_threshold = request_rate_threshold
        self.request_rate_window = request_rate_window
        self.logger = logging.getLogger('security_monitor.anomaly_detector')
        
        self.anomalies = []
        
    def add_to_blacklist(self, ip_address: str) -> None:
        """Add IP to blacklist."""
        if validate_ip(ip_address):
            self.blacklist.add(ip_address)
            self.logger.info(f"Added {ip_address} to blacklist")
    
    def add_to_whitelist(self, ip_address: str) -> None:
        """Add IP to whitelist."""
        if validate_ip(ip_address):
            self.whitelist.add(ip_address)
            self.logger.info(f"Added {ip_address} to whitelist")
    
    def is_blacklisted(self, ip_address: str) -> bool:
        """Check if IP is blacklisted."""
        return ip_address in self.blacklist
    
    def is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is whitelisted."""
        return ip_address in self.whitelist
    
    def analyze_logs(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze log entries for anomalies.
        
        Args:
            log_entries: List of parsed log entries
            
        Returns:
            List of detected anomalies
        """
        self.anomalies = []
        
        # Check blacklisted IPs
        self._detect_blacklisted_ips(log_entries)
        
        # Detect brute force attacks
        self._detect_brute_force(log_entries)
        
        # Detect high request rates
        self._detect_high_request_rate(log_entries)
        
        # Detect suspicious status codes
        self._detect_suspicious_status_codes(log_entries)
        
        # Detect unusual access patterns
        self._detect_unusual_patterns(log_entries)
        
        self.logger.info(f"Detected {len(self.anomalies)} anomalies")
        return self.anomalies
    
    def _detect_blacklisted_ips(self, log_entries: List[Dict[str, Any]]) -> None:
        """Detect access from blacklisted IPs."""
        blacklisted_access = defaultdict(list)
        
        for entry in log_entries:
            ip = entry.get('ip_address')
            if ip and self.is_blacklisted(ip) and not self.is_whitelisted(ip):
                blacklisted_access[ip].append(entry)
        
        for ip, entries in blacklisted_access.items():
            self.anomalies.append({
                'type': 'blacklisted_ip',
                'severity': 'high',
                'ip_address': ip,
                'count': len(entries),
                'description': f'Access from blacklisted IP: {ip}',
                'entries': entries,
                'timestamp': datetime.now()
            })
    
    def _detect_brute_force(self, log_entries: List[Dict[str, Any]]) -> None:
        """Detect brute force login attempts."""
        # Group failed logins by IP
        failed_logins = defaultdict(list)
        
        for entry in log_entries:
            if entry.get('event_type') == 'failed_login':
                ip = entry.get('ip_address')
                timestamp = entry.get('timestamp')
                if ip and timestamp:
                    failed_logins[ip].append(entry)
        
        # Check for brute force patterns
        for ip, entries in failed_logins.items():
            if self.is_whitelisted(ip):
                continue
                
            # Sort by timestamp
            sorted_entries = sorted(entries, key=lambda x: x['timestamp'] or datetime.min)
            
            # Check for threshold violations within time window
            for i, entry in enumerate(sorted_entries):
                window_start = entry['timestamp']
                window_end = window_start + timedelta(seconds=self.failed_login_window)
                
                # Count failures in window
                failures_in_window = [
                    e for e in sorted_entries[i:]
                    if e['timestamp'] and window_start <= e['timestamp'] <= window_end
                ]
                
                if len(failures_in_window) >= self.failed_login_threshold:
                    self.anomalies.append({
                        'type': 'brute_force',
                        'severity': 'critical',
                        'ip_address': ip,
                        'count': len(failures_in_window),
                        'description': f'Brute force attack detected from {ip}: {len(failures_in_window)} failed logins in {self.failed_login_window}s',
                        'entries': failures_in_window,
                        'timestamp': window_start,
                        'window_start': window_start,
                        'window_end': window_end
                    })
                    break  # Only report once per IP
    
    def _detect_high_request_rate(self, log_entries: List[Dict[str, Any]]) -> None:
        """Detect unusually high request rates."""
        # Group requests by IP
        requests_by_ip = defaultdict(list)
        
        for entry in log_entries:
            if entry.get('log_type') in ['apache', 'nginx']:
                ip = entry.get('ip_address')
                timestamp = entry.get('timestamp')
                if ip and timestamp:
                    requests_by_ip[ip].append(entry)
        
        # Check request rates
        for ip, entries in requests_by_ip.items():
            if self.is_whitelisted(ip):
                continue
                
            sorted_entries = sorted(entries, key=lambda x: x['timestamp'] or datetime.min)
            
            for i, entry in enumerate(sorted_entries):
                window_start = entry['timestamp']
                window_end = window_start + timedelta(seconds=self.request_rate_window)
                
                requests_in_window = [
                    e for e in sorted_entries[i:]
                    if e['timestamp'] and window_start <= e['timestamp'] <= window_end
                ]
                
                if len(requests_in_window) >= self.request_rate_threshold:
                    self.anomalies.append({
                        'type': 'high_request_rate',
                        'severity': 'medium',
                        'ip_address': ip,
                        'count': len(requests_in_window),
                        'description': f'High request rate from {ip}: {len(requests_in_window)} requests in {self.request_rate_window}s',
                        'entries': requests_in_window[:10],  # Limit entries
                        'timestamp': window_start,
                        'window_start': window_start,
                        'window_end': window_end
                    })
                    break
    
    def _detect_suspicious_status_codes(self, log_entries: List[Dict[str, Any]]) -> None:
        """Detect suspicious HTTP status codes."""
        suspicious_codes = {401, 403, 404, 500, 503}
        suspicious_by_ip = defaultdict(lambda: defaultdict(list))
        
        for entry in log_entries:
            status = entry.get('status_code')
            ip = entry.get('ip_address')
            
            if status in suspicious_codes and ip:
                if self.is_whitelisted(ip):
                    continue
                suspicious_by_ip[ip][status].append(entry)
        
        for ip, status_dict in suspicious_by_ip.items():
            for status, entries in status_dict.items():
                if len(entries) >= 10:  # Threshold for suspicious activity
                    severity = 'high' if status in [401, 403] else 'medium'
                    self.anomalies.append({
                        'type': 'suspicious_status_code',
                        'severity': severity,
                        'ip_address': ip,
                        'status_code': status,
                        'count': len(entries),
                        'description': f'Multiple {status} responses from {ip}: {len(entries)} occurrences',
                        'entries': entries[:5],  # Limit entries
                        'timestamp': datetime.now()
                    })
    
    def _detect_unusual_patterns(self, log_entries: List[Dict[str, Any]]) -> None:
        """Detect unusual access patterns."""
        # Detect access to sensitive paths
        sensitive_paths = ['/admin', '/wp-admin', '/.env', '/config', '/backup', '/.git']
        
        for entry in log_entries:
            url = entry.get('url', '')
            ip = entry.get('ip_address')
            
            if ip and self.is_whitelisted(ip):
                continue
            
            for sensitive_path in sensitive_paths:
                if sensitive_path in url.lower():
                    self.anomalies.append({
                        'type': 'sensitive_path_access',
                        'severity': 'high',
                        'ip_address': ip,
                        'url': url,
                        'description': f'Access to sensitive path from {ip}: {url}',
                        'entries': [entry],
                        'timestamp': entry.get('timestamp', datetime.now())
                    })
    
    def get_anomalies_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get anomalies filtered by severity.
        
        Args:
            severity: Severity level ('low', 'medium', 'high', 'critical')
            
        Returns:
            List of matching anomalies
        """
        return [a for a in self.anomalies if a.get('severity') == severity]
    
    def get_anomalies_by_type(self, anomaly_type: str) -> List[Dict[str, Any]]:
        """
        Get anomalies filtered by type.
        
        Args:
            anomaly_type: Type of anomaly
            
        Returns:
            List of matching anomalies
        """
        return [a for a in self.anomalies if a.get('type') == anomaly_type]
    
    def get_anomalies_by_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """
        Get all anomalies for a specific IP.
        
        Args:
            ip_address: IP address to filter
            
        Returns:
            List of matching anomalies
        """
        return [a for a in self.anomalies if a.get('ip_address') == ip_address]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about detected anomalies.
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_anomalies': len(self.anomalies),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'unique_ips': set()
        }
        
        for anomaly in self.anomalies:
            stats['by_severity'][anomaly.get('severity', 'unknown')] += 1
            stats['by_type'][anomaly.get('type', 'unknown')] += 1
            if anomaly.get('ip_address'):
                stats['unique_ips'].add(anomaly['ip_address'])
        
        stats['by_severity'] = dict(stats['by_severity'])
        stats['by_type'] = dict(stats['by_type'])
        stats['unique_ips'] = len(stats['unique_ips'])
        
        return stats
