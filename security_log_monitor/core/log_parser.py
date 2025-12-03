"""
Log Parser Module
Parses various log formats and extracts security-relevant information.
"""

import re
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path
import logging

from utils.utils import validate_ip, parse_timestamp


class LogParser:
    """
    Parse security logs from various sources and formats.
    Supports Apache, Nginx, SSH, and system logs.
    """
    
    # Log format patterns
    APACHE_PATTERN = r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<url>[^\s]+) HTTP/[\d.]+" (?P<status>\d+) (?P<size>\d+|-)'
    NGINX_PATTERN = r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<url>[^\s]+) HTTP/[\d.]+" (?P<status>\d+) (?P<size>\d+)'
    SSH_PATTERN = r'(?P<timestamp>\w+\s+\d+\s+[\d:]+).*sshd.*(?P<event>Failed password|Accepted password|Invalid user).*from (?P<ip>[\d.]+)'
    SYSTEM_PATTERN = r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+[\d:]+).*\[(?P<level>\w+)\].*(?P<message>.*)'
    
    def __init__(self, log_type: str = 'auto'):
        """
        Initialize LogParser.
        
        Args:
            log_type: Type of log to parse ('apache', 'nginx', 'ssh', 'system', 'auto')
        """
        self.log_type = log_type.lower()
        self.logger = logging.getLogger('security_monitor.log_parser')
        self.parsed_entries = []
        
    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a log file and extract entries.
        
        Args:
            file_path: Path to log file
            
        Returns:
            List of parsed log entries
        """
        self.parsed_entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    entry = self._parse_line(line, line_num)
                    if entry:
                        entry['source_file'] = file_path
                        self.parsed_entries.append(entry)
                        
            self.logger.info(f"Parsed {len(self.parsed_entries)} entries from {file_path}")
            return self.parsed_entries
            
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {file_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing file {file_path}: {e}")
            return []
    
    def _parse_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line.
        
        Args:
            line: Log line to parse
            line_num: Line number in file
            
        Returns:
            Parsed entry dictionary or None
        """
        if self.log_type == 'auto':
            # Try each pattern
            for log_type in ['apache', 'nginx', 'ssh', 'system']:
                entry = self._parse_by_type(line, log_type, line_num)
                if entry:
                    return entry
            return None
        else:
            return self._parse_by_type(line, self.log_type, line_num)
    
    def _parse_by_type(self, line: str, log_type: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        Parse line by specific log type.
        
        Args:
            line: Log line to parse
            log_type: Type of log
            line_num: Line number
            
        Returns:
            Parsed entry or None
        """
        try:
            if log_type == 'apache':
                return self._parse_apache(line, line_num)
            elif log_type == 'nginx':
                return self._parse_nginx(line, line_num)
            elif log_type == 'ssh':
                return self._parse_ssh(line, line_num)
            elif log_type == 'system':
                return self._parse_system(line, line_num)
        except Exception as e:
            self.logger.debug(f"Failed to parse line {line_num} as {log_type}: {e}")
        
        return None
    
    def _parse_apache(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse Apache access log format."""
        match = re.match(self.APACHE_PATTERN, line)
        if not match:
            return None
            
        data = match.groupdict()
        
        return {
            'line_number': line_num,
            'log_type': 'apache',
            'ip_address': data['ip'],
            'timestamp': parse_timestamp(data['timestamp'], ['%d/%b/%Y:%H:%M:%S %z']),
            'timestamp_raw': data['timestamp'],
            'method': data['method'],
            'url': data['url'],
            'status_code': int(data['status']),
            'size': int(data['size']) if data['size'] != '-' else 0,
            'raw_line': line
        }
    
    def _parse_nginx(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse Nginx access log format."""
        match = re.match(self.NGINX_PATTERN, line)
        if not match:
            return None
            
        data = match.groupdict()
        
        return {
            'line_number': line_num,
            'log_type': 'nginx',
            'ip_address': data['ip'],
            'timestamp': parse_timestamp(data['timestamp'], ['%d/%b/%Y:%H:%M:%S %z']),
            'timestamp_raw': data['timestamp'],
            'method': data['method'],
            'url': data['url'],
            'status_code': int(data['status']),
            'size': int(data['size']),
            'raw_line': line
        }
    
    def _parse_ssh(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse SSH authentication log format."""
        match = re.search(self.SSH_PATTERN, line)
        if not match:
            return None
            
        data = match.groupdict()
        
        # Determine event type
        event = data['event']
        if 'Failed' in event:
            event_type = 'failed_login'
        elif 'Accepted' in event:
            event_type = 'successful_login'
        elif 'Invalid' in event:
            event_type = 'invalid_user'
        else:
            event_type = 'unknown'
        
        return {
            'line_number': line_num,
            'log_type': 'ssh',
            'ip_address': data['ip'],
            'timestamp': parse_timestamp(data['timestamp'], ['%b %d %H:%M:%S']),
            'timestamp_raw': data['timestamp'],
            'event': event,
            'event_type': event_type,
            'raw_line': line
        }
    
    def _parse_system(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse system log format."""
        match = re.match(self.SYSTEM_PATTERN, line)
        if not match:
            return None
            
        data = match.groupdict()
        
        # Try to extract IP if present
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', data['message'])
        ip_address = ip_match.group(1) if ip_match else None
        
        return {
            'line_number': line_num,
            'log_type': 'system',
            'ip_address': ip_address,
            'timestamp': parse_timestamp(data['timestamp']),
            'timestamp_raw': data['timestamp'],
            'level': data['level'],
            'message': data['message'],
            'raw_line': line
        }
    
    def get_entries_by_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """
        Get all entries for a specific IP address.
        
        Args:
            ip_address: IP address to filter
            
        Returns:
            List of matching entries
        """
        return [entry for entry in self.parsed_entries 
                if entry.get('ip_address') == ip_address]
    
    def get_entries_by_status(self, status_code: int) -> List[Dict[str, Any]]:
        """
        Get all entries with a specific status code.
        
        Args:
            status_code: HTTP status code
            
        Returns:
            List of matching entries
        """
        return [entry for entry in self.parsed_entries 
                if entry.get('status_code') == status_code]
    
    def get_failed_logins(self) -> List[Dict[str, Any]]:
        """
        Get all failed login attempts.
        
        Returns:
            List of failed login entries
        """
        return [entry for entry in self.parsed_entries 
                if entry.get('event_type') == 'failed_login']
    
    def get_unique_ips(self) -> List[str]:
        """
        Get list of unique IP addresses.
        
        Returns:
            List of unique IPs
        """
        ips = set()
        for entry in self.parsed_entries:
            ip = entry.get('ip_address')
            if ip and validate_ip(ip):
                ips.add(ip)
        return sorted(list(ips))
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about parsed logs.
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_entries': len(self.parsed_entries),
            'unique_ips': len(self.get_unique_ips()),
            'log_types': {},
            'status_codes': {},
            'event_types': {}
        }
        
        for entry in self.parsed_entries:
            # Count log types
            log_type = entry.get('log_type', 'unknown')
            stats['log_types'][log_type] = stats['log_types'].get(log_type, 0) + 1
            
            # Count status codes
            status = entry.get('status_code')
            if status:
                stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
            
            # Count event types
            event_type = entry.get('event_type')
            if event_type:
                stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
        
        return stats
