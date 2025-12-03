"""
Utility functions for the security log monitoring system.
Provides helper functions for IP validation, timestamp parsing, logging, and file I/O.
"""

import re
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


def validate_ip(ip_address: str) -> bool:
    """
    Validate if a string is a valid IPv4 address.
    
    Args:
        ip_address: String to validate
        
    Returns:
        True if valid IPv4 address, False otherwise
    """
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip_address):
        return False
    
    # Check each octet is between 0-255
    octets = ip_address.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)


def parse_timestamp(timestamp_str: str, formats: Optional[List[str]] = None) -> Optional[datetime]:
    """
    Parse timestamp string into datetime object.
    Tries multiple common formats.
    
    Args:
        timestamp_str: Timestamp string to parse
        formats: List of datetime format strings to try
        
    Returns:
        datetime object if successful, None otherwise
    """
    if formats is None:
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S %z',
            '%b %d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%d/%m/%Y %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
        ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str.strip(), fmt)
        except ValueError:
            continue
    
    # If no format matches, return None
    return None


def setup_logging(log_file: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
    """
    Setup logging configuration for the application.
    
    Args:
        log_file: Optional log file path
        level: Logging level
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('security_monitor')
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(console_formatter)
        logger.addHandler(file_handler)
    
    return logger


def load_ip_list(file_path: str) -> List[str]:
    """
    Load IP addresses from a text file (one per line).
    
    Args:
        file_path: Path to IP list file
        
    Returns:
        List of IP addresses
    """
    ip_list = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    if validate_ip(line):
                        ip_list.append(line)
    except FileNotFoundError:
        pass  # Return empty list if file doesn't exist
    
    return ip_list


def save_json(data: Any, file_path: str, indent: int = 2) -> None:
    """
    Save data to JSON file.
    
    Args:
        data: Data to save
        file_path: Output file path
        indent: JSON indentation level
    """
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=indent, default=str)


def load_json(file_path: str) -> Any:
    """
    Load data from JSON file.
    
    Args:
        file_path: Input file path
        
    Returns:
        Loaded data
    """
    with open(file_path, 'r') as f:
        return json.load(f)


def calculate_time_diff(time1: datetime, time2: datetime) -> float:
    """
    Calculate time difference in seconds between two datetime objects.
    
    Args:
        time1: First datetime
        time2: Second datetime
        
    Returns:
        Time difference in seconds
    """
    return abs((time2 - time1).total_seconds())


def format_bytes(bytes_count: int) -> str:
    """
    Format bytes into human-readable format.
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def is_private_ip(ip_address: str) -> bool:
    """
    Check if an IP address is in a private range.
    
    Args:
        ip_address: IP address to check
        
    Returns:
        True if private IP, False otherwise
    """
    if not validate_ip(ip_address):
        return False
    
    octets = [int(x) for x in ip_address.split('.')]
    
    # Private IP ranges:
    # 10.0.0.0 - 10.255.255.255
    # 172.16.0.0 - 172.31.255.255
    # 192.168.0.0 - 192.168.255.255
    # 127.0.0.0 - 127.255.255.255 (loopback)
    
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    
    return False
