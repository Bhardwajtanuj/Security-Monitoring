"""
Unit tests for the LogParser module.
"""

import unittest
from datetime import datetime
from core.log_parser import LogParser


class TestLogParser(unittest.TestCase):
    """Test cases for LogParser class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = LogParser()
    
    def test_parse_apache_log(self):
        """Test parsing Apache log format."""
        line = '192.168.1.1 - - [15/Nov/2024:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 2326'
        parser = LogParser(log_type='apache')
        entry = parser._parse_line(line, 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['ip_address'], '192.168.1.1')
        self.assertEqual(entry['method'], 'GET')
        self.assertEqual(entry['url'], '/index.html')
        self.assertEqual(entry['status_code'], 200)
        self.assertEqual(entry['log_type'], 'apache')
    
    def test_parse_ssh_log(self):
        """Test parsing SSH log format."""
        line = 'Nov 15 10:15:23 server sshd[12345]: Failed password for root from 203.0.113.45 port 22334 ssh2'
        parser = LogParser(log_type='ssh')
        entry = parser._parse_line(line, 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['ip_address'], '203.0.113.45')
        self.assertEqual(entry['event_type'], 'failed_login')
        self.assertEqual(entry['log_type'], 'ssh')
    
    def test_auto_detect_format(self):
        """Test automatic log format detection."""
        apache_line = '192.168.1.1 - - [15/Nov/2024:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 2326'
        parser = LogParser(log_type='auto')
        entry = parser._parse_line(apache_line, 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['log_type'], 'apache')
    
    def test_get_unique_ips(self):
        """Test getting unique IP addresses."""
        self.parser.parsed_entries = [
            {'ip_address': '192.168.1.1'},
            {'ip_address': '192.168.1.2'},
            {'ip_address': '192.168.1.1'},
        ]
        
        unique_ips = self.parser.get_unique_ips()
        self.assertEqual(len(unique_ips), 2)
        self.assertIn('192.168.1.1', unique_ips)
        self.assertIn('192.168.1.2', unique_ips)
    
    def test_get_failed_logins(self):
        """Test filtering failed login attempts."""
        self.parser.parsed_entries = [
            {'event_type': 'failed_login', 'ip_address': '1.2.3.4'},
            {'event_type': 'successful_login', 'ip_address': '5.6.7.8'},
            {'event_type': 'failed_login', 'ip_address': '9.10.11.12'},
        ]
        
        failed = self.parser.get_failed_logins()
        self.assertEqual(len(failed), 2)


class TestAnomalyDetector(unittest.TestCase):
    """Test cases for AnomalyDetector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        from core.anomaly_detector import AnomalyDetector
        self.detector = AnomalyDetector(
            blacklist=['192.168.1.100'],
            whitelist=['10.0.0.1'],
            failed_login_threshold=3,
            failed_login_window=300
        )
    
    def test_blacklist_detection(self):
        """Test blacklisted IP detection."""
        self.assertTrue(self.detector.is_blacklisted('192.168.1.100'))
        self.assertFalse(self.detector.is_blacklisted('192.168.1.1'))
    
    def test_whitelist_detection(self):
        """Test whitelisted IP detection."""
        self.assertTrue(self.detector.is_whitelisted('10.0.0.1'))
        self.assertFalse(self.detector.is_whitelisted('192.168.1.1'))
    
    def test_add_to_blacklist(self):
        """Test adding IP to blacklist."""
        self.detector.add_to_blacklist('203.0.113.45')
        self.assertTrue(self.detector.is_blacklisted('203.0.113.45'))


class TestUtils(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_validate_ip(self):
        """Test IP address validation."""
        from utils.utils import validate_ip
        
        self.assertTrue(validate_ip('192.168.1.1'))
        self.assertTrue(validate_ip('10.0.0.1'))
        self.assertFalse(validate_ip('256.1.1.1'))
        self.assertFalse(validate_ip('invalid'))
        self.assertFalse(validate_ip('192.168.1'))
    
    def test_is_private_ip(self):
        """Test private IP detection."""
        from utils.utils import is_private_ip
        
        self.assertTrue(is_private_ip('192.168.1.1'))
        self.assertTrue(is_private_ip('10.0.0.1'))
        self.assertTrue(is_private_ip('172.16.0.1'))
        self.assertFalse(is_private_ip('8.8.8.8'))
        self.assertFalse(is_private_ip('1.1.1.1'))


if __name__ == '__main__':
    unittest.main()
