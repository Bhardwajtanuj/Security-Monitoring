"""
Security Log Monitoring & Alert Automation System
Main application entry point with CLI interface.
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List, Dict, Any

from core.log_parser import LogParser
from core.anomaly_detector import AnomalyDetector
from core.alert_manager import AlertManager
from core.report_generator import ReportGenerator
from utils.utils import setup_logging, load_ip_list, load_json


def load_config(config_path: str = 'config/config.json') -> Dict[str, Any]:
    """Load configuration from JSON file."""
    try:
        return load_json(config_path)
    except FileNotFoundError:
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in configuration file: {e}")
        sys.exit(1)


def parse_logs(config: Dict[str, Any], logger) -> tuple:
    """Parse all configured log sources."""
    all_entries = []
    log_sources = config.get('log_sources', [])
    
    for source in log_sources:
        if not source.get('enabled', True):
            continue
            
        log_path = source['path']
        log_type = source.get('type', 'auto')
        
        logger.info(f"Parsing {source['name']} from {log_path}")
        
        parser = LogParser(log_type=log_type)
        entries = parser.parse_file(log_path)
        all_entries.extend(entries)
        
        logger.info(f"Parsed {len(entries)} entries from {source['name']}")
    
    # Get statistics
    if all_entries:
        parser = LogParser()
        parser.parsed_entries = all_entries
        stats = parser.get_statistics()
    else:
        stats = {'total_entries': 0, 'unique_ips': 0}
    
    return all_entries, stats


def detect_anomalies(log_entries: List[Dict[str, Any]], 
                     config: Dict[str, Any], 
                     logger) -> tuple:
    """Detect anomalies in parsed logs."""
    anomaly_config = config.get('anomaly_detection', {})
    
    # Load blacklist and whitelist
    blacklist = []
    whitelist = []
    
    blacklist_file = anomaly_config.get('blacklist_file')
    if blacklist_file and Path(blacklist_file).exists():
        blacklist = load_ip_list(blacklist_file)
        logger.info(f"Loaded {len(blacklist)} IPs from blacklist")
    
    whitelist_file = anomaly_config.get('whitelist_file')
    if whitelist_file and Path(whitelist_file).exists():
        whitelist = load_ip_list(whitelist_file)
        logger.info(f"Loaded {len(whitelist)} IPs from whitelist")
    
    # Initialize detector
    detector = AnomalyDetector(
        blacklist=blacklist,
        whitelist=whitelist,
        failed_login_threshold=anomaly_config.get('failed_login_threshold', 5),
        failed_login_window=anomaly_config.get('failed_login_window_seconds', 300),
        request_rate_threshold=anomaly_config.get('request_rate_threshold', 100),
        request_rate_window=anomaly_config.get('request_rate_window_seconds', 60)
    )
    
    # Analyze logs
    logger.info("Analyzing logs for anomalies...")
    anomalies = detector.analyze_logs(log_entries)
    stats = detector.get_statistics()
    
    return anomalies, stats


def send_alerts(anomalies: List[Dict[str, Any]], 
                config: Dict[str, Any], 
                logger) -> None:
    """Send alerts for detected anomalies."""
    alert_config = config.get('alerting', {})
    
    if not alert_config.get('email', {}).get('enabled') and \
       not alert_config.get('webhook', {}).get('enabled'):
        logger.info("Alerting is disabled in configuration")
        return
    
    alert_manager = AlertManager(config=alert_config)
    
    # Send individual alerts
    sent_count = alert_manager.send_batch_alerts(anomalies)
    logger.info(f"Sent {sent_count} alerts")


def generate_report(log_stats: Dict[str, Any],
                    anomalies: List[Dict[str, Any]],
                    anomaly_stats: Dict[str, Any],
                    config: Dict[str, Any],
                    logger) -> str:
    """Generate security report."""
    report_config = config.get('reporting', {})
    output_dir = report_config.get('output_directory', 'reports')
    report_format = report_config.get('default_format', 'html')
    
    generator = ReportGenerator(output_dir=output_dir)
    
    logger.info(f"Generating {report_format.upper()} report...")
    report_path = generator.generate_report(
        log_stats=log_stats,
        anomalies=anomalies,
        anomaly_stats=anomaly_stats,
        format=report_format
    )
    
    # Also generate JSON report
    if report_format != 'json':
        json_path = generator.generate_report(
            log_stats=log_stats,
            anomalies=anomalies,
            anomaly_stats=anomaly_stats,
            format='json'
        )
        logger.info(f"JSON report saved to: {json_path}")
    
    return report_path


def print_summary(log_stats: Dict[str, Any], 
                 anomaly_stats: Dict[str, Any]) -> None:
    """Print summary to console."""
    print("\n" + "="*60)
    print("SECURITY MONITORING SUMMARY")
    print("="*60)
    print(f"\nLog Statistics:")
    print(f"  Total Entries: {log_stats.get('total_entries', 0):,}")
    print(f"  Unique IPs: {log_stats.get('unique_ips', 0):,}")
    
    print(f"\nAnomaly Statistics:")
    print(f"  Total Anomalies: {anomaly_stats.get('total_anomalies', 0):,}")
    print(f"  Affected IPs: {anomaly_stats.get('unique_ips', 0):,}")
    
    severity_breakdown = anomaly_stats.get('by_severity', {})
    if severity_breakdown:
        print(f"\nSeverity Breakdown:")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_breakdown.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")
    
    type_breakdown = anomaly_stats.get('by_type', {})
    if type_breakdown:
        print(f"\nAnomaly Types:")
        for atype, count in sorted(type_breakdown.items(), key=lambda x: x[1], reverse=True):
            display_name = atype.replace('_', ' ').title()
            print(f"  {display_name}: {count}")
    
    print("\n" + "="*60 + "\n")


def main():
    """Main application function."""
    parser = argparse.ArgumentParser(
        description='Security Log Monitoring & Alert Automation System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Run with default config
  python main.py -c custom_config.json    # Use custom config
  python main.py --no-alerts              # Skip sending alerts
  python main.py --format json            # Generate JSON report
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config/config.json',
        help='Path to configuration file (default: config/config.json)'
    )
    
    parser.add_argument(
        '--no-alerts',
        action='store_true',
        help='Skip sending alerts'
    )
    
    parser.add_argument(
        '--format',
        choices=['html', 'json'],
        help='Report format (overrides config)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Setup logging
    log_config = config.get('logging', {})
    log_level = 'DEBUG' if args.verbose else log_config.get('level', 'INFO')
    log_file = log_config.get('log_file')
    
    import logging
    level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR
    }
    
    logger = setup_logging(log_file=log_file, level=level_map.get(log_level, logging.INFO))
    
    logger.info("="*60)
    logger.info("Security Log Monitoring & Alert Automation System")
    logger.info("="*60)
    
    try:
        # Step 1: Parse logs
        logger.info("\n[1/4] Parsing log files...")
        log_entries, log_stats = parse_logs(config, logger)
        
        if not log_entries:
            logger.warning("No log entries found!")
            print("\nNo log entries found. Please check your log files.")
            return
        
        # Step 2: Detect anomalies
        logger.info("\n[2/4] Detecting anomalies...")
        anomalies, anomaly_stats = detect_anomalies(log_entries, config, logger)
        
        # Step 3: Send alerts
        if not args.no_alerts and anomalies:
            logger.info("\n[3/4] Sending alerts...")
            send_alerts(anomalies, config, logger)
        else:
            logger.info("\n[3/4] Skipping alerts (disabled or no anomalies)")
        
        # Step 4: Generate report
        logger.info("\n[4/4] Generating report...")
        report_format = args.format or config.get('reporting', {}).get('default_format', 'html')
        
        # Override config for report format
        if args.format:
            config['reporting']['default_format'] = args.format
        
        report_path = generate_report(log_stats, anomalies, anomaly_stats, config, logger)
        
        # Print summary
        print_summary(log_stats, anomaly_stats)
        
        print(f"\n[SUCCESS] Report generated successfully!")
        print(f"[REPORT] Report location: {report_path}")
        
        if anomalies:
            critical_count = anomaly_stats.get('by_severity', {}).get('critical', 0)
            high_count = anomaly_stats.get('by_severity', {}).get('high', 0)
            
            if critical_count > 0:
                print(f"\n[WARNING] {critical_count} CRITICAL anomalies detected!")
            if high_count > 0:
                print(f"[WARNING] {high_count} HIGH severity anomalies detected!")
        else:
            print(f"\n[SUCCESS] No security anomalies detected. System is secure!")
        
        logger.info("\nProcessing complete!")
        
    except Exception as e:
        logger.error(f"Error during processing: {e}", exc_info=True)
        print(f"\n[ERROR] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
