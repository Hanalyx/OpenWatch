#!/usr/bin/env python3
"""
OpenWatch CLI Interface
Direct command-line interface for SCAP scanning operations
"""
import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict

# Add the backend app to the path
sys.path.insert(0, str(Path(__file__).parent))

from services.scap_cli_scanner import SCAPCLIScanner, CLIScannerError
from config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OpenWatchCLI:
    """Main CLI interface for OpenWatch SCAP scanning"""
    
    def __init__(self):
        self.settings = get_settings()
        self.scanner = SCAPCLIScanner(
            content_dir=self.settings.scap_content_dir,
            results_dir=self.settings.scan_results_dir,
            max_parallel_scans=100  # Support 100+ parallel scans
        )
    
    async def scan_local(self, profile_id: str, content_path: str = None, 
                        rule_id: str = None, output_file: str = None) -> int:
        """Execute local SCAP scan"""
        try:
            print(f"[OpenWatch] Starting local scan with profile: {profile_id}")
            
            # Use default content if not specified
            if not content_path:
                content_path = self.scanner.get_default_content_path()
                print(f"[OpenWatch] Using default content: {content_path}")
            
            # Validate content file
            if not self.scanner.validate_content_file(content_path):
                print(f"[OpenWatch] ERROR: Invalid SCAP content file: {content_path}")
                return 1
            
            # Configure host for local scan
            host_config = {
                'hostname': 'localhost',
                'port': 22,
                'username': 'root',
                'auth_method': 'local',
                'credential': ''
            }
            
            # Execute scan
            if rule_id:
                print(f"[OpenWatch] Scanning specific rule: {rule_id}")
            
            result = await self.scanner.scan_single_host(
                host_config, profile_id, content_path, rule_id
            )
            
            # Display results
            self._print_scan_result(result)
            
            # Export results if requested
            if output_file:
                self.scanner.export_results_json([result], output_file)
                print(f"[OpenWatch] Results exported to: {output_file}")
            
            return 0 if result.get('status') == 'completed' else 1
            
        except Exception as e:
            print(f"[OpenWatch] ERROR: Local scan failed: {e}")
            logger.error(f"Local scan error: {e}")
            return 1
    
    async def scan_remote(self, targets: List[str], profile_id: str, 
                         content_path: str = None, rule_id: str = None,
                         output_file: str = None, parallel: int = 5) -> int:
        """Execute remote SCAP scan on one or more hosts"""
        try:
            print(f"[OpenWatch] Starting remote scan on {len(targets)} target(s)")
            print(f"[OpenWatch] Profile: {profile_id}")
            print(f"[OpenWatch] Max parallel: {parallel}")
            
            # Use default content if not specified  
            if not content_path:
                content_path = self.scanner.get_default_content_path()
                print(f"[OpenWatch] Using default content: {content_path}")
            
            # Validate content file
            if not self.scanner.validate_content_file(content_path):
                print(f"[OpenWatch] ERROR: Invalid SCAP content file: {content_path}")
                return 1
            
            # Note: For demo purposes, remote scanning needs proper credential management
            # In production, this would integrate with the credential storage system
            print("[OpenWatch] NOTE: Remote scanning requires SSH credentials")
            print("[OpenWatch] For demo purposes, showing scan initiation workflow")
            
            default_credentials = {
                'username': 'root',
                'auth_method': 'password', 
                'credential': ''  # Would be loaded from secure storage
            }
            
            # Update scanner concurrency
            self.scanner.max_parallel_scans = parallel
            
            if rule_id:
                print(f"[OpenWatch] Scanning specific rule: {rule_id}")
            
            # Execute batch scan
            results = await self.scanner.batch_scan_from_targets(
                targets, profile_id, content_path, rule_id, default_credentials
            )
            
            # Display summary
            summary = self.scanner.generate_scan_summary(results)
            self._print_scan_summary(summary, targets)
            
            # Export results if requested
            if output_file:
                self.scanner.export_results_json(results, output_file)
                print(f"[OpenWatch] Results exported to: {output_file}")
            
            # Return success if all scans completed
            successful_scans = summary['scan_summary']['successful_scans']
            return 0 if successful_scans == len(targets) else 1
            
        except Exception as e:
            print(f"[OpenWatch] ERROR: Remote scan failed: {e}")
            logger.error(f"Remote scan error: {e}")
            return 1
    
    def list_profiles(self, content_path: str = None) -> int:
        """List available SCAP profiles"""
        try:
            if not content_path:
                content_path = self.scanner.get_default_content_path()
                
            print(f"[OpenWatch] Listing profiles from: {content_path}")
            
            profiles = self.scanner.get_available_profiles(content_path)
            
            if not profiles:
                print("[OpenWatch] No profiles found in content file")
                return 1
            
            print(f"\n[OpenWatch] Available Profiles ({len(profiles)}):")
            print("=" * 60)
            
            for i, profile in enumerate(profiles, 1):
                print(f"{i}. {profile.get('id', 'Unknown ID')}")
                print(f"   Title: {profile.get('title', 'No title')}")
                print(f"   Description: {profile.get('description', 'No description')[:100]}...")
                print()
            
            return 0
            
        except Exception as e:
            print(f"[OpenWatch] ERROR: Failed to list profiles: {e}")
            return 1
    
    def _print_scan_result(self, result: Dict):
        """Print formatted scan result"""
        hostname = result.get('hostname', 'unknown')
        status = result.get('status', 'unknown')
        
        print(f"\n[OpenWatch] Scan Results for {hostname}")
        print("=" * 50)
        print(f"Status: {status.upper()}")
        
        if 'rules_total' in result:
            print(f"Rules Total: {result['rules_total']}")
            print(f"Rules Passed: {result['rules_passed']}")
            print(f"Rules Failed: {result['rules_failed']}")
            print(f"Compliance Score: {result.get('score', 0):.1f}%")
        
        if result.get('error'):
            print(f"Error: {result['error']}")
        
        print()
    
    def _print_scan_summary(self, summary: Dict, targets: List[str]):
        """Print formatted scan summary"""
        scan_sum = summary['scan_summary']
        comp_sum = summary['compliance_summary']
        
        print(f"\n[OpenWatch] Batch Scan Summary")
        print("=" * 50)
        print(f"Total Targets: {len(targets)}")
        print(f"Successful Scans: {scan_sum['successful_scans']}")
        print(f"Failed Scans: {scan_sum['failed_scans']}")
        print(f"Error Scans: {scan_sum['error_scans']}")
        print(f"Success Rate: {scan_sum['success_rate']:.1f}%")
        print()
        print(f"Total Rules Checked: {comp_sum['total_rules_checked']}")
        print(f"Total Rules Passed: {comp_sum['total_rules_passed']}")
        print(f"Total Rules Failed: {comp_sum['total_rules_failed']}")
        print(f"Average Compliance Score: {comp_sum['average_compliance_score']:.1f}%")
        print()


async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='OpenWatch SCAP Compliance Scanner CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli_interface.py scan-local --profile stig-rhel8
  python cli_interface.py scan-remote --targets host1,host2,host3 --profile cis-ubuntu --parallel 10
  python cli_interface.py list-profiles
  python cli_interface.py scan-local --profile custom --content /path/to/content.xml --rule specific_rule_id
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Local scan command
    local_parser = subparsers.add_parser('scan-local', help='Execute local SCAP scan')
    local_parser.add_argument('--profile', '-p', required=True, help='SCAP profile ID')
    local_parser.add_argument('--content', '-c', help='SCAP content file path')
    local_parser.add_argument('--rule', '-r', help='Specific rule ID to scan')
    local_parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    
    # Remote scan command
    remote_parser = subparsers.add_parser('scan-remote', help='Execute remote SCAP scan')
    remote_parser.add_argument('--targets', '-t', required=True, help='Comma-separated list of target hosts')
    remote_parser.add_argument('--profile', '-p', required=True, help='SCAP profile ID')
    remote_parser.add_argument('--content', '-c', help='SCAP content file path')
    remote_parser.add_argument('--rule', '-r', help='Specific rule ID to scan')
    remote_parser.add_argument('--parallel', type=int, default=5, help='Max parallel scans (default: 5)')
    remote_parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    
    # List profiles command
    list_parser = subparsers.add_parser('list-profiles', help='List available SCAP profiles')
    list_parser.add_argument('--content', '-c', help='SCAP content file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    cli = OpenWatchCLI()
    
    try:
        if args.command == 'scan-local':
            return await cli.scan_local(
                args.profile, args.content, args.rule, args.output
            )
        
        elif args.command == 'scan-remote':
            targets = [t.strip() for t in args.targets.split(',') if t.strip()]
            return await cli.scan_remote(
                targets, args.profile, args.content, args.rule, args.output, args.parallel
            )
        
        elif args.command == 'list-profiles':
            return cli.list_profiles(args.content)
        
        else:
            print(f"[OpenWatch] ERROR: Unknown command: {args.command}")
            return 1
            
    except KeyboardInterrupt:
        print("\n[OpenWatch] Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"[OpenWatch] ERROR: {e}")
        logger.error(f"CLI error: {e}")
        return 1


if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)