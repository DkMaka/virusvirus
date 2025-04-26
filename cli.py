#!/usr/bin/env python3
import sys
import os
import argparse
import logging
import time
import signal
from datetime import datetime
from scanner import Scanner
from signature_db import SignatureDatabase
from system_monitor import SystemMonitor

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VirusScannerCLI:
    def __init__(self):
        self.scanner = Scanner()
        self.signature_db = SignatureDatabase()
        self.system_monitor = SystemMonitor()
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._handle_interrupt)
    
    def _handle_interrupt(self, sig, frame):
        print("\nOperation interrupted by user. Exiting...")
        sys.exit(0)
    
    def run(self):
        """
        Main entry point for the CLI
        """
        parser = argparse.ArgumentParser(description="Virus Scanner CLI")
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan for viruses')
        scan_parser.add_argument('--type', choices=['quick', 'full', 'custom'], default='quick',
                                help='Type of scan to perform')
        scan_parser.add_argument('--path', help='Path to scan (required for custom scan)', default=None)
        
        # Update command
        update_parser = subparsers.add_parser('update', help='Update virus definitions')
        
        # System command
        system_parser = subparsers.add_parser('system', help='Show system status')
        
        # Quarantine command
        quarantine_parser = subparsers.add_parser('quarantine', help='Manage quarantined files')
        quarantine_parser.add_argument('--list', action='store_true', help='List quarantined files')
        quarantine_parser.add_argument('--restore', type=int, help='Restore file by ID')
        quarantine_parser.add_argument('--delete', type=int, help='Delete file by ID')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        # Handle commands
        if args.command == 'scan':
            self._handle_scan_command(args)
        elif args.command == 'update':
            self._handle_update_command()
        elif args.command == 'system':
            self._handle_system_command()
        elif args.command == 'quarantine':
            self._handle_quarantine_command(args)
    
    def _handle_scan_command(self, args):
        """
        Handle the scan command
        """
        scan_type = args.type
        path = args.path
        
        if scan_type == 'custom' and not path:
            print("Error: --path is required for custom scan")
            return
        
        print(f"Starting {scan_type} scan...")
        
        if scan_type == 'quick':
            paths = ['/home', '/tmp']
        elif scan_type == 'full':
            paths = ['/']
        else:  # custom
            paths = [path]
        
        try:
            scan_id = self.scanner.start_scan(paths, scan_type)
            self._display_scan_progress(scan_id)
        except Exception as e:
            print(f"Error during scan: {str(e)}")
    
    def _display_scan_progress(self, scan_id):
        """
        Display scan progress in real-time
        """
        last_progress = -1
        dots = 0
        
        while True:
            progress = self.scanner.get_scan_progress(scan_id)
            if progress['progress'] != last_progress:
                current_file = progress['current_file']
                if len(current_file) > 50:
                    current_file = "..." + current_file[-47:]
                
                # Clear line and update progress
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                sys.stdout.write(f"Progress: {progress['progress']}% | Files: {progress['files_scanned']} | {current_file}")
                sys.stdout.flush()
                last_progress = progress['progress']
            
            # If scan is complete, exit loop
            if progress['progress'] == 100:
                print("\nScan completed!")
                self._display_scan_results(scan_id)
                break
            
            # Display "working" animation
            if progress['progress'] == last_progress:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                sys.stdout.write(f"Progress: {progress['progress']}% | Files: {progress['files_scanned']} | {progress['current_file']} {'.' * dots}")
                sys.stdout.flush()
                dots = (dots + 1) % 4
            
            time.sleep(0.5)
    
    def _display_scan_results(self, scan_id):
        """
        Display scan results
        """
        threats = self.scanner.get_threats(scan_id)
        
        if not threats:
            print("No threats detected!")
            return
        
        print(f"\nFound {len(threats)} threat(s):")
        print("-" * 80)
        print(f"{'ID':<5} | {'Threat Type':<15} | {'Threat Name':<20} | {'File Path':<30}")
        print("-" * 80)
        
        for threat in threats:
            path = threat.file_path
            if len(path) > 30:
                path = "..." + path[-27:]
            
            print(f"{threat.id:<5} | {threat.threat_type:<15} | {threat.threat_name:<20} | {path:<30}")
        
        print("-" * 80)
        
        # Ask if user wants to quarantine threats
        response = input("Do you want to quarantine all threats? (y/n): ").lower()
        if response == 'y':
            for threat in threats:
                try:
                    print(f"Quarantining: {threat.file_path}...", end='')
                    self.scanner.quarantine_file(threat.id)
                    print(" Done!")
                except Exception as e:
                    print(f" Error: {str(e)}")
    
    def _handle_update_command(self):
        """
        Handle the update command
        """
        print("Updating virus definitions...")
        try:
            self.signature_db.update_definitions()
            print("Virus definitions updated successfully!")
        except Exception as e:
            print(f"Error updating virus definitions: {str(e)}")
    
    def _handle_system_command(self):
        """
        Handle the system command
        """
        print("Gathering system information...")
        status = self.system_monitor.get_system_status()
        
        # Display CPU info
        print("\n=== CPU Information ===")
        print(f"Usage: {status['cpu']['usage_percent']}%")
        print(f"Cores: {status['cpu']['count']}")
        if status['cpu']['frequency_mhz']:
            print(f"Frequency: {status['cpu']['frequency_mhz']:.2f} MHz")
        
        # Display memory info
        print("\n=== Memory Information ===")
        print(f"Total: {status['memory']['total_gb']:.2f} GB")
        print(f"Used: {status['memory']['used_gb']:.2f} GB ({status['memory']['percent']}%)")
        
        # Display disk info
        print("\n=== Disk Information ===")
        for disk in status['disks']:
            print(f"Disk: {disk['mountpoint']}")
            print(f"  Total: {disk['total_gb']:.2f} GB")
            print(f"  Used: {disk['used_gb']:.2f} GB ({disk['percent']}%)")
        
        # Display suspicious processes
        if status['processes']['suspicious_processes']:
            print("\n=== Suspicious Processes ===")
            for proc in status['processes']['suspicious_processes']:
                print(f"PID: {proc['pid']} | Name: {proc['name']} | CPU: {proc['cpu_percent']}% | Memory: {proc['memory_percent']:.2f}%")
        
        # Display top processes
        print("\n=== Top Processes ===")
        for proc in status['processes']['top_processes'][:5]:
            print(f"PID: {proc['pid']} | Name: {proc['name']} | CPU: {proc['cpu_percent']}% | Memory: {proc['memory_percent']:.2f}%")
        
        # Display system info
        print("\n=== System Information ===")
        print(f"OS: {status['system']['system']} {status['system']['release']}")
        print(f"Version: {status['system']['version']}")
        print(f"Architecture: {status['system']['machine']}")
        print(f"Boot Time: {status['system']['boot_time']}")
        
        # Display network info
        print("\n=== Network Information ===")
        print(f"Active Connections: {status['network']['total_connections']}")
        print(f"Bytes Sent: {status['network']['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"Bytes Received: {status['network']['bytes_recv'] / (1024*1024):.2f} MB")
    
    def _handle_quarantine_command(self, args):
        """
        Handle the quarantine command
        """
        from models import QuarantinedFile
        from app import app
        
        with app.app_context():
            if args.list or (not args.restore and not args.delete):
                quarantined_files = QuarantinedFile.query.all()
                
                if not quarantined_files:
                    print("No files in quarantine.")
                    return
                
                print("\n=== Quarantined Files ===")
                print("-" * 80)
                print(f"{'ID':<5} | {'Threat Name':<20} | {'Original Path':<40} | {'Date':<15}")
                print("-" * 80)
                
                for qfile in quarantined_files:
                    path = qfile.original_path
                    if len(path) > 40:
                        path = "..." + path[-37:]
                    
                    date = qfile.quarantine_date.strftime("%Y-%m-%d")
                    print(f"{qfile.id:<5} | {qfile.threat_name:<20} | {path:<40} | {date:<15}")
                
                print("-" * 80)
            
            elif args.restore:
                try:
                    self.scanner.restore_file(args.restore)
                    print(f"File with ID {args.restore} restored successfully.")
                except Exception as e:
                    print(f"Error restoring file: {str(e)}")
            
            elif args.delete:
                try:
                    # Get quarantined file record
                    quarantined_file = QuarantinedFile.query.get(args.delete)
                    if not quarantined_file:
                        print(f"No quarantined file with ID {args.delete}")
                        return
                    
                    # Delete the actual file
                    if os.path.exists(quarantined_file.quarantine_path):
                        os.remove(quarantined_file.quarantine_path)
                    
                    # Delete the database record
                    db.session.delete(quarantined_file)
                    db.session.commit()
                    
                    print(f"File with ID {args.delete} permanently deleted.")
                except Exception as e:
                    print(f"Error deleting file: {str(e)}")

if __name__ == "__main__":
    cli = VirusScannerCLI()
    cli.run()
