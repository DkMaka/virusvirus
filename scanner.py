import os
import hashlib
import logging
import time
import magic
import threading
from datetime import datetime
from pathlib import Path
import shutil

from app import db
from models import ScanResult, DetectedThreat, QuarantinedFile
from signature_db import SignatureDatabase

logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self):
        self.signature_db = SignatureDatabase()
        self.active_scans = {}
        self.quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine')
        
        # Create quarantine directory if it doesn't exist
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def start_scan(self, paths, scan_type):
        """
        Start a new scan and return scan ID
        """
        # Import app here to avoid circular imports
        from app import app
        
        # Use application context for database operations
        with app.app_context():
            # Create scan result record
            scan_result = ScanResult(
                scan_type=scan_type,
                targets=','.join(paths),
                status='in_progress'
            )
            db.session.add(scan_result)
            db.session.commit()
            
            # Get the ID to return
            scan_id = scan_result.id
            
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(scan_id, paths)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # Store thread in active scans
        self.active_scans[scan_id] = {
            'thread': scan_thread,
            'progress': 0,
            'current_file': '',
            'files_scanned': 0
        }
        
        return scan_id
    
    def _perform_scan(self, scan_id, paths):
        """
        Perform the actual scanning operation
        """
        logger.info(f"Starting scan {scan_id} for paths: {paths}")
        
        # Import app here to avoid circular imports
        from app import app
        
        # Get signatures outside of the app context
        signatures = self.signature_db.get_signatures()
        files_scanned = 0
        threats_found = 0
        start_time = time.time()
        
        try:
            # Scan each path
            for path in paths:
                if not os.path.exists(path):
                    logger.warning(f"Path {path} does not exist, skipping")
                    continue
                
                # Walk through directory if it's a directory
                if os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            self.active_scans[scan_id]['current_file'] = file_path
                            
                            # Check if file is a threat
                            if self._scan_file(file_path, scan_id, signatures):
                                threats_found += 1
                            
                            files_scanned += 1
                            self.active_scans[scan_id]['files_scanned'] = files_scanned
                            self.active_scans[scan_id]['progress'] = min(99, int((files_scanned / (files_scanned + 1)) * 100))
                
                # If it's a file, scan it directly
                elif os.path.isfile(path):
                    self.active_scans[scan_id]['current_file'] = path
                    if self._scan_file(path, scan_id, signatures):
                        threats_found += 1
                    files_scanned += 1
                    self.active_scans[scan_id]['files_scanned'] = files_scanned
            
            # Update scan result in the app context
            with app.app_context():
                scan_result = ScanResult.query.get(scan_id)
                if scan_result:
                    scan_result.status = 'completed'
                    scan_result.files_scanned = files_scanned
                    scan_result.threats_found = threats_found
                    scan_result.completion_time = time.time() - start_time
                    db.session.commit()
            
            logger.info(f"Scan {scan_id} completed: {files_scanned} files scanned, {threats_found} threats found")
            self.active_scans[scan_id]['progress'] = 100
        
        except Exception as e:
            logger.error(f"Error during scan {scan_id}: {str(e)}")
            # Update scan result in the app context
            with app.app_context():
                scan_result = ScanResult.query.get(scan_id)
                if scan_result:
                    scan_result.status = 'failed'
                    db.session.commit()
            raise
    
    def _scan_file(self, file_path, scan_id, signatures):
        """
        Scan a single file for threats
        Returns True if a threat is found, False otherwise
        """
        try:
            # Skip if file too large (>100MB) or not accessible
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                return False
            
            file_stat = os.stat(file_path)
            if file_stat.st_size > 100 * 1024 * 1024:  # 100MB
                logger.info(f"Skipping large file: {file_path}")
                return False
            
            # Get file type
            file_type = magic.from_file(file_path, mime=True)
            
            # Skip certain file types
            if file_type.startswith(('image/', 'audio/', 'video/')):
                return False
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check against signature database
            threat_info = self._check_signatures(file_hash, signatures)
            
            # Import app here to avoid circular imports
            from app import app
            
            # Use application context for database operations
            with app.app_context():
                if threat_info:
                    # Create detected threat record
                    threat = DetectedThreat(
                        scan_id=scan_id,
                        file_path=file_path,
                        threat_type=threat_info['type'],
                        threat_name=threat_info['name'],
                        detection_method='signature',
                        file_hash=file_hash
                    )
                    db.session.add(threat)
                    db.session.commit()
                    return True
                
                # If no signature match, check for suspicious patterns
                if self._check_heuristics(file_path, file_type):
                    threat = DetectedThreat(
                        scan_id=scan_id,
                        file_path=file_path,
                        threat_type='Suspicious',
                        threat_name='Heuristic.Suspicious',
                        detection_method='heuristic',
                        file_hash=file_hash
                    )
                    db.session.add(threat)
                    db.session.commit()
                    return True
                    
            return False
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return False
    
    def _calculate_file_hash(self, file_path):
        """
        Calculate SHA-256 hash of a file
        """
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def _check_signatures(self, file_hash, signatures):
        """
        Check file hash against signature database
        """
        if file_hash in signatures:
            return {
                'type': 'Malware',
                'name': signatures[file_hash]['threat_name'],
                'severity': signatures[file_hash]['severity']
            }
        return None
    
    def _check_heuristics(self, file_path, file_type):
        """
        Check file for suspicious patterns using heuristics
        """
        try:
            # Check executable files
            if file_type in ('application/x-executable', 'application/x-dosexec', 'application/x-sharedlib'):
                # Read first few bytes to check for suspicious patterns
                with open(file_path, 'rb') as f:
                    header = f.read(4096)
                    
                    # Simple pattern matching for demonstration
                    suspicious_patterns = [
                        b'CreateRemoteThread',
                        b'VirtualAlloc',
                        b'ShellExecute',
                        b'WinExec',
                        b'URLDownloadToFile'
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in header:
                            return True
            
            # Check script files
            elif file_type in ('text/x-python', 'text/javascript', 'text/x-php'):
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    suspicious_patterns = [
                        'eval(', 
                        'base64_decode(',
                        'exec(',
                        'system(',
                        'passthru(',
                        'shell_exec('
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            return True
            
            return False
        
        except Exception as e:
            logger.error(f"Error during heuristic check on {file_path}: {str(e)}")
            return False
    
    def get_scan_progress(self, scan_id):
        """
        Get progress of an active scan
        """
        if scan_id in self.active_scans:
            return {
                'progress': self.active_scans[scan_id]['progress'],
                'current_file': self.active_scans[scan_id]['current_file'],
                'files_scanned': self.active_scans[scan_id]['files_scanned']
            }
        
        # Import app here to avoid circular imports
        from app import app
        
        # Use application context for database queries
        with app.app_context():
            # If not in active scans, check database
            scan_result = ScanResult.query.get(scan_id)
            if scan_result:
                if scan_result.status == 'completed':
                    return {
                        'progress': 100,
                        'current_file': 'Completed',
                        'files_scanned': scan_result.files_scanned
                    }
                elif scan_result.status == 'failed':
                    return {
                        'progress': 0,
                        'current_file': 'Failed',
                        'files_scanned': scan_result.files_scanned
                    }
        
        return {
            'progress': 0,
            'current_file': 'Unknown',
            'files_scanned': 0
        }
    
    def get_threats(self, scan_id):
        """
        Get all threats detected in a scan
        """
        # Import app here to avoid circular imports
        from app import app
        
        # Use application context for database queries
        with app.app_context():
            return DetectedThreat.query.filter_by(scan_id=scan_id).all()
    
    def quarantine_file(self, threat_id):
        """
        Move a file to quarantine
        """
        # Import app here to avoid circular imports
        from app import app
        
        # Use application context for database queries
        with app.app_context():
            threat = DetectedThreat.query.get(threat_id)
            if not threat:
                raise ValueError(f"Threat with ID {threat_id} not found")
            
            # Check if file exists
            if not os.path.exists(threat.file_path):
                raise FileNotFoundError(f"File {threat.file_path} does not exist")
            
            # Create quarantine location
            quarantine_filename = f"{threat.file_hash}_{os.path.basename(threat.file_path)}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Move file to quarantine
            try:
                shutil.move(threat.file_path, quarantine_path)
                
                # Update threat record
                threat.quarantined = True
                
                # Create quarantined file record
                quarantined_file = QuarantinedFile(
                    original_path=threat.file_path,
                    quarantine_path=quarantine_path,
                    file_hash=threat.file_hash,
                    threat_name=threat.threat_name
                )
                
                db.session.add(quarantined_file)
                db.session.commit()
                
                logger.info(f"File {threat.file_path} quarantined to {quarantine_path}")
                return True
            
            except Exception as e:
                logger.error(f"Error quarantining file {threat.file_path}: {str(e)}")
                raise
    
    def delete_file(self, threat_id):
        """
        Delete a file directly
        """
        # Import app here to avoid circular imports
        from app import app
        
        # Use application context for database queries
        with app.app_context():
            threat = DetectedThreat.query.get(threat_id)
            if not threat:
                raise ValueError(f"Threat with ID {threat_id} not found")
            
            # Check if file exists
            if not os.path.exists(threat.file_path):
                raise FileNotFoundError(f"File {threat.file_path} does not exist")
            
            # Delete the file
            try:
                os.remove(threat.file_path)
                
                # Update threat record
                threat.deleted = True
                db.session.commit()
                
                logger.info(f"File {threat.file_path} deleted")
                return True
            
            except Exception as e:
                logger.error(f"Error deleting file {threat.file_path}: {str(e)}")
                raise
    
    def restore_file(self, quarantine_id):
        """
        Restore a quarantined file to its original location
        """
        # Import app here to avoid circular imports
        from app import app
        
        # Use application context for database queries
        with app.app_context():
            quarantined_file = QuarantinedFile.query.get(quarantine_id)
            if not quarantined_file:
                raise ValueError(f"Quarantined file with ID {quarantine_id} not found")
            
            # Check if quarantined file exists
            if not os.path.exists(quarantined_file.quarantine_path):
                raise FileNotFoundError(f"Quarantined file {quarantined_file.quarantine_path} does not exist")
            
            # Ensure the destination directory exists
            os.makedirs(os.path.dirname(quarantined_file.original_path), exist_ok=True)
            
            # Restore the file
            try:
                shutil.move(quarantined_file.quarantine_path, quarantined_file.original_path)
                
                # Update any associated threat records
                threats = DetectedThreat.query.filter_by(
                    file_path=quarantined_file.original_path,
                    file_hash=quarantined_file.file_hash
                ).all()
                
                for threat in threats:
                    threat.quarantined = False
                
                # Delete the quarantined file record
                db.session.delete(quarantined_file)
                db.session.commit()
                
                logger.info(f"File restored from {quarantined_file.quarantine_path} to {quarantined_file.original_path}")
                return True
            
            except Exception as e:
                logger.error(f"Error restoring file from {quarantined_file.quarantine_path} to {quarantined_file.original_path}: {str(e)}")
                raise
