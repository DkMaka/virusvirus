import os
import requests
import logging
import json
from datetime import datetime
import hashlib
from app import db
from models import SignatureDefinition

logger = logging.getLogger(__name__)

class SignatureDatabase:
    def __init__(self):
        self.local_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'signatures.json')
        self.update_url = os.environ.get(
            'SIGNATURE_UPDATE_URL',
            'https://raw.githubusercontent.com/ytisf/theZoo/master/malwares.yml'  # Example fallback URL
        )
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.local_db_path), exist_ok=True)
        
        # Create default signatures file if it doesn't exist
        if not os.path.exists(self.local_db_path):
            self._create_default_signatures()
    
    def _create_default_signatures(self):
        """
        Create a default signatures file with some basic signatures
        """
        default_signatures = {
            # Known malware hashes (examples)
            "44d88612fea8a8f36de82e1278abb02f": {
                "threat_name": "Eicar.Test.File",
                "severity": "low",
                "description": "EICAR test file"
            },
            "275a021bbfb6489e54d471899f7db9d1": {
                "threat_name": "Malware.Example.1",
                "severity": "medium",
                "description": "Example malware signature"
            },
            "3f786850e387550fdab836ed7e6dc881": {
                "threat_name": "Malware.Example.2",
                "severity": "high",
                "description": "Example malware signature 2"
            }
        }
        
        os.makedirs(os.path.dirname(self.local_db_path), exist_ok=True)
        with open(self.local_db_path, 'w') as f:
            json.dump(default_signatures, f, indent=2)
    
    def update_definitions(self):
        """
        Update virus signature definitions from a remote source
        """
        logger.info("Updating virus signature definitions")
        
        try:
            # Try to download updated signatures
            response = requests.get(self.update_url, timeout=10)
            if response.status_code == 200:
                # This is a simplified example, in a real application you'd
                # need to parse the downloaded data appropriately
                
                # For demonstration, we'll add a few new signatures
                # In a real app, you'd parse the response and extract signatures
                new_signatures = {
                    # Add EICAR test file signature
                    hashlib.md5(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').hexdigest(): {
                        "threat_name": "Eicar.Test.File",
                        "severity": "low",
                        "description": "EICAR test file"
                    }
                }
                
                # Merge with existing signatures
                existing_signatures = self.get_signatures()
                existing_signatures.update(new_signatures)
                
                # Save updated signatures
                with open(self.local_db_path, 'w') as f:
                    json.dump(existing_signatures, f, indent=2)
                
                # Update database records
                for sig_hash, sig_data in new_signatures.items():
                    existing_sig = SignatureDefinition.query.filter_by(signature_hash=sig_hash).first()
                    if not existing_sig:
                        new_sig = SignatureDefinition(
                            signature_hash=sig_hash,
                            threat_name=sig_data['threat_name'],
                            severity=sig_data['severity'],
                            description=sig_data.get('description', '')
                        )
                        db.session.add(new_sig)
                
                db.session.commit()
                logger.info(f"Signature database updated with {len(new_signatures)} new signatures")
            else:
                logger.warning(f"Failed to update signatures: HTTP {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error updating signatures: {str(e)}")
    
    def get_signatures(self):
        """
        Get all virus signatures from the local database
        """
        try:
            with open(self.local_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading signatures: {str(e)}")
            return {}
    
    def add_signature(self, file_hash, threat_info):
        """
        Add a new signature to the database
        """
        try:
            signatures = self.get_signatures()
            signatures[file_hash] = threat_info
            
            with open(self.local_db_path, 'w') as f:
                json.dump(signatures, f, indent=2)
            
            # Add to database
            existing_sig = SignatureDefinition.query.filter_by(signature_hash=file_hash).first()
            if not existing_sig:
                new_sig = SignatureDefinition(
                    signature_hash=file_hash,
                    threat_name=threat_info['threat_name'],
                    severity=threat_info['severity'],
                    description=threat_info.get('description', '')
                )
                db.session.add(new_sig)
                db.session.commit()
            
            logger.info(f"Added new signature for {threat_info['threat_name']}")
            return True
        
        except Exception as e:
            logger.error(f"Error adding signature: {str(e)}")
            return False
