from datetime import datetime
from app import db
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship

class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    scan_type = Column(String(50), nullable=False)  # quick, full, custom
    scan_date = Column(DateTime, default=datetime.utcnow)
    targets = Column(Text, nullable=False)  # Comma-separated list of scanned paths
    status = Column(String(20), default='in_progress')  # in_progress, completed, failed
    files_scanned = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    completion_time = Column(Float, nullable=True)  # Time in seconds
    
    # Relationship with detected threats
    threats = relationship("DetectedThreat", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<ScanResult {self.id} - {self.scan_type} - {self.scan_date}>'

class DetectedThreat(db.Model):
    __tablename__ = 'detected_threats'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_results.id'), nullable=False)
    file_path = Column(String(255), nullable=False)
    threat_type = Column(String(100), nullable=False)
    threat_name = Column(String(100), nullable=True)
    detection_method = Column(String(50), nullable=False)  # signature, heuristic, behavioral
    file_hash = Column(String(64), nullable=False)  # SHA-256 hash
    quarantined = Column(Boolean, default=False)
    deleted = Column(Boolean, default=False)
    
    # Relationship with scan result
    scan = relationship("ScanResult", back_populates="threats")
    
    def __repr__(self):
        return f'<DetectedThreat {self.id} - {self.threat_name} - {self.file_path}>'

class QuarantinedFile(db.Model):
    __tablename__ = 'quarantined_files'
    
    id = Column(Integer, primary_key=True)
    original_path = Column(String(255), nullable=False)
    quarantine_path = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256 hash
    threat_name = Column(String(100), nullable=True)
    quarantine_date = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<QuarantinedFile {self.id} - {self.original_path}>'

class SignatureDefinition(db.Model):
    __tablename__ = 'signature_definitions'
    
    id = Column(Integer, primary_key=True)
    signature_hash = Column(String(64), nullable=False, unique=True)
    threat_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    description = Column(Text, nullable=True)
    added_date = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<SignatureDefinition {self.id} - {self.threat_name}>'

class SystemHealthLog(db.Model):
    __tablename__ = 'system_health_logs'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    cpu_usage = Column(Float, nullable=False)
    memory_usage = Column(Float, nullable=False)
    disk_usage = Column(Float, nullable=False)
    running_processes = Column(Integer, nullable=False)
    suspicious_processes = Column(Integer, default=0)
    network_connections = Column(Integer, nullable=False)
    suspicious_connections = Column(Integer, default=0)
    
    def __repr__(self):
        return f'<SystemHealthLog {self.id} - {self.timestamp}>'
