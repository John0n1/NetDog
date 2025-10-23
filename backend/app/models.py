from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, ForeignKey, Boolean, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    targets = Column(JSON, nullable=False)  # List of IP ranges/hosts
    mode = Column(String(50), nullable=False)  # slow, medium, normal, aggressive
    status = Column(String(50), default="queued")  # queued, running, done, error
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    result_summary = Column(JSON, nullable=True)  # {hosts_found, vulns_found, etc}
    error_message = Column(Text, nullable=True)
    progress_percent = Column(Float, default=0.0)
    current_target = Column(String(255), nullable=True)
    
    # Relationships
    devices = relationship("Device", back_populates="scan", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="scan")


class Device(Base):
    __tablename__ = "devices"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    ip = Column(String(45), nullable=False)  # IPv4/IPv6
    hostname = Column(String(255), nullable=True)
    os_guess = Column(String(255), nullable=True)
    device_type = Column(String(255), nullable=True)  # Android, Windows, Samsung TV, etc.
    vendor = Column(String(255), nullable=True)
    mac_address = Column(String(17), nullable=True)
    open_ports = Column(JSON, nullable=True)  # List of port objects
    last_seen = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Float, default=0.0)
    
    # Relationships
    scan = relationship("Scan", back_populates="devices")
    vulnerabilities = relationship("Vulnerability", secondary="device_vulnerabilities", back_populates="devices")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve = Column(String(50), unique=True, nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score = Column(Float, nullable=True)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)  # List of URLs
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    devices = relationship("Device", secondary="device_vulnerabilities", back_populates="vulnerabilities")


class DeviceVulnerability(Base):
    __tablename__ = "device_vulnerabilities"
    
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), primary_key=True)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), primary_key=True)
    detected_at = Column(DateTime, default=datetime.utcnow)
    affected_service = Column(String(255), nullable=True)  # e.g., "ssh 7.4"
    confidence = Column(Float, default=1.0)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor = Column(String(255), nullable=False)  # Username or system
    action = Column(String(100), nullable=False)  # start_scan, stop_scan, etc
    resource_type = Column(String(50), nullable=True)  # scan, device, etc
    resource_id = Column(String(255), nullable=True)
    params = Column(JSON, nullable=True)  # Action parameters
    consent = Column(JSON, nullable=True)  # {by, reason, approved}
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="audit_logs")


class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
