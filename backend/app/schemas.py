from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID
from typing import List, Optional, Dict, Any


# Consent Schema
class ConsentSchema(BaseModel):
    approved: bool
    by: str
    reason: str


# Scan Schemas
class ScanCreate(BaseModel):
    targets: List[str] = Field(..., description="List of IP addresses or CIDR ranges")
    mode: str = Field("normal", description="Scan mode: slow, medium, normal, aggressive")
    options: Optional[Dict[str, Any]] = None
    consent: ConsentSchema


class ScanResponse(BaseModel):
    scan_id: UUID
    
    class Config:
        from_attributes = True


class ScanStatus(BaseModel):
    id: UUID
    targets: List[str]
    mode: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    progress_percent: float
    current_target: Optional[str]
    result_summary: Optional[Dict[str, Any]]
    error_message: Optional[str]
    
    class Config:
        from_attributes = True


class ScanListItem(BaseModel):
    id: UUID
    targets: List[str]
    mode: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    result_summary: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True


class RiskBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class DashboardOverview(BaseModel):
    total_scans: int
    active_scans: int
    completed_scans: int
    total_devices: int
    new_devices_24h: int
    high_risk_devices: int
    critical_vulnerabilities: int
    average_risk_score: Optional[float] = None
    risk_distribution: RiskBreakdown
    recent_scan: Optional[ScanListItem] = None
    last_updated: datetime

    class Config:
        from_attributes = True


# Device Schemas
class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class DeviceResponse(BaseModel):
    id: UUID
    scan_id: UUID
    ip: str
    hostname: Optional[str]
    os_guess: Optional[str]
    device_type: Optional[str]
    vendor: Optional[str]
    mac_address: Optional[str]
    open_ports: Optional[List[Dict[str, Any]]]
    last_seen: datetime
    risk_score: float
    
    class Config:
        from_attributes = True


class DeviceDetail(DeviceResponse):
    vulnerabilities: List["VulnerabilityResponse"] = []


# Vulnerability Schemas
class VulnerabilityResponse(BaseModel):
    id: UUID
    cve: str
    severity: str
    cvss_score: Optional[float]
    summary: Optional[str]
    description: Optional[str]
    references: Optional[List[str]]
    published_date: Optional[datetime]
    first_seen: datetime
    
    class Config:
        from_attributes = True


class VulnerabilityWithDevices(VulnerabilityResponse):
    affected_devices: List[UUID] = []


# Network Utility Schemas
class PingRequest(BaseModel):
    target: str
    count: int = 4
    consent: ConsentSchema


class PingResponse(BaseModel):
    target: str
    packets_sent: int
    packets_received: int
    packet_loss_percent: float
    min_rtt: Optional[float]
    avg_rtt: Optional[float]
    max_rtt: Optional[float]
    stddev_rtt: Optional[float]
    output: Optional[str] = None


class SpeedTestRequest(BaseModel):
    consent: ConsentSchema


class SpeedTestResponse(BaseModel):
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    server: str
    server_location: Optional[str] = None
    isp: Optional[str] = None
    result_url: Optional[str] = None
    timestamp: datetime


class DNSLookupResponse(BaseModel):
    hostname: str
    canonical_name: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    ipv4_addresses: List[str] = Field(default_factory=list)
    ipv6_addresses: List[str] = Field(default_factory=list)
    reverse_dns: Optional[str] = None
    name_servers: List[str] = Field(default_factory=list)
    resolved_at: datetime


class TracerouteRequest(BaseModel):
    target: str
    max_hops: int = Field(20, ge=1, le=64)
    attempts: int = Field(3, ge=1, le=5)


class TracerouteHop(BaseModel):
    hop: int
    host: str
    ip: Optional[str]
    rtt_ms: Optional[float]


class TracerouteResponse(BaseModel):
    target: str
    hops: List[TracerouteHop] = Field(default_factory=list)
    completed: bool


class PortScanRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None
    timeout: float = Field(1.0, ge=0.1, le=5.0)


class PortScanResult(BaseModel):
    port: int
    status: str
    service_guess: Optional[str] = None


class PortScanResponse(BaseModel):
    target: str
    results: List[PortScanResult] = Field(default_factory=list)
    duration_ms: float


# Disruptor Schemas
class DisruptorRequest(BaseModel):
    target: str
    method: str = Field(..., description="Method: syn_flood, udp_flood, icmp_flood")
    duration: int = Field(..., ge=1, le=60, description="Duration in seconds (max 60)")


class DisruptorResponse(BaseModel):
    task_id: UUID
    status: str
    message: str


# Audit Log Schemas
class AuditLogResponse(BaseModel):
    id: UUID
    timestamp: datetime
    actor: str
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    params: Optional[Dict[str, Any]]
    consent: Optional[Dict[str, Any]]
    
    class Config:
        from_attributes = True


# WebSocket Message Schemas
class WSMessage(BaseModel):
    type: str  # scan.progress, scan.result, console.log
    data: Dict[str, Any]


class ScanProgressMessage(BaseModel):
    scan_id: UUID
    percent: float
    current_target: str
    status: str


class ConsoleLogMessage(BaseModel):
    timestamp: datetime
    level: str  # INFO, WARNING, ERROR, DEBUG
    source: str
    text: str


# Authentication Schemas
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True
