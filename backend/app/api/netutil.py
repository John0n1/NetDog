from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.database import get_db
from app.schemas import (
    PingRequest, PingResponse,
    SpeedTestRequest, SpeedTestResponse,
    DNSLookupResponse,
    TracerouteRequest, TracerouteResponse, TracerouteHop,
    PortScanRequest, PortScanResponse, PortScanResult,
    DisruptorRequest, DisruptorResponse
)
from app.tasks import ping_task, speedtest_task, disruptor_task
from app.api.scans import create_audit_log
from datetime import datetime
import uuid
import socket
import subprocess
import time
import re

router = APIRouter()


@router.post("/ping", response_model=PingResponse)
async def ping(
    ping_data: PingRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Execute ping test - NO AUTH REQUIRED"""
    
    # Validate consent
    if not ping_data.consent.approved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation consent required"
        )
    
    # Create audit log
    await create_audit_log(
        db,
        actor=ping_data.consent.by or "anonymous",
        action="ping",
        params={"target": ping_data.target, "count": ping_data.count},
        consent=ping_data.consent.model_dump(),
        request=request,
    )
    await db.commit()
    
    # Execute ping
    result = ping_task.delay(ping_data.target, ping_data.count)
    ping_result = result.get(timeout=30)
    
    if "error" in ping_result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ping_result["error"]
        )
    
    return ping_result


@router.post("/speedtest", response_model=SpeedTestResponse)
async def speedtest(
    speedtest_data: SpeedTestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Execute speed test - NO AUTH REQUIRED"""
    
    # Validate consent
    if not speedtest_data.consent.approved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation consent required"
        )
    
    # Create audit log
    await create_audit_log(
        db,
        actor=speedtest_data.consent.by or "anonymous",
        action="speedtest",
        consent=speedtest_data.consent.model_dump(),
        request=request,
    )
    await db.commit()
    
    # Execute speedtest
    result = speedtest_task.delay()
    speedtest_result = result.get(timeout=90)
    
    if "error" in speedtest_result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=speedtest_result["error"]
        )
    
    return speedtest_result


@router.post("/traceroute", response_model=TracerouteResponse)
async def traceroute(
    traceroute_data: TracerouteRequest,
):
    """Execute traceroute using system traceroute utility"""
    command = [
        "traceroute",
        "-n",
        "-m",
        str(traceroute_data.max_hops),
        "-q",
        str(traceroute_data.attempts),
        traceroute_data.target,
    ]
    hops: List[TracerouteHop] = []
    completed = False
    try:
        timeout = traceroute_data.max_hops * 3
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.splitlines()
        hop_pattern = re.compile(r"^\s*(\d+)\s+([\w\-.*:]+)(?:\s+\(([^)]+)\))?(.*)$")
        for line in output:
            line = line.strip()
            if not line or line.lower().startswith("traceroute"):
                continue
            match = hop_pattern.match(line)
            if not match:
                continue
            hop_number = int(match.group(1))
            host_field = match.group(2)
            ip_field = match.group(3) or (host_field if re.match(r"^[\d:.]+$", host_field) else None)
            remaining = match.group(4)
            rtts = re.findall(r"([\d.]+)\s*ms", remaining)
            avg_rtt = float(sum(map(float, rtts)) / len(rtts)) if rtts else None
            host_display = host_field if host_field != "*" else "*"
            hops.append(TracerouteHop(
                hop=hop_number,
                host=host_display,
                ip=ip_field,
                rtt_ms=avg_rtt,
            ))
            if ip_field and traceroute_data.target in {ip_field, host_display}:
                completed = True
        if not completed and hops:
            last_ip = hops[-1].ip
            completed = bool(last_ip and last_ip == traceroute_data.target)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="traceroute command not available on server"
        )
    except subprocess.TimeoutExpired as exc:
        partial_output = exc.stdout.decode() if exc.stdout else ""
        error_output = exc.stderr.decode() if exc.stderr else ""
        combined = (partial_output + "\n" + error_output).splitlines()
        hop_pattern = re.compile(r"^\s*(\d+)\s+([\w\-.*:]+)(?:\s+\(([^)]+)\))?(.*)$")
        for line in combined:
            line = line.strip()
            if not line or line.lower().startswith("traceroute"):
                continue
            match = hop_pattern.match(line)
            if not match:
                continue
            hop_number = int(match.group(1))
            host_field = match.group(2)
            ip_field = match.group(3) or (host_field if re.match(r"^[\d:.]+$", host_field) else None)
            hops.append(TracerouteHop(hop=hop_number, host=host_field, ip=ip_field, rtt_ms=None))
        completed = False
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Traceroute failed: {str(e)}"
        )

    return TracerouteResponse(target=traceroute_data.target, hops=hops, completed=completed)


@router.post("/dns-lookup", response_model=DNSLookupResponse)
async def dns_lookup(
    hostname: str,
):
    """Perform DNS lookup with additional metadata"""
    try:
        canonical_name = socket.getfqdn(hostname)
        host_entry = socket.gethostbyname_ex(hostname)
        aliases = sorted(set(host_entry[1]))
        ipv4_addresses = sorted(set([ip for ip in host_entry[2] if "." in ip]))
    except socket.gaierror as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DNS lookup failed: {str(e)}"
        )

    ipv6_addresses: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for info in addr_info:
            family, _, _, _, sockaddr = info
            ip_addr = sockaddr[0]
            if family == socket.AF_INET6 and ip_addr not in ipv6_addresses:
                ipv6_addresses.append(ip_addr)
    except socket.gaierror:
        pass

    reverse_dns = None
    primary_ip = ipv4_addresses[0] if ipv4_addresses else (ipv6_addresses[0] if ipv6_addresses else None)
    if primary_ip:
        try:
            reverse_dns = socket.gethostbyaddr(primary_ip)[0]
        except (socket.herror, socket.gaierror):
            reverse_dns = None

    name_servers: List[str] = []
    try:
        dig_proc = subprocess.run(
            ["dig", "+short", "NS", hostname],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if dig_proc.returncode == 0 and dig_proc.stdout.strip():
            for line in dig_proc.stdout.splitlines():
                entry = line.strip().rstrip('.')
                if entry:
                    name_servers.append(entry)
    except FileNotFoundError:
        try:
            nslookup_proc = subprocess.run(
                ["nslookup", "-type=ns", hostname],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if nslookup_proc.returncode == 0:
                for line in nslookup_proc.stdout.splitlines():
                    if "nameserver" in line.lower():
                        entry = line.split("=")[-1].strip()
                        if entry:
                            name_servers.append(entry)
        except FileNotFoundError:
            name_servers = []
    except subprocess.TimeoutExpired:
        name_servers = []

    return DNSLookupResponse(
        hostname=hostname,
        canonical_name=canonical_name,
        aliases=aliases,
        ipv4_addresses=ipv4_addresses,
        ipv6_addresses=ipv6_addresses,
        reverse_dns=reverse_dns,
        name_servers=sorted(set(name_servers)),
        resolved_at=datetime.utcnow(),
    )


@router.get("/my-network")
async def get_my_network(
    
):
    """Get the user's local network information"""
    import socket
    import ipaddress
    
    try:
        # Get the local IP address by connecting to a public IP (doesn't actually send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Determine the network based on IP
        ip_obj = ipaddress.ip_address(local_ip)
        
        # Guess the subnet based on private network ranges
        if local_ip.startswith("192.168."):
            network = f"{'.'.join(local_ip.split('.')[:3])}.0/24"
        elif local_ip.startswith("10."):
            network = f"{'.'.join(local_ip.split('.')[:3])}.0/24"
        elif local_ip.startswith("172."):
            second_octet = int(local_ip.split('.')[1])
            if 16 <= second_octet <= 31:
                network = f"{'.'.join(local_ip.split('.')[:3])}.0/24"
            else:
                network = f"{local_ip}/32"
        else:
            network = f"{local_ip}/32"
        
        return {
            "local_ip": local_ip,
            "suggested_network": network,
        }
    except Exception as e:
        return {
            "local_ip": "127.0.0.1",
            "suggested_network": "192.168.1.0/24",
            "error": str(e)
        }


@router.post("/disruptor", response_model=DisruptorResponse)
async def disruptor(
    disruptor_data: DisruptorRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Execute network disruptor test - NO AUTH REQUIRED BUT REQUIRES CONSENT"""
    
    # Validate consent
    if not disruptor_data.consent.approved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation consent required - you must have authorization"
        )
    
    # Create audit log with all details
    await create_audit_log(
        db,
        actor=disruptor_data.consent.by or "anonymous",
        action="disruptor",
        params={
            "target": disruptor_data.target,
            "method": disruptor_data.method,
            "duration": disruptor_data.duration,
        },
        consent=disruptor_data.consent.model_dump(),
        request=request,
    )
    await db.commit()
    
    # Execute disruptor task and wait for result
    result = disruptor_task.delay(
        disruptor_data.target,
        disruptor_data.method,
        disruptor_data.duration
    )
    
    # Wait for task to complete (with timeout)
    try:
        task_result = result.get(timeout=disruptor_data.duration + 10)
        
        if "error" in task_result or task_result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=task_result.get("error") or task_result.get("message", "Disruptor test failed")
            )
        
        return {
            "task_id": uuid.uuid4(),
            "status": task_result.get("status", "completed"),
            "message": task_result.get("message", f"Test completed for {disruptor_data.target}"),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/port-scan", response_model=PortScanResponse)
async def port_scan(scan_request: PortScanRequest):
    """Perform a lightweight TCP port scan"""
    ports = sorted(set(scan_request.ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443]))
    timeout = scan_request.timeout
    start = time.perf_counter()
    results: List[PortScanResult] = []

    service_map = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3389: "rdp",
        8080: "http-alt",
        8443: "https-alt",
    }

    for port in ports:
        status = "closed"
        try:
            with socket.create_connection((scan_request.target, port), timeout=timeout):
                status = "open"
        except socket.gaierror as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid target: {str(e)}"
            )
        except socket.timeout:
            status = "filtered"
        except ConnectionRefusedError:
            status = "closed"
        except OSError:
            status = "error"
        except Exception:
            status = "error"
        results.append(PortScanResult(
            port=port,
            status=status,
            service_guess=service_map.get(port)
        ))

    duration_ms = (time.perf_counter() - start) * 1000
    return PortScanResponse(target=scan_request.target, results=results, duration_ms=duration_ms)
