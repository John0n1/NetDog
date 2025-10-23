from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.models import Vulnerability, Device, DeviceVulnerability, User
from app.schemas import VulnerabilityResponse, VulnerabilityWithDevices
from app.api.auth import get_current_user

router = APIRouter()


@router.get("/vulns", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    device_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    
):
    """List vulnerabilities"""
    query = select(Vulnerability).order_by(Vulnerability.first_seen.desc()).limit(limit).offset(offset)
    
    if device_id:
        query = (
            query
            .join(DeviceVulnerability)
            .where(DeviceVulnerability.device_id == device_id)
        )
    
    if severity:
        query = query.where(Vulnerability.severity == severity.upper())
    
    result = await db.execute(query)
    vulns = result.scalars().unique().all()
    
    return vulns


@router.get("/vuln/{vuln_id}", response_model=VulnerabilityWithDevices)
async def get_vulnerability(
    vuln_id: UUID,
    db: AsyncSession = Depends(get_db),
    
):
    """Get vulnerability details with affected devices"""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    # Get affected devices
    device_result = await db.execute(
        select(Device.id)
        .join(DeviceVulnerability)
        .where(DeviceVulnerability.vulnerability_id == vuln_id)
    )
    affected_devices = [row[0] for row in device_result.all()]
    
    return {
        "id": vuln.id,
        "cve": vuln.cve,
        "severity": vuln.severity,
        "cvss_score": vuln.cvss_score,
        "summary": vuln.summary,
        "description": vuln.description,
        "references": vuln.references,
        "published_date": vuln.published_date,
        "first_seen": vuln.first_seen,
        "affected_devices": affected_devices,
    }


@router.get("/vulns/stats")
async def get_vulnerability_stats(
    db: AsyncSession = Depends(get_db),
    
):
    """Get vulnerability statistics"""
    from sqlalchemy import func
    
    result = await db.execute(
        select(
            Vulnerability.severity,
            func.count(Vulnerability.id).label("count")
        )
        .group_by(Vulnerability.severity)
    )
    
    stats = {row[0]: row[1] for row in result.all()}
    
    return {
        "critical": stats.get("CRITICAL", 0),
        "high": stats.get("HIGH", 0),
        "medium": stats.get("MEDIUM", 0),
        "low": stats.get("LOW", 0),
        "total": sum(stats.values()),
    }
