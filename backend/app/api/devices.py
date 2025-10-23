from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.models import Device, User, Vulnerability, DeviceVulnerability
from app.schemas import DeviceResponse, DeviceDetail
from app.api.auth import get_current_user

router = APIRouter()


@router.get("/devices", response_model=List[DeviceResponse])
async def list_devices(
    scan_id: Optional[UUID] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    
):
    """List devices discovered in scans"""
    query = select(Device).order_by(Device.last_seen.desc()).limit(limit).offset(offset)
    
    if scan_id:
        query = query.where(Device.scan_id == scan_id)
    
    result = await db.execute(query)
    devices = result.scalars().all()
    
    return devices


@router.get("/device/{device_id}", response_model=DeviceDetail)
async def get_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    
):
    """Get detailed device information including vulnerabilities"""
    result = await db.execute(
        select(Device)
        .where(Device.id == device_id)
        .options(selectinload(Device.vulnerabilities))
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    # Format response
    device_dict = {
        "id": device.id,
        "scan_id": device.scan_id,
        "ip": device.ip,
        "hostname": device.hostname,
        "os_guess": device.os_guess,
        "vendor": device.vendor,
        "mac_address": device.mac_address,
        "open_ports": device.open_ports,
        "last_seen": device.last_seen,
        "risk_score": device.risk_score,
        "vulnerabilities": [
            {
                "id": v.id,
                "cve": v.cve,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "summary": v.summary,
                "description": v.description,
                "references": v.references,
                "published_date": v.published_date,
                "first_seen": v.first_seen,
            }
            for v in device.vulnerabilities
        ]
    }
    
    return device_dict
