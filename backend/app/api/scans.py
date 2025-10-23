from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID
import uuid
from datetime import datetime

from app.database import get_db
from app.models import Scan, User, AuditLog
from app.schemas import ScanCreate, ScanResponse, ScanStatus, ScanListItem
from app.tasks import nmap_scan
from app.api.auth import get_current_user

router = APIRouter()


def get_optional_user(token: Optional[str] = None) -> Optional[User]:
    """Get current user if token provided, otherwise return None"""
    if not token:
        return None
    try:
        from app.api.auth import decode_token
        return decode_token(token)
    except:
        return None


async def create_audit_log(
    db: AsyncSession,
    actor: str,
    action: str,
    scan_id: Optional[UUID] = None,
    params: Optional[dict] = None,
    consent: Optional[dict] = None,
    request: Optional[Request] = None,
):
    """Create audit log entry"""
    log = AuditLog(
        id=uuid.uuid4(),
        actor=actor,
        action=action,
        resource_type="scan",
        resource_id=str(scan_id) if scan_id else None,
        params=params,
        consent=consent,
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get("user-agent") if request else None,
        scan_id=scan_id,
    )
    db.add(log)
    await db.flush()
    return log


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Start a new network scan - NO AUTH REQUIRED"""
    
    # Validate consent
    if not scan_data.consent.approved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan consent required"
        )
    
    # Create scan record
    scan = Scan(
        id=uuid.uuid4(),
        targets=scan_data.targets,
        mode=scan_data.mode,
        status="queued",
    )
    db.add(scan)
    await db.flush()
    
    # Create audit log
    await create_audit_log(
        db,
        actor=scan_data.consent.by or "anonymous",
        action="start_scan",
        scan_id=scan.id,
        params={
            "targets": scan_data.targets,
            "mode": scan_data.mode,
            "options": scan_data.options,
        },
        consent=scan_data.consent.model_dump(),
        request=request,
    )
    
    await db.commit()
    
    # Queue scan task
    nmap_scan.delay(
        scan_id=str(scan.id),
        targets=scan_data.targets,
        mode=scan_data.mode,
        options=scan_data.options,
    )
    
    return {"scan_id": scan.id}


@router.get("/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get scan status and progress - NO AUTH REQUIRED"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return scan


@router.get("/scans", response_model=List[ScanListItem])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all scans - NO AUTH REQUIRED"""
    query = select(Scan).order_by(Scan.started_at.desc()).limit(limit).offset(offset)
    
    if status_filter:
        query = query.where(Scan.status == status_filter)
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    return scans


@router.delete("/scan/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and all associated data - NO AUTH REQUIRED"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Create audit log
    await create_audit_log(
        db,
        actor="user",
        action="delete_scan",
        scan_id=scan.id,
        request=request,
    )
    
    await db.delete(scan)
    await db.commit()
    
    return None
