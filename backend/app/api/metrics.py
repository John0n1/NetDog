from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Device, Scan, Vulnerability
from app.schemas import DashboardOverview, RiskBreakdown


router = APIRouter()


@router.get("/metrics/overview", response_model=DashboardOverview)
async def get_dashboard_overview(
    db: AsyncSession = Depends(get_db),
):
    """Return aggregate metrics for the dashboard view."""

    # Scan statistics
    total_scans = await db.scalar(select(func.count(Scan.id))) or 0
    active_scans = (
        await db.scalar(
            select(func.count(Scan.id)).where(
                Scan.status.in_(["queued", "running", "discovering", "profiling"])
            )
        )
        or 0
    )
    completed_scans = (
        await db.scalar(select(func.count(Scan.id)).where(Scan.status == "done"))
        or 0
    )

    latest_scan_stmt = select(Scan).order_by(Scan.started_at.desc()).limit(1)
    latest_scan_result = await db.execute(latest_scan_stmt)
    latest_scan: Optional[Scan] = latest_scan_result.scalar_one_or_none()

    # Device statistics
    total_devices = await db.scalar(select(func.count(Device.id))) or 0
    high_risk_devices = (
        await db.scalar(
            select(func.count(Device.id)).where(Device.risk_score >= 7.0)
        )
        or 0
    )
    average_risk = await db.scalar(select(func.avg(Device.risk_score)))
    if average_risk is not None:
        average_risk = round(float(average_risk), 2)

    last_24h = datetime.utcnow() - timedelta(hours=24)
    new_devices_24h = (
        await db.scalar(
            select(func.count(Device.id)).where(Device.last_seen >= last_24h)
        )
        or 0
    )

    # Risk distribution (evaluated in Python for clarity and portability)
    risk_scores_result = await db.execute(select(Device.risk_score))
    risk_counts = RiskBreakdown().model_dump()
    for (risk_score,) in risk_scores_result:
        if risk_score is None:
            risk_counts["unknown"] += 1
        elif risk_score >= 9:
            risk_counts["critical"] += 1
        elif risk_score >= 7:
            risk_counts["high"] += 1
        elif risk_score >= 4:
            risk_counts["medium"] += 1
        elif risk_score > 0:
            risk_counts["low"] += 1
        else:
            risk_counts["unknown"] += 1

    risk_distribution = RiskBreakdown(**risk_counts)

    # Vulnerability statistics
    critical_vulns = (
        await db.scalar(
            select(func.count(Vulnerability.id)).where(
                func.upper(Vulnerability.severity) == "CRITICAL"
            )
        )
        or 0
    )

    return DashboardOverview(
        total_scans=total_scans,
        active_scans=active_scans,
        completed_scans=completed_scans,
        total_devices=total_devices,
        new_devices_24h=new_devices_24h,
        high_risk_devices=high_risk_devices,
        critical_vulnerabilities=critical_vulns,
        average_risk_score=average_risk,
        risk_distribution=risk_distribution,
        recent_scan=latest_scan,
        last_updated=datetime.utcnow(),
    )
