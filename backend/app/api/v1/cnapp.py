"""
CyberFusion XDR Enterprise - CNAPP Cloud Security Posture APIs
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Dict, Any, List
from app.core.database import get_db
from app.models.models import CNAPPFinding

router = APIRouter()

SEED_CNAPP_FINDINGS = [
    {
        "cloud_provider": "AWS",
        "account_id": "112233445566",
        "resource_id": "arn:aws:s3:::enterprise-finance-records-prod",
        "resource_type": "S3_BUCKET",
        "finding_title": "S3 Bucket Public Read/Write ACL Enabled",
        "severity": "CRITICAL",
        "compliance_framework": "CIS AWS Benchmark 2.1.5",
        "remediation_command": "aws s3api put-public-access-block --bucket enterprise-finance-records-prod --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "status": "ACTIVE"
    },
    {
        "cloud_provider": "AZURE",
        "account_id": "sub-prod-eastus-01",
        "resource_id": "/subscriptions/sub-prod-eastus-01/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-db-prod",
        "resource_type": "NETWORK_SECURITY_GROUP",
        "finding_title": "Port 3389 (RDP) Exposed to 0.0.0.0/0",
        "severity": "HIGH",
        "compliance_framework": "CIS Azure Benchmark 6.1",
        "remediation_command": "az network nsg rule delete --name Allow-RDP-All --nsg-name nsg-db-prod --resource-group prod-rg",
        "status": "ACTIVE"
    },
    {
        "cloud_provider": "GCP",
        "account_id": "corp-analytics-gcp-99",
        "resource_id": "//iam.googleapis.com/projects/corp-analytics-gcp-99/serviceAccounts/compute-engine-sa",
        "resource_type": "SERVICE_ACCOUNT",
        "finding_title": "Service Account Granted Owner Privilege (Excessive IAM)",
        "severity": "HIGH",
        "compliance_framework": "CIS GCP Benchmark 1.4",
        "remediation_command": "gcloud projects remove-iam-policy-binding corp-analytics-gcp-99 --member='serviceAccount:compute-engine-sa@corp.iam.gserviceaccount.com' --role='roles/owner'",
        "status": "ACTIVE"
    }
]

@router.get("/findings")
async def list_cnapp_findings(db: AsyncSession = Depends(get_db)):
    """List cloud security posture and misconfiguration findings."""
    stmt = select(CNAPPFinding)
    res = await db.execute(stmt)
    records = res.scalars().all()
    
    if not records:
        return SEED_CNAPP_FINDINGS

    return [{
        "id": r.id,
        "cloud_provider": r.cloud_provider,
        "account_id": r.account_id,
        "resource_id": r.resource_id,
        "resource_type": r.resource_type,
        "finding_title": r.finding_title,
        "severity": r.severity,
        "compliance_framework": r.compliance_framework,
        "remediation_command": r.remediation_command,
        "status": r.status,
        "detected_at": r.detected_at
    } for r in records]
