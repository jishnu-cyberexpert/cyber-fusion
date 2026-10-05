"""
CyberFusion XDR Enterprise - Authentication & Multi-Tenancy APIs
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import verify_password, hash_password, create_access_token, get_current_user_payload, Roles
from app.models.models import User, Tenant
from app.schemas.schemas import LoginRequest, TokenResponse
from typing import Dict, Any, List

router = APIRouter()

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.email == req.email)
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()
    
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials for enterprise console"
        )
    
    token = create_access_token({
        "sub": user.email,
        "role": user.role,
        "tenant_id": user.tenant_id,
        "name": user.full_name
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "tenant_id": user.tenant_id,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.full_name,
            "role": user.role,
            "tenant_id": user.tenant_id
        }
    }

@router.get("/me")
async def get_current_profile(current_user: Dict[str, Any] = Depends(get_current_user_payload)):
    return current_user

@router.get("/tenants")
async def list_tenants(db: AsyncSession = Depends(get_db)):
    stmt = select(Tenant)
    res = await db.execute(stmt)
    tenants = res.scalars().all()
    return [{"tenant_id": t.tenant_id, "name": t.name, "tier": t.tier, "eps_quota": t.eps_quota, "status": t.status} for t in tenants]
