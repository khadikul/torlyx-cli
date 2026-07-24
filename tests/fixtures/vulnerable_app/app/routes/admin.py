"""Admin routes. (Intentionally vulnerable fixture.)"""

from fastapi import APIRouter

router = APIRouter()


# TLX-F002: admin route with no auth dependency
@router.get("/admin/stats")
def admin_stats():
    return {"users": 42, "revenue": 1337}
