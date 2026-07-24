"""User routes. (Intentionally vulnerable fixture.)"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class UserOut(BaseModel):
    id: int
    email: str
    password: str  # TLX-F007: sensitive field in a response model


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int):
    return {"id": user_id, "email": "a@b.co", "password": "hunter2"}


# TLX-F001: state-changing route with no auth dependency
@router.delete("/users/{user_id}")
def delete_user(user_id: int):
    return {"deleted": user_id}
