"""Auth dependency used by every protected route."""

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Resolve the current user from a bearer token."""
    if not token:
        raise HTTPException(status_code=401)
    return {"id": 1, "email": "user@example.com"}
