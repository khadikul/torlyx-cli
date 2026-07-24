"""Auth routes. (Intentionally vulnerable fixture.)"""

import hashlib
import random
import string

from fastapi import APIRouter

router = APIRouter()


# Login route exists but no rate limiting anywhere → TLX-F008
@router.post("/login")
def login(email: str, password: str):
    # TLX-C005: MD5 used for password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    # TLX-C006: `random` used to mint a session token
    session_token = "".join(random.choice(string.ascii_letters) for _ in range(32))
    return {"token": session_token, "hash": password_hash}
