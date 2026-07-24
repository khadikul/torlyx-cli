"""A small FastAPI app that gets the security basics right."""

import secrets

import uvicorn
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import ALLOWED_ORIGINS
from app.deps import get_current_user

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


class UserOut(BaseModel):
    id: int
    email: str


@app.get("/me", response_model=UserOut)
def read_me(user: dict = Depends(get_current_user)):
    return user


@app.post("/login")
def login(email: str, password: str):
    return {"access_token": secrets.token_urlsafe(32), "token_type": "bearer"}


@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int, user: dict = Depends(get_current_user)):
    return {"deleted": todo_id}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
