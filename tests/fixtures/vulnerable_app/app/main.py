"""Main FastAPI app. (Intentionally vulnerable fixture.)"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import admin, auth, users

# TLX-F005: debug=True · TLX-F006: docs left enabled (Dockerfile present)
app = FastAPI(title="Vibe Todo API", debug=True)

# TLX-F003: CORS wildcard origin combined with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(users.router)
app.include_router(admin.router)
app.include_router(auth.router)


@app.get("/")
def read_root():
    return {"status": "ok"}


if __name__ == "__main__":
    # TLX-I002: binds all interfaces with no auth anywhere in the project
    uvicorn.run(app, host="0.0.0.0", port=8000)
