"""Secondary internal service. (Intentionally vulnerable fixture.)"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

metrics_app = FastAPI(title="Internal Metrics")

# TLX-F004: CORS wildcard origin (without credentials)
metrics_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
)


@metrics_app.get("/metrics")
def metrics():
    return {"uptime": 123}
