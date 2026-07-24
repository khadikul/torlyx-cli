"""Configuration loaded from the environment — nothing hardcoded."""

import os

SECRET_KEY = os.getenv("SECRET_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
STRIPE_KEY = os.getenv("STRIPE_KEY", "")
ALLOWED_ORIGINS = ["https://app.example.com"]
