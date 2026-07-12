import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # MongoDB
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/hexaguard")

    # JWT
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = False  # Tokens don't expire during dev — tighten in prod

    # Scraper auth token (Bearer token used by crawler scripts)
    SCRAPER_API_TOKEN = os.getenv("SCRAPER_API_TOKEN", "scraper-dev-token")

    # CORS — accept both common Vite dev ports
    _origin_env = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    FRONTEND_ORIGIN = [o.strip() for o in _origin_env.split(",")]

    # Email SMTP settings
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
