from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import os

client = None
db = None

def connect_db(app):
    global client, db

    try:
        client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        db = client["CVE_DB"]
        print("✅ MongoDB Connected — Database: CVE_DB")
        app.db = db
    except ConnectionFailure as e:
        print(f"❌ MongoDB Connection Failed: {e}")
        raise SystemExit(1)

def get_db():
    return db
