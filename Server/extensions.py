"""
Shared Flask extensions — initialized here and registered in app.py
to avoid circular imports.
"""
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

mongo = PyMongo()
jwt = JWTManager()
socketio = SocketIO(cors_allowed_origins="*", async_mode="eventlet")
