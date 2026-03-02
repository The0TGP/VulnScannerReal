from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)   # email
    password = Column(String)
    is_verified = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)


class EmailVerification(Base):
    __tablename__ = "email_verification"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    token = Column(String)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    token = Column(String)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    target = Column(String)
    ports = Column(Text)
    headers = Column(Text)
    tls = Column(Text)
    injection = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = Column(String)  # username of who ran the scan
