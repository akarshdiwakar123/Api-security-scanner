from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_pw = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    # SaaS/Billing specific fields
    stripe_customer_id = Column(String, unique=True, index=True, nullable=True)
    subscription_status = Column(String, default="free")
    subscription_end_date = Column(DateTime, nullable=True)
    api_usage_current_month = Column(Integer, default=0)

    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    total = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    
    # Task specific fields
    status = Column(String, default="completed") # pending, processing, completed, failed
    task_id = Column(String, nullable=True) # Celery task ID

    owner = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    description = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")
