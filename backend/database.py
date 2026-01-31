"""
Database models and setup for AI-DLP System.
Uses SQLite with SQLAlchemy ORM for persistence.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

# Database setup
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "data" / "dlp.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# Models
class Alert(Base):
    """Alert/Event model for storing DLP detection events."""
    
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    input_text = Column(Text, nullable=False)
    classification = Column(String(50), nullable=False)
    risk_level = Column(String(20), nullable=False)
    action = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False)
    reasons = Column(Text, nullable=False)  # JSON array
    source = Column(String(100), default="api", nullable=False)
    policy_id = Column(Integer, nullable=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "input_text": self.input_text,
            "classification": self.classification,
            "risk_level": self.risk_level,
            "action": self.action,
            "risk_score": self.risk_score,
            "reasons": json.loads(self.reasons) if isinstance(self.reasons, str) else self.reasons,
            "source": self.source,
            "policy_id": self.policy_id,
        }


class Policy(Base):
    """Policy model for storing custom DLP policies."""
    
    __tablename__ = "policies"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=0, nullable=False)
    rules = Column(Text, nullable=False)  # JSON object
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "rules": json.loads(self.rules) if isinstance(self.rules, str) else self.rules,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FileScan(Base):
    """FileScan model for tracking file scans."""
    
    __tablename__ = "file_scans"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    file_path = Column(String(500), nullable=False)
    scan_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    file_size = Column(Integer, nullable=True)
    findings_count = Column(Integer, default=0, nullable=False)
    highest_risk = Column(String(20), nullable=True)
    status = Column(String(20), default="completed", nullable=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "file_path": self.file_path,
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "file_size": self.file_size,
            "findings_count": self.findings_count,
            "highest_risk": self.highest_risk,
            "status": self.status,
        }


# Database initialization
def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# CRUD operations
def create_alert(db: Session, alert_data: Dict[str, Any]) -> Alert:
    """Create a new alert."""
    alert = Alert(
        input_text=alert_data.get("input", ""),
        classification=alert_data.get("classification", "SAFE"),
        risk_level=alert_data.get("risk_level", "LOW"),
        action=alert_data.get("action", "ALLOWED"),
        risk_score=alert_data.get("risk_score", 0),
        reasons=json.dumps(alert_data.get("reasons", [])),
        source=alert_data.get("source", "api"),
        policy_id=alert_data.get("policy_id"),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alerts(db: Session, skip: int = 0, limit: int = 100, risk_level: Optional[str] = None) -> List[Alert]:
    """Get alerts with optional filtering."""
    query = db.query(Alert)
    if risk_level:
        query = query.filter(Alert.risk_level == risk_level)
    return query.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()


def create_policy(db: Session, policy_data: Dict[str, Any]) -> Policy:
    """Create a new policy."""
    policy = Policy(
        name=policy_data["name"],
        description=policy_data.get("description"),
        enabled=policy_data.get("enabled", True),
        priority=policy_data.get("priority", 0),
        rules=json.dumps(policy_data.get("rules", {})),
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


def get_policies(db: Session, enabled_only: bool = False) -> List[Policy]:
    """Get all policies."""
    query = db.query(Policy)
    if enabled_only:
        query = query.filter(Policy.enabled == True)
    return query.order_by(Policy.priority.desc()).all()


def get_policy(db: Session, policy_id: int) -> Optional[Policy]:
    """Get a specific policy by ID."""
    return db.query(Policy).filter(Policy.id == policy_id).first()


def update_policy(db: Session, policy_id: int, policy_data: Dict[str, Any]) -> Optional[Policy]:
    """Update a policy."""
    policy = get_policy(db, policy_id)
    if not policy:
        return None
    
    for key, value in policy_data.items():
        if key == "rules":
            value = json.dumps(value)
        if hasattr(policy, key):
            setattr(policy, key, value)
    
    policy.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(policy)
    return policy


def delete_policy(db: Session, policy_id: int) -> bool:
    """Delete a policy."""
    policy = get_policy(db, policy_id)
    if not policy:
        return False
    db.delete(policy)
    db.commit()
    return True


def create_file_scan(db: Session, scan_data: Dict[str, Any]) -> FileScan:
    """Create a new file scan record."""
    scan = FileScan(
        file_path=scan_data["file_path"],
        file_size=scan_data.get("file_size"),
        findings_count=scan_data.get("findings_count", 0),
        highest_risk=scan_data.get("highest_risk"),
        status=scan_data.get("status", "completed"),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_file_scans(db: Session, skip: int = 0, limit: int = 100) -> List[FileScan]:
    """Get file scans."""
    return db.query(FileScan).order_by(FileScan.scan_time.desc()).offset(skip).limit(limit).all()


# Analytics queries
def get_stats(db: Session) -> Dict[str, Any]:
    """Get overall statistics."""
    total_alerts = db.query(Alert).count()
    high_risk = db.query(Alert).filter(Alert.risk_level == "HIGH").count()
    medium_risk = db.query(Alert).filter(Alert.risk_level == "MEDIUM").count()
    low_risk = db.query(Alert).filter(Alert.risk_level == "LOW").count()
    
    total_scans = db.query(FileScan).count()
    total_policies = db.query(Policy).filter(Policy.enabled == True).count()
    
    return {
        "total_alerts": total_alerts,
        "high_risk_alerts": high_risk,
        "medium_risk_alerts": medium_risk,
        "low_risk_alerts": low_risk,
        "total_file_scans": total_scans,
        "active_policies": total_policies,
    }
