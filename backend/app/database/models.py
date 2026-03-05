from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    ip = Column(String(50), nullable=False, unique=True)
    type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default='在线')
    risk_level = Column(String(20), nullable=False, default='低')
    last_scan = Column(DateTime, default=datetime.datetime.utcnow)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Threat(Base):
    __tablename__ = 'threats'
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default='未处理')
    source = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    detected_at = Column(DateTime, default=datetime.datetime.utcnow)
    handled_at = Column(DateTime, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default='未修复')
    asset_id = Column(Integer, ForeignKey('assets.id'), nullable=True)
    cvss = Column(Float, nullable=False)
    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)
    due_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    asset = relationship('Asset')

class ThreatIntelligence(Base):
    __tablename__ = 'threat_intelligence'
    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), unique=True, nullable=False)
    indicator_type = Column(String(50), nullable=False)  # ip, domain, hash, url
    threat_type = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(100), nullable=False)  # microstep, local
    confidence = Column(Float, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    reference = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class DefenseRule(Base):
    __tablename__ = 'defense_rules'
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default='启用')
    priority = Column(String(20), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)