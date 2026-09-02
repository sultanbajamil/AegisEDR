import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

DATABASE_URL = "sqlite:///./aegis_edr.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Agent(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, index=True) # GUID sent by Agent
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    os_version = Column(String, nullable=True)
    status = Column(String, default="Active") # Active, Inactive
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    registered_at = Column(DateTime, default=datetime.datetime.utcnow)

    alerts = relationship("Alert", back_populates="agent", cascade="all, delete-orphan")
    commands = relationship("Command", back_populates="agent", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    alert_type = Column(String, nullable=False) # PROCESS, REGISTRY, FILE, NETWORK
    severity = Column(String, nullable=False) # INFO, WARNING, CRITICAL
    description = Column(String, nullable=False)
    details = Column(String, nullable=True) # JSON string
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    resolved = Column(Boolean, default=False)

    agent = relationship("Agent", back_populates="alerts")

class Command(Base):
    __tablename__ = "commands"

    id = Column(String, primary_key=True, index=True) # GUID for command tracking
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    command_type = Column(String, nullable=False) # KILL_PROCESS, DIAGNOSTIC, ISOLATE
    arguments = Column(String, nullable=True) # e.g. process name or PID
    status = Column(String, default="PENDING") # PENDING, SENT, COMPLETED, FAILED
    result = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    executed_at = Column(DateTime, nullable=True)

    agent = relationship("Agent", back_populates="commands")

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
