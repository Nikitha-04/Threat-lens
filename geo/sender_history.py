import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class SenderHistory(Base):
    __tablename__ = 'sender_history'
    
    id = Column(Integer, primary_key=True)
    sender_email = Column(String, index=True, nullable=False)
    ip = Column(String, nullable=False)
    country = Column(String)
    city = Column(String)
    lat = Column(Float)
    long = Column(Float)
    seen_at = Column(DateTime, default=datetime.utcnow, index=True)
    message_id = Column(String)

class Database:
    def __init__(self, db_path='./data/db/threat_platform.db'):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.engine = create_engine(f'sqlite:///{os.path.abspath(db_path)}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
    def add_history(self, sender_email, ip, country, city, lat, long, seen_at, message_id):
        session = self.Session()
        history = SenderHistory(
            sender_email=sender_email,
            ip=ip,
            country=country,
            city=city,
            lat=lat,
            long=long,
            seen_at=seen_at,
            message_id=message_id
        )
        session.add(history)
        session.commit()
        session.close()
        
    def get_latest_location(self, sender_email):
        session = self.Session()
        # Get the latest location BEFORE this one was added?
        # Typically we fetch latest, compare, then add.
        history = session.query(SenderHistory)\
            .filter(SenderHistory.sender_email == sender_email)\
            .order_by(SenderHistory.seen_at.desc())\
            .first()
        
        # Detach from session so we can return and close session
        if history:
            session.expunge(history)
        session.close()
        return history
        
    def get_history_count(self, sender_email):
        session = self.Session()
        count = session.query(SenderHistory)\
            .filter(SenderHistory.sender_email == sender_email)\
            .count()
        session.close()
        return count
