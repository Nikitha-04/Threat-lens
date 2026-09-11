from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
import os

Base = declarative_base()
CACHE_TTL_HOURS = 24


class UrlReputation(Base):
    __tablename__ = "url_reputation"

    id = Column(Integer, primary_key=True)
    url = Column(Text, nullable=False, index=True)
    safe_browsing_flagged = Column(Boolean, default=False)
    safe_browsing_threat_types = Column(Text, default="")   # JSON-encoded list
    virustotal_malicious_count = Column(Integer)
    virustotal_suspicious_count = Column(Integer)
    virustotal_total_vendors = Column(Integer)
    checked_at = Column(DateTime, nullable=False)


class FileReputation(Base):
    __tablename__ = "file_reputation"

    id = Column(Integer, primary_key=True)
    sha256 = Column(String(64), nullable=False, index=True, unique=True)
    virustotal_malicious_count = Column(Integer)
    virustotal_total_vendors = Column(Integer)
    known_to_virustotal = Column(Boolean, default=False)
    checked_at = Column(DateTime, nullable=False)


class ReputationCache:
    def __init__(self, db_path="./data/db/threat_platform.db"):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.engine = create_engine(f"sqlite:///{os.path.abspath(db_path)}")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def _now(self) -> datetime:
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def _is_fresh(self, checked_at: datetime) -> bool:
        age = self._now() - checked_at
        return age < timedelta(hours=CACHE_TTL_HOURS)

    # ── URL cache ─────────────────────────────────────────────────────────────

    def get_url(self, url: str) -> UrlReputation | None:
        session = self.Session()
        try:
            row = (
                session.query(UrlReputation)
                .filter(UrlReputation.url == url)
                .order_by(UrlReputation.checked_at.desc())
                .first()
            )
            if row and self._is_fresh(row.checked_at):
                session.expunge(row)
                return row
            return None
        finally:
            session.close()

    def set_url(self, url: str, sb_flagged: bool, sb_threats: list,
                vt_malicious: int | None, vt_suspicious: int | None,
                vt_total: int | None) -> None:
        import json
        session = self.Session()
        try:
            row = UrlReputation(
                url=url,
                safe_browsing_flagged=sb_flagged,
                safe_browsing_threat_types=json.dumps(sb_threats),
                virustotal_malicious_count=vt_malicious,
                virustotal_suspicious_count=vt_suspicious,
                virustotal_total_vendors=vt_total,
                checked_at=self._now(),
            )
            session.add(row)
            session.commit()
        finally:
            session.close()

    # ── File cache ────────────────────────────────────────────────────────────

    def get_file(self, sha256: str) -> FileReputation | None:
        session = self.Session()
        try:
            row = session.query(FileReputation).filter(FileReputation.sha256 == sha256).first()
            if row and self._is_fresh(row.checked_at):
                session.expunge(row)
                return row
            return None
        finally:
            session.close()

    def set_file(self, sha256: str, vt_malicious: int | None,
                 vt_total: int | None, known: bool) -> None:
        session = self.Session()
        try:
            row = session.query(FileReputation).filter(FileReputation.sha256 == sha256).first()
            if row:
                row.virustotal_malicious_count = vt_malicious
                row.virustotal_total_vendors = vt_total
                row.known_to_virustotal = known
                row.checked_at = self._now()
            else:
                row = FileReputation(
                    sha256=sha256,
                    virustotal_malicious_count=vt_malicious,
                    virustotal_total_vendors=vt_total,
                    known_to_virustotal=known,
                    checked_at=self._now(),
                )
                session.add(row)
            session.commit()
        finally:
            session.close()
