"""
SQLite Persistence Layer for Analysis Sessions.
Stores completed AnalysisSessionResult objects on disk so history and
side-by-side comparisons persist across backend restarts.
"""

import os
import sqlite3
from contextlib import closing
from typing import List, Optional
from backend.app.schemas.models import AnalysisSessionResult, SessionSummary


class SessionStore:
    """Lightweight SQLite store for IPsec analysis session history."""

    def __init__(self, db_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self.db_path = db_path or os.path.join(base_dir, "datasets", "sessions.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    pcap_filename TEXT NOT NULL,
                    overall_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save(self, result: AnalysisSessionResult) -> None:
        payload_json = result.model_dump_json()
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (session_id, timestamp, pcap_filename, overall_score, risk_level, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.session_id,
                    result.timestamp.isoformat(),
                    result.pcap_filename,
                    result.score_breakdown.overall_score,
                    result.score_breakdown.risk_level.value,
                    payload_json,
                ),
            )
            conn.commit()

    def get(self, session_id: str) -> Optional[AnalysisSessionResult]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT payload_json FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if not row:
            return None
        return AnalysisSessionResult.model_validate_json(row[0])

    def list_summaries(self, limit: int = 30) -> List[SessionSummary]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT payload_json FROM sessions ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()

        summaries: List[SessionSummary] = []
        for (payload_json,) in rows:
            res = AnalysisSessionResult.model_validate_json(payload_json)
            summaries.append(SessionSummary(
                session_id=res.session_id,
                timestamp=res.timestamp,
                pcap_filename=res.pcap_filename,
                overall_score=res.score_breakdown.overall_score,
                risk_level=res.score_breakdown.risk_level,
                ike_version=res.security_association.ike_version.value,
                encryption_algorithm=res.security_association.encryption_algorithm,
                mode=res.security_association.mode.value,
                total_packets_parsed=res.total_packets_parsed,
                threat_count=len(res.threat_matrix),
            ))
        return summaries

    def delete(self, session_id: str) -> bool:
        with closing(sqlite3.connect(self.db_path)) as conn:
            cur = conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            return cur.rowcount > 0
