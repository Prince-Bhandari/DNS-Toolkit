"""DNS caching and history tracking."""
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from dataclasses import asdict
from .utils import DNSResult
class DNSCache:
    """In-memory and persistent DNS cache with history."""
    
    def __init__(
        self,
        db_path: str | Path | None = None,
        default_ttl: int = 300,
        max_memory_entries: int = 10000,
    ):
        """
        Initialize DNS cache.
        
        Args:
            db_path: Path to SQLite database for persistent storage (optional)
            default_ttl: Default TTL in seconds for cached entries
            max_memory_entries: Maximum entries in memory cache
        """
        self.default_ttl = default_ttl
        self.max_memory_entries = max_memory_entries
        self._memory_cache: dict[str, tuple[DNSResult, datetime]] = {}
        self._lock = threading.Lock()
        
        self.db_path = Path(db_path) if db_path else None
        if self.db_path:
            self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dns_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    records TEXT,
                    ttl INTEGER,
                    query_time_ms REAL,
                    nameserver TEXT,
                    timestamp TEXT NOT NULL,
                    expiry TEXT NOT NULL,
                    error TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_key ON dns_cache(cache_key)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_domain ON dns_cache(domain)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_cache(timestamp)
            """)
            
            # History table - stores all lookups without expiry
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dns_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    records TEXT,
                    ttl INTEGER,
                    query_time_ms REAL,
                    nameserver TEXT,
                    timestamp TEXT NOT NULL,
                    error TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_domain ON dns_history(domain)
            """)
    
    def _cache_key(self, domain: str, record_type: str) -> str:
        """Generate cache key."""
        return f"{domain.lower()}:{record_type.upper()}"
    
    def get(self, domain: str, record_type: str) -> DNSResult | None:
        """
        Get cached DNS result.
        
        Returns None if not in cache or expired.
        """
        key = self._cache_key(domain, record_type)
        now = datetime.utcnow()
        
        # Check memory cache first
        with self._lock:
            if key in self._memory_cache:
                result, expiry = self._memory_cache[key]
                if expiry > now:
                    return result
                else:
                    del self._memory_cache[key]
        
        # Check database
        if self.db_path:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    """
                    SELECT * FROM dns_cache 
                    WHERE cache_key = ? AND expiry > ?
                    ORDER BY timestamp DESC LIMIT 1
                    """,
                    (key, now.isoformat())
                )
                row = cursor.fetchone()
                
                if row:
                    result = self._row_to_result(row)
                    # Store in memory cache
                    expiry = datetime.fromisoformat(row["expiry"])
                    self._set_memory(key, result, expiry)
                    return result
        
        return None
    
    def set(
        self,
        result: DNSResult,
        ttl: int | None = None,
    ) -> None:
        """
        Cache a DNS result.
        
        Args:
            result: DNS result to cache
            ttl: TTL in seconds (defaults to result TTL or default_ttl)
        """
        key = self._cache_key(result.domain, result.record_type)
        
        # Determine TTL
        if ttl is None:
            ttl = result.ttl if result.ttl else self.default_ttl
        
        now = datetime.utcnow()
        expiry = now + timedelta(seconds=ttl)
        
        # Store in memory
        self._set_memory(key, result, expiry)
        
        # Store in database
        if self.db_path:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO dns_cache 
                    (cache_key, domain, record_type, records, ttl, query_time_ms,
                     nameserver, timestamp, expiry, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        result.domain,
                        result.record_type,
                        json.dumps(result.records),
                        result.ttl,
                        result.query_time_ms,
                        result.nameserver,
                        result.timestamp.isoformat(),
                        expiry.isoformat(),
                        result.error,
                    )
                )
    
    def _set_memory(self, key: str, result: DNSResult, expiry: datetime) -> None:
        """Set entry in memory cache."""
        with self._lock:
            # Evict old entries if at capacity
            if len(self._memory_cache) >= self.max_memory_entries:
                # Remove oldest entries
                sorted_keys = sorted(
                    self._memory_cache.keys(),
                    key=lambda k: self._memory_cache[k][1]
                )
                for old_key in sorted_keys[:100]:
                    del self._memory_cache[old_key]
            
            self._memory_cache[key] = (result, expiry)
    
    def add_to_history(self, result: DNSResult) -> None:
        """Add a lookup to permanent history."""
        if not self.db_path:
            return
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO dns_history 
                (domain, record_type, records, ttl, query_time_ms,
                 nameserver, timestamp, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.domain,
                    result.record_type,
                    json.dumps(result.records),
                    result.ttl,
                    result.query_time_ms,
                    result.nameserver,
                    result.timestamp.isoformat(),
                    result.error,
                )
            )
    
    def get_history(
        self,
        domain: str | None = None,
        record_type: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[DNSResult]:
        """
        Get DNS lookup history.
        
        Args:
            domain: Filter by domain (optional)
            record_type: Filter by record type (optional)
            since: Only return entries after this time (optional)
            limit: Maximum number of entries to return
        
        Returns:
            List of historical DNS results
        """
        if not self.db_path:
            return []
        
        query = "SELECT * FROM dns_history WHERE 1=1"
        params = []
        
        if domain:
            query += " AND domain = ?"
            params.append(domain.lower())
        
        if record_type:
            query += " AND record_type = ?"
            params.append(record_type.upper())
        
        if since:
            query += " AND timestamp > ?"
            params.append(since.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            
            return [self._row_to_result(row) for row in cursor.fetchall()]
    
    def _row_to_result(self, row: sqlite3.Row) -> DNSResult:
        """Convert database row to DNSResult."""
        return DNSResult(
            domain=row["domain"],
            record_type=row["record_type"],
            records=json.loads(row["records"]) if row["records"] else [],
            ttl=row["ttl"],
            query_time_ms=row["query_time_ms"],
            nameserver=row["nameserver"] or "",
            timestamp=datetime.fromisoformat(row["timestamp"]),
            error=row["error"],
        )
    
    def clear(self, expired_only: bool = True) -> int:
        """
        Clear cache entries.
        
        Args:
            expired_only: If True, only clear expired entries
        
        Returns:
            Number of entries cleared
        """
        now = datetime.utcnow()
        cleared = 0
        
        with self._lock:
            if expired_only:
                expired_keys = [
                    k for k, (_, expiry) in self._memory_cache.items()
                    if expiry <= now
                ]
                for key in expired_keys:
                    del self._memory_cache[key]
                cleared += len(expired_keys)
            else:
                cleared += len(self._memory_cache)
                self._memory_cache.clear()
        
        if self.db_path:
            with sqlite3.connect(self.db_path) as conn:
                if expired_only:
                    cursor = conn.execute(
                        "DELETE FROM dns_cache WHERE expiry <= ?",
                        (now.isoformat(),)
                    )
                else:
                    cursor = conn.execute("DELETE FROM dns_cache")
                cleared += cursor.rowcount
        
        return cleared
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        stats = {
            "memory_entries": len(self._memory_cache),
            "memory_max": self.max_memory_entries,
        }
        
        if self.db_path:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM dns_cache")
                stats["db_cache_entries"] = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT COUNT(*) FROM dns_history")
                stats["history_entries"] = cursor.fetchone()[0]
                
                now = datetime.utcnow().isoformat()
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM dns_cache WHERE expiry > ?",
                    (now,)
                )
                stats["db_valid_entries"] = cursor.fetchone()[0]
        
        return stats
    
    def get_domain_history_changes(
        self,
        domain: str,
        record_type: str = "A",
    ) -> list[dict[str, Any]]:
        """
        Get history of changes for a domain's records.
        
        Returns list of changes showing when records changed.
        """
        history = self.get_history(domain, record_type, limit=1000)
        
        if not history:
            return []
        
        changes = []
        prev_records = None
        
        for result in reversed(history):
            current_records = tuple(sorted(result.records))
            
            if prev_records is not None and current_records != prev_records:
                changes.append({
                    "timestamp": result.timestamp.isoformat(),
                    "old_records": list(prev_records),
                    "new_records": list(current_records),
                })
            
            prev_records = current_records
        
        return changes
