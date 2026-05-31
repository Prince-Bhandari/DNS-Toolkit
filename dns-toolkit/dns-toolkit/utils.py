"""Utility functions and common configurations."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import socket
# Global DNS servers for propagation checks
PUBLIC_DNS_SERVERS = {
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
    "Level3": ["4.2.2.1", "4.2.2.2"],
    "Verisign": ["64.6.64.6", "64.6.65.6"],
    "DNS.Watch": ["84.200.69.80", "84.200.70.40"],
    "Comodo": ["8.26.56.26", "8.20.247.20"],
}
# All standard DNS record types
RECORD_TYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV",
    "PTR", "CAA", "DNSKEY", "DS", "NAPTR", "TLSA", "SSHFP",
    "HINFO", "RP", "AFSDB", "LOC", "CERT", "DNAME", "SPF",
]
@dataclass
class DNSResult:
    """Container for DNS query results."""
    domain: str
    record_type: str
    records: list[str] = field(default_factory=list)
    ttl: int | None = None
    query_time_ms: float = 0.0
    nameserver: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "record_type": self.record_type,
            "records": self.records,
            "ttl": self.ttl,
            "query_time_ms": round(self.query_time_ms, 2),
            "nameserver": self.nameserver,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error,
        }
@dataclass
class WhoisResult:
    """Container for WHOIS lookup results."""
    domain: str
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    registrant: dict[str, str] = field(default_factory=dict)
    dnssec: str | None = None
    raw_data: str = ""
    error: str | None = None
    
    @property
    def days_until_expiry(self) -> int | None:
        if not self.expiration_date:
            return None
        now = datetime.now(timezone.utc)
        expiry = self.expiration_date
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        return (expiry - now).days
    
    @property
    def domain_age_days(self) -> int | None:
        if not self.creation_date:
            return None
        now = datetime.now(timezone.utc)
        creation = self.creation_date
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        return (now - creation).days       
def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False
def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False
def normalize_domain(domain: str) -> str:
    """Normalize domain name by removing protocol and trailing dots."""
    domain = domain.lower().strip()
    for prefix in ("https://", "http://", "//"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]  # Remove path
    domain = domain.rstrip(".")
    return domain
