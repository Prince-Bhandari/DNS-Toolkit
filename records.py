"""Comprehensive record fetching and parsing."""
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
from dataclasses import dataclass, field
from typing import Any
from .lookup import DNSLookup
from .utils import RECORD_TYPES, normalize_domain
@dataclass
class ParsedRecord:
    """Structured representation of a DNS record."""
    record_type: str
    name: str
    value: str
    ttl: int | None = None
    priority: int | None = None  # For MX, SRV
    weight: int | None = None    # For SRV
    port: int | None = None      # For SRV
    extra: dict[str, Any] = field(default_factory=dict)
class RecordFetcher:
    """Fetch and parse all DNS records for a domain."""
    
    def __init__(self, nameservers: list[str] | None = None):
        self.lookup = DNSLookup(nameservers=nameservers)
    
    def get_all_records(
        self,
        domain: str,
        include_rare: bool = False,
    ) -> dict[str, list[ParsedRecord]]:
        """
        Fetch all DNS records for a domain.
        
        Args:
            domain: Domain to query
            include_rare: Include rarely-used record types
        
        Returns:
            Dictionary mapping record types to lists of parsed records
        """
        domain = normalize_domain(domain)
        
        if include_rare:
            types_to_check = RECORD_TYPES
        else:
            types_to_check = [
                "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", 
                "SRV", "CAA", "PTR", "DNSKEY", "DS"
            ]
        
        results = self.lookup.lookup_all(domain, types_to_check)
        parsed = {}
        
        for record_type, result in results.items():
            if result.error or not result.records:
                continue
            
            parsed[record_type] = [
                self._parse_record(record_type, domain, record, result.ttl)
                for record in result.records
            ]
        
        return parsed
    
    def _parse_record(
        self,
        record_type: str,
        domain: str,
        value: str,
        ttl: int | None,
    ) -> ParsedRecord:
        """Parse a raw record value into structured format."""
        record = ParsedRecord(
            record_type=record_type,
            name=domain,
            value=value,
            ttl=ttl,
        )
        
        if record_type == "MX":
            parts = value.split(maxsplit=1)
            if len(parts) == 2:
                record.priority = int(parts[0])
                record.value = parts[1].rstrip(".")
        
        elif record_type == "SRV":
            parts = value.split()
            if len(parts) >= 4:
                record.priority = int(parts[0])
                record.weight = int(parts[1])
                record.port = int(parts[2])
                record.value = parts[3].rstrip(".")
        
        elif record_type == "SOA":
            parts = value.split()
            if len(parts) >= 7:
                record.extra = {
                    "primary_ns": parts[0],
                    "admin_email": parts[1].replace(".", "@", 1),
                    "serial": int(parts[2]),
                    "refresh": int(parts[3]),
                    "retry": int(parts[4]),
                    "expire": int(parts[5]),
                    "minimum_ttl": int(parts[6]),
                }
        
        elif record_type == "CAA":
            parts = value.split(maxsplit=2)
            if len(parts) >= 3:
                record.extra = {
                    "flags": int(parts[0]),
                    "tag": parts[1],
                    "value": parts[2].strip('"'),
                }
        
        elif record_type == "TXT":
            # Handle SPF, DKIM, DMARC parsing
            value_lower = value.lower()
            if value_lower.startswith('"v=spf1'):
                record.extra["spf"] = self._parse_spf(value.strip('"'))
            elif "dkim" in domain.lower() or value_lower.startswith('"v=dkim1'):
                record.extra["dkim"] = True
            elif value_lower.startswith('"v=dmarc1'):
                record.extra["dmarc"] = self._parse_dmarc(value.strip('"'))
        
        return record
    
    def _parse_spf(self, spf: str) -> dict[str, Any]:
        """Parse SPF record into components."""
        result = {
            "version": "spf1",
            "mechanisms": [],
            "modifiers": {},
        }
        
        parts = spf.split()
        for part in parts[1:]:  # Skip version
            if part.startswith(("redirect=", "exp=")):
                key, val = part.split("=", 1)
                result["modifiers"][key] = val
            else:
                result["mechanisms"].append(part)
        
        return result
    
    def _parse_dmarc(self, dmarc: str) -> dict[str, str]:
        """Parse DMARC record into components."""
        result = {}
        parts = dmarc.split(";")
        for part in parts:
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                result[key.strip()] = val.strip()
        return result
    
    def get_zone_records(
        self,
        domain: str,
        nameserver: str | None = None,
    ) -> list[ParsedRecord] | None:
        """
        Attempt zone transfer (AXFR) to get all zone records.
        
        Note: Most DNS servers block zone transfers for security.
        Returns None if zone transfer is not allowed.
        """
        domain = normalize_domain(domain)
        
        if not nameserver:
            # Get authoritative nameserver
            ns_result = self.lookup.lookup(domain, "NS")
            if ns_result.error or not ns_result.records:
                return None
            nameserver = ns_result.records[0].rstrip(".")
            
            # Resolve NS hostname to IP
            a_result = self.lookup.lookup(nameserver, "A")
            if a_result.error or not a_result.records:
                return None
            nameserver = a_result.records[0]
        
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(nameserver, domain, timeout=10)
            )
            
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(ParsedRecord(
                            record_type=dns.rdatatype.to_text(rdataset.rdtype),
                            name=str(name),
                            value=str(rdata),
                            ttl=rdataset.ttl,
                        ))
            
            return records
            
        except Exception:
            return None
    
    def check_email_records(self, domain: str) -> dict[str, Any]:
        """
        Check email-related DNS records (MX, SPF, DKIM, DMARC).
        
        Returns summary of email authentication configuration.
        """
        domain = normalize_domain(domain)
        
        results = {
            "domain": domain,
            "mx_configured": False,
            "spf_configured": False,
            "dmarc_configured": False,
            "dkim_selector_hints": [],
            "mx_records": [],
            "spf_record": None,
            "dmarc_record": None,
            "issues": [],
        }
        
        # Check MX
        mx_result = self.lookup.lookup(domain, "MX")
        if not mx_result.error and mx_result.records:
            results["mx_configured"] = True
            results["mx_records"] = mx_result.records
        else:
            results["issues"].append("No MX records found")
        
        # Check SPF (in TXT records)
        txt_result = self.lookup.lookup(domain, "TXT")
        if not txt_result.error:
            for record in txt_result.records:
                if record.lower().startswith('"v=spf1') or record.lower().startswith('v=spf1'):
                    results["spf_configured"] = True
                    results["spf_record"] = record.strip('"')
                    break
        
        if not results["spf_configured"]:
            results["issues"].append("No SPF record found")
        
        # Check DMARC
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_result = self.lookup.lookup(dmarc_domain, "TXT")
        if not dmarc_result.error:
            for record in dmarc_result.records:
                if "v=dmarc1" in record.lower():
                    results["dmarc_configured"] = True
                    results["dmarc_record"] = record.strip('"')
                    break
        
        if not results["dmarc_configured"]:
            results["issues"].append("No DMARC record found")
        
        # Try common DKIM selectors
        common_selectors = ["default", "google", "selector1", "selector2", "k1", "mail"]
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_result = self.lookup.lookup(dkim_domain, "TXT")
            if not dkim_result.error and dkim_result.records:
                results["dkim_selector_hints"].append(selector)
        
        return results