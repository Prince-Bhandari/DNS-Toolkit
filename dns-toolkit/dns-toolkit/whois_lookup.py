"""WHOIS lookup functionality."""
import whois
from datetime import datetime
from typing import Any
from .utils import WhoisResult, normalize_domain
class WhoisLookup:
    """Perform WHOIS lookups for domain information."""
    
    def lookup(self, domain: str) -> WhoisResult:
        """
        Perform WHOIS lookup for a domain.
        
        Args:
            domain: Domain name to look up
        
        Returns:
            WhoisResult containing registration information
        """
        domain = normalize_domain(domain)
        
        try:
            w = whois.whois(domain)
            
            # Handle dates that might be lists
            creation = self._get_first_date(w.creation_date)
            expiration = self._get_first_date(w.expiration_date)
            updated = self._get_first_date(w.updated_date)
            
            # Handle name servers
            name_servers = w.name_servers or []
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            name_servers = [ns.lower() for ns in name_servers if ns]
            
            # Handle status
            status = w.status or []
            if isinstance(status, str):
                status = [status]
            
            # Build registrant info
            registrant = {}
            for field in ["name", "org", "organization", "email", "country"]:
                value = getattr(w, field, None) or getattr(w, f"registrant_{field}", None)
                if value:
                    registrant[field] = value
            
            return WhoisResult(
                domain=domain,
                registrar=w.registrar,
                creation_date=creation,
                expiration_date=expiration,
                updated_date=updated,
                name_servers=name_servers,
                status=status,
                registrant=registrant,
                dnssec=getattr(w, "dnssec", None),
                raw_data=str(w),
            )
            
        except whois.parser.PywhoisError as e:
            return WhoisResult(domain=domain, error=f"WHOIS error: {e}")
        except Exception as e:
            return WhoisResult(domain=domain, error=str(e))
    
    def _get_first_date(self, date_value: Any) -> datetime | None:
        """Extract first date from a value that might be a list."""
        if date_value is None:
            return None
        if isinstance(date_value, list):
            return date_value[0] if date_value else None
        return date_value
    
    def check_availability(self, domain: str) -> dict[str, Any]:
        """
        Check if a domain is available for registration.
        
        Note: This is not authoritative - always verify with a registrar.
        """
        result = self.lookup(domain)
        
        return {
            "domain": domain,
            "available": result.error is not None and "not found" in result.error.lower(),
            "registered": not result.error and result.registrar is not None,
            "whois_result": result,
        }
    
    def get_expiry_info(self, domain: str) -> dict[str, Any]:
        """Get domain expiration information."""
        result = self.lookup(domain)
        
        info = {
            "domain": domain,
            "expiration_date": None,
            "days_until_expiry": None,
            "is_expired": False,
            "status": "unknown",
        }
        
        if result.error:
            info["status"] = "error"
            info["error"] = result.error
            return info
        
        if result.expiration_date:
            info["expiration_date"] = result.expiration_date.isoformat()
            info["days_until_expiry"] = result.days_until_expiry
            
            if result.days_until_expiry is not None:
                if result.days_until_expiry < 0:
                    info["is_expired"] = True
                    info["status"] = "expired"
                elif result.days_until_expiry < 30:
                    info["status"] = "expiring_soon"
                elif result.days_until_expiry < 90:
                    info["status"] = "expiring_in_90_days"
                else:
                    info["status"] = "active"
        
        return info
    
    def get_history_summary(self, domain: str) -> dict[str, Any]:
        """Get domain history summary from WHOIS data."""
        result = self.lookup(domain)
        
        summary = {
            "domain": domain,
            "age_days": result.domain_age_days,
            "age_years": None,
            "creation_date": None,
            "last_updated": None,
            "registrar": result.registrar,
        }
        
        if result.domain_age_days:
            summary["age_years"] = round(result.domain_age_days / 365.25, 1)
        
        if result.creation_date:
            summary["creation_date"] = result.creation_date.isoformat()
        
        if result.updated_date:
            summary["last_updated"] = result.updated_date.isoformat()
        
        return summary
    
    def bulk_lookup(self, domains: list[str]) -> dict[str, WhoisResult]:
        """
        Perform WHOIS lookups for multiple domains.
        
        Note: Sequential to avoid rate limiting.
        """
        results = {}
        for domain in domains:
            results[domain] = self.lookup(domain)
        return results
