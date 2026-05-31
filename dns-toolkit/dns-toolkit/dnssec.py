"""DNSSEC validation and checking."""
import dns.resolver
import dns.dnssec
import dns.rdatatype
import dns.name
from dataclasses import dataclass, field
from typing import Any
from .utils import normalize_domain
from .lookup import DNSLookup
@dataclass
class DNSSECResult:
    """Result of DNSSEC validation."""
    domain: str
    dnssec_enabled: bool
    validated: bool = False
    dnskey_records: list[str] = field(default_factory=list)
    ds_records: list[str] = field(default_factory=list)
    rrsig_records: list[str] = field(default_factory=list)
    nsec_type: str | None = None  # NSEC or NSEC3
    algorithm: str | None = None
    key_tag: int | None = None
    errors: list[str] = field(default_factory=list)
    chain_of_trust: list[dict] = field(default_factory=list)
class DNSSECChecker:
    """Check and validate DNSSEC configuration."""
    
    def __init__(self, nameservers: list[str] | None = None):
        self.lookup = DNSLookup(nameservers=nameservers)
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.use_edns(edns=0, ednsflags=dns.flags.DO)  # Enable DNSSEC OK flag
    
    def check(self, domain: str) -> DNSSECResult:
        """
        Check DNSSEC status for a domain.
        
        Args:
            domain: Domain to check
        
        Returns:
            DNSSECResult with DNSSEC information
        """
        domain = normalize_domain(domain)
        
        result = DNSSECResult(domain=domain, dnssec_enabled=False)
        
        # Check for DNSKEY records
        dnskey_result = self.lookup.lookup(domain, "DNSKEY")
        if not dnskey_result.error and dnskey_result.records:
            result.dnssec_enabled = True
            result.dnskey_records = dnskey_result.records
            
            # Parse first DNSKEY for algorithm info
            self._parse_dnskey(dnskey_result.records[0], result)
        
        # Check for DS records (in parent zone)
        ds_result = self.lookup.lookup(domain, "DS")
        if not ds_result.error and ds_result.records:
            result.ds_records = ds_result.records
            if not result.dnssec_enabled:
                result.dnssec_enabled = True
        
        # Check for RRSIG records
        try:
            # Query A record with DNSSEC
            response = self.resolver.resolve(domain, "A", raise_on_no_answer=False)
            
            # Check if RRSIG was returned
            for rrset in response.response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    result.rrsig_records = [str(r) for r in rrset]
                    break
                    
        except Exception:
            pass
        
        # Check NSEC/NSEC3
        result.nsec_type = self._check_nsec_type(domain)
        
        # Validate chain of trust
        if result.dnssec_enabled:
            result.chain_of_trust = self._build_chain_of_trust(domain)
            result.validated = self._validate_chain(result.chain_of_trust)
        
        return result
    
    def _parse_dnskey(self, dnskey: str, result: DNSSECResult) -> None:
        """Parse DNSKEY record for metadata."""
        parts = dnskey.split()
        if len(parts) >= 3:
            try:
                result.algorithm = self._algorithm_name(int(parts[2]))
            except (ValueError, IndexError):
                pass
    
    def _algorithm_name(self, algo_num: int) -> str:
        """Convert algorithm number to name."""
        algorithms = {
            5: "RSASHA1",
            7: "RSASHA1-NSEC3-SHA1",
            8: "RSASHA256",
            10: "RSASHA512",
            13: "ECDSAP256SHA256",
            14: "ECDSAP384SHA384",
            15: "ED25519",
            16: "ED448",
        }
        return algorithms.get(algo_num, f"Unknown ({algo_num})")
    
    def _check_nsec_type(self, domain: str) -> str | None:
        """Check if zone uses NSEC or NSEC3."""
        try:
            response = self.resolver.resolve(domain, "NSEC", raise_on_no_answer=False)
            if response.rrset:
                return "NSEC"
        except dns.resolver.NoAnswer:
            pass
        
        try:
            response = self.resolver.resolve(domain, "NSEC3", raise_on_no_answer=False)
            if response.rrset:
                return "NSEC3"
        except dns.resolver.NoAnswer:
            pass
        
        return None
    
    def _build_chain_of_trust(self, domain: str) -> list[dict]:
        """Build the DNSSEC chain of trust from root to domain."""
        chain = []
        parts = domain.split(".")
        
        # Start from TLD and work down
        for i in range(len(parts), 0, -1):
            zone = ".".join(parts[-i:])
            
            zone_info = {
                "zone": zone,
                "has_ds": False,
                "has_dnskey": False,
                "ds_records": [],
                "dnskey_records": [],
            }
            
            # Check DS in parent
            ds_result = self.lookup.lookup(zone, "DS")
            if not ds_result.error and ds_result.records:
                zone_info["has_ds"] = True
                zone_info["ds_records"] = ds_result.records
            
            # Check DNSKEY
            dnskey_result = self.lookup.lookup(zone, "DNSKEY")
            if not dnskey_result.error and dnskey_result.records:
                zone_info["has_dnskey"] = True
                zone_info["dnskey_records"] = dnskey_result.records
            
            chain.append(zone_info)
        
        return chain
    
    def _validate_chain(self, chain: list[dict]) -> bool:
        """Validate the chain of trust."""
        # Simplified validation - check that each zone has both DS and DNSKEY
        for zone_info in chain:
            if zone_info["has_dnskey"]:
                # For non-TLD zones, should have DS in parent
                if "." in zone_info["zone"]:
                    if not zone_info["has_ds"]:
                        return False
        
        return True
    
    def get_dnssec_status(self, domain: str) -> dict[str, Any]:
        """Get a simplified DNSSEC status summary."""
        result = self.check(domain)
        
        return {
            "domain": domain,
            "enabled": result.dnssec_enabled,
            "validated": result.validated,
            "algorithm": result.algorithm,
            "nsec_type": result.nsec_type,
            "has_dnskey": len(result.dnskey_records) > 0,
            "has_ds": len(result.ds_records) > 0,
            "has_rrsig": len(result.rrsig_records) > 0,
            "errors": result.errors,
        }
    
    def verify_signature(self, domain: str, record_type: str = "A") -> dict[str, Any]:
        """
        Verify DNSSEC signatures for a specific record.
        
        Note: Full cryptographic validation requires additional setup.
        This performs basic checks.
        """
        domain = normalize_domain(domain)
        
        result = {
            "domain": domain,
            "record_type": record_type,
            "signed": False,
            "signature_valid": None,
            "signer": None,
            "expiration": None,
        }
        
        try:
            response = self.resolver.resolve(domain, record_type)
            
            # Look for RRSIG
            for rrset in response.response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    result["signed"] = True
                    for rdata in rrset:
                        result["signer"] = str(rdata.signer)
                        result["expiration"] = str(rdata.expiration)
                        break
                    break
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
