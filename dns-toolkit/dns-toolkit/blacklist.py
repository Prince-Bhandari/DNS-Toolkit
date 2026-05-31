"""DNS blacklist (DNSBL) checking."""
import dns.resolver
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import is_valid_ipv4, is_valid_ipv6
# Common DNS blacklists
DEFAULT_BLACKLISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "db.wpbl.info",
    "all.s5h.net",
]
@dataclass
class BlacklistResult:
    """Result of checking a single blacklist."""
    blacklist: str
    listed: bool
    reason: str | None = None
    response_time_ms: float = 0.0
    error: str | None = None
@dataclass
class BlacklistReport:
    """Complete blacklist check report."""
    ip: str
    total_checked: int
    listed_count: int
    results: list[BlacklistResult] = field(default_factory=list)
    
    @property
    def is_clean(self) -> bool:
        return self.listed_count == 0
    
    @property
    def listed_on(self) -> list[str]:
        return [r.blacklist for r in self.results if r.listed]
class BlacklistChecker:
    """Check IP addresses against DNS blacklists."""
    
    def __init__(
        self,
        blacklists: list[str] | None = None,
        timeout: float = 5.0,
    ):
        self.blacklists = blacklists or DEFAULT_BLACKLISTS
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def check(
        self,
        ip: str,
        blacklists: list[str] | None = None,
        parallel: bool = True,
    ) -> BlacklistReport:
        """
        Check an IP address against DNS blacklists.
        
        Args:
            ip: IP address to check
            blacklists: List of DNSBL hosts (defaults to common lists)
            parallel: Run checks in parallel
        
        Returns:
            BlacklistReport with results from all checked lists
        """
        if not is_valid_ipv4(ip):
            # IPv6 DNSBL support is limited
            if not is_valid_ipv6(ip):
                return BlacklistReport(
                    ip=ip,
                    total_checked=0,
                    listed_count=0,
                    results=[BlacklistResult(
                        blacklist="",
                        listed=False,
                        error="Invalid IP address",
                    )],
                )
        
        blacklists = blacklists or self.blacklists
        results = []
        
        if parallel:
            with ThreadPoolExecutor(max_workers=len(blacklists)) as executor:
                futures = {
                    executor.submit(self._check_blacklist, ip, bl): bl
                    for bl in blacklists
                }
                for future in as_completed(futures):
                    results.append(future.result())
        else:
            for bl in blacklists:
                results.append(self._check_blacklist(ip, bl))
        
        listed_count = sum(1 for r in results if r.listed)
        
        return BlacklistReport(
            ip=ip,
            total_checked=len(results),
            listed_count=listed_count,
            results=results,
        )
    
    def _check_blacklist(self, ip: str, blacklist: str) -> BlacklistResult:
        """Check a single blacklist."""
        import time
        
        # Reverse the IP octets
        reversed_ip = ".".join(ip.split(".")[::-1])
        query = f"{reversed_ip}.{blacklist}"
        
        start = time.perf_counter()
        
        try:
            answers = self.resolver.resolve(query, "A")
            response_time = (time.perf_counter() - start) * 1000
            
            # IP is listed - check for TXT record with reason
            reason = None
            try:
                txt_answers = self.resolver.resolve(query, "TXT")
                reason = " ".join(str(r).strip('"') for r in txt_answers)
            except Exception:
                # Return code can indicate listing type
                for rdata in answers:
                    reason = f"Listed (return code: {rdata})"
                    break
            
            return BlacklistResult(
                blacklist=blacklist,
                listed=True,
                reason=reason,
                response_time_ms=response_time,
            )
            
        except dns.resolver.NXDOMAIN:
            # Not listed
            response_time = (time.perf_counter() - start) * 1000
            return BlacklistResult(
                blacklist=blacklist,
                listed=False,
                response_time_ms=response_time,
            )
        except Exception as e:
            response_time = (time.perf_counter() - start) * 1000
            return BlacklistResult(
                blacklist=blacklist,
                listed=False,
                response_time_ms=response_time,
                error=str(e),
            )
    
    def check_domain(self, domain: str) -> dict[str, BlacklistReport]:
        """
        Check all IPs associated with a domain.
        
        Returns reports for each resolved IP.
        """
        from .lookup import DNSLookup
        
        lookup = DNSLookup()
        reports = {}
        
        # Get A records
        a_result = lookup.lookup(domain, "A")
        if not a_result.error:
            for ip in a_result.records:
                reports[ip] = self.check(ip)
        
        return reports
    
    def quick_check(self, ip: str) -> bool:
        """
        Quick check if IP is listed on any major blacklist.
        
        Returns True if listed anywhere, False if clean.
        """
        # Check top 3 most reliable blacklists
        quick_lists = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "cbl.abuseat.org",
        ]
        
        for bl in quick_lists:
            result = self._check_blacklist(ip, bl)
            if result.listed:
                return True
        
        return False
    
    def add_blacklist(self, blacklist: str) -> None:
        """Add a custom blacklist to check."""
        if blacklist not in self.blacklists:
            self.blacklists.append(blacklist)
    
    def remove_blacklist(self, blacklist: str) -> None:
        """Remove a blacklist from the check list."""
        if blacklist in self.blacklists:
            self.blacklists.remove(blacklist)
