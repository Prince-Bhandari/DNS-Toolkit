"""Subdomain enumeration and discovery."""
import dns.resolver
import dns.zone
import dns.query
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from .utils import normalize_domain
from .lookup import DNSLookup
# Common subdomain prefixes
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "imap", "pop3", "cpanel", "whm", "webdisk", "www2", "admin",
    "portal", "blog", "dev", "api", "app", "stage", "staging", "test", "testing",
    "demo", "cdn", "static", "assets", "img", "images", "media", "video", "docs",
    "support", "help", "status", "monitor", "git", "svn", "vpn", "remote", "m",
    "mobile", "shop", "store", "secure", "ssl", "login", "auth", "sso", "id",
    "account", "accounts", "dashboard", "panel", "cms", "crm", "erp", "hr",
    "intranet", "internal", "private", "public", "beta", "alpha", "v1", "v2",
    "old", "new", "backup", "bak", "db", "database", "sql", "mysql", "postgres",
    "redis", "cache", "proxy", "gateway", "edge", "node", "server", "host",
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "jenkins",
    "ci", "cd", "build", "release", "prod", "production", "uat", "qa",
]
@dataclass
class SubdomainResult:
    """Result of subdomain discovery."""
    subdomain: str
    full_domain: str
    exists: bool
    a_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    response_time_ms: float = 0.0
@dataclass
class EnumerationReport:
    """Complete subdomain enumeration report."""
    domain: str
    total_checked: int
    found_count: int
    subdomains: list[SubdomainResult] = field(default_factory=list)
    
    @property
    def found_subdomains(self) -> list[str]:
        return [s.full_domain for s in self.subdomains if s.exists]
class SubdomainEnumerator:
    """Enumerate and discover subdomains."""
    
    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 3.0,
        wordlist: list[str] | None = None,
    ):
        self.lookup = DNSLookup(nameservers=nameservers, timeout=timeout)
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.timeout = timeout
    
    def enumerate(
        self,
        domain: str,
        wordlist: list[str] | None = None,
        parallel: bool = True,
        max_workers: int = 50,
    ) -> EnumerationReport:
        """
        Enumerate subdomains using wordlist.
        
        Args:
            domain: Base domain to enumerate
            wordlist: List of subdomain prefixes to try
            parallel: Run checks in parallel
            max_workers: Maximum parallel workers
        
        Returns:
            EnumerationReport with discovered subdomains
        """
        domain = normalize_domain(domain)
        wordlist = wordlist or self.wordlist
        
        results = []
        
        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._check_subdomain, prefix, domain): prefix
                    for prefix in wordlist
                }
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
        else:
            for prefix in wordlist:
                results.append(self._check_subdomain(prefix, domain))
        
        # Sort by subdomain name
        results.sort(key=lambda r: r.subdomain)
        
        found_count = sum(1 for r in results if r.exists)
        
        return EnumerationReport(
            domain=domain,
            total_checked=len(results),
            found_count=found_count,
            subdomains=results,
        )
    
    def _check_subdomain(self, prefix: str, domain: str) -> SubdomainResult:
        """Check if a subdomain exists."""
        import time
        
        full_domain = f"{prefix}.{domain}"
        
        result = SubdomainResult(
            subdomain=prefix,
            full_domain=full_domain,
            exists=False,
        )
        
        start = time.perf_counter()
        
        # Try A record
        a_result = self.lookup.lookup(full_domain, "A")
        if not a_result.error and a_result.records:
            result.exists = True
            result.a_records = a_result.records
        
        # Try CNAME
        cname_result = self.lookup.lookup(full_domain, "CNAME")
        if not cname_result.error and cname_result.records:
            result.exists = True
            result.cname_records = cname_result.records
        
        result.response_time_ms = (time.perf_counter() - start) * 1000
        
        return result
    
    def enumerate_from_file(
        self,
        domain: str,
        wordlist_path: str | Path,
        parallel: bool = True,
        max_workers: int = 50,
    ) -> EnumerationReport:
        """
        Enumerate subdomains using a wordlist file.
        
        Args:
            domain: Base domain to enumerate
            wordlist_path: Path to wordlist file (one prefix per line)
            parallel: Run checks in parallel
            max_workers: Maximum parallel workers
        
        Returns:
            EnumerationReport with discovered subdomains
        """
        path = Path(wordlist_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
        
        wordlist = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    wordlist.append(line)
        
        return self.enumerate(domain, wordlist, parallel, max_workers)
    
    def try_zone_transfer(self, domain: str) -> list[str] | None:
        """
        Attempt zone transfer (AXFR) to get all subdomains.
        
        Note: Most DNS servers block zone transfers for security.
        Returns None if zone transfer is not allowed.
        """
        domain = normalize_domain(domain)
        
        # Get nameservers
        ns_result = self.lookup.lookup(domain, "NS")
        if ns_result.error:
            return None
        
        for ns in ns_result.records:
            ns = ns.rstrip(".")
            
            # Resolve NS to IP
            a_result = self.lookup.lookup(ns, "A")
            if a_result.error:
                continue
            
            for ns_ip in a_result.records:
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, domain, timeout=10)
                    )
                    
                    subdomains = []
                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != "@":
                            full_domain = f"{subdomain}.{domain}"
                            subdomains.append(full_domain)
                    
                    return sorted(set(subdomains))
                    
                except Exception:
                    continue
        
        return None
    
    def discover_from_certificate(self, domain: str) -> list[str]:
        """
        Discover subdomains from SSL certificate transparency logs.
        
        Uses crt.sh API to find certificates issued for the domain.
        """
        import requests
        
        domain = normalize_domain(domain)
        subdomains = set()
        
        try:
            url = f"[crt.sh](https://crt.sh/?q=%.{domain}&output=json)"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # Handle wildcard and multi-value entries
                    for name in name_value.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
        
        except Exception:
            pass
        
        return sorted(subdomains)
    
    def comprehensive_scan(
        self,
        domain: str,
        use_certificate: bool = True,
        use_zone_transfer: bool = True,
        use_wordlist: bool = True,
        wordlist: list[str] | None = None,
    ) -> EnumerationReport:
        """
        Comprehensive subdomain discovery using multiple methods.
        
        Args:
            domain: Base domain to scan
            use_certificate: Check certificate transparency logs
            use_zone_transfer: Attempt zone transfer
            use_wordlist: Use wordlist enumeration
            wordlist: Custom wordlist (defaults to common subdomains)
        
        Returns:
            Combined EnumerationReport
        """
        domain = normalize_domain(domain)
        all_subdomains = set()
        
        # Certificate transparency
        if use_certificate:
            ct_subdomains = self.discover_from_certificate(domain)
            all_subdomains.update(ct_subdomains)
        
        # Zone transfer
        if use_zone_transfer:
            zt_subdomains = self.try_zone_transfer(domain)
            if zt_subdomains:
                all_subdomains.update(zt_subdomains)
        
        # Wordlist enumeration
        if use_wordlist:
            wordlist = wordlist or self.wordlist
            report = self.enumerate(domain, wordlist)
            all_subdomains.update(report.found_subdomains)
        
        # Verify all discovered subdomains
        results = []
        for subdomain in all_subdomains:
            prefix = subdomain.replace(f".{domain}", "")
            results.append(self._check_subdomain(prefix, domain))
        
        results.sort(key=lambda r: r.subdomain)
        found_count = sum(1 for r in results if r.exists)
        
        return EnumerationReport(
            domain=domain,
            total_checked=len(results),
            found_count=found_count,
            subdomains=results,
        )
