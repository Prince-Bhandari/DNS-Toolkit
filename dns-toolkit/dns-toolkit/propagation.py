"""DNS propagation checking across global DNS servers."""
import asyncio
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from .utils import PUBLIC_DNS_SERVERS, normalize_domain
@dataclass
class PropagationResult:
    """Result of propagation check for a single server."""
    server_name: str
    server_ip: str
    records: list[str] = field(default_factory=list)
    ttl: int | None = None
    response_time_ms: float = 0.0
    error: str | None = None
    propagated: bool = False
@dataclass
class PropagationReport:
    """Overall propagation report."""
    domain: str
    record_type: str
    expected_value: str | None
    total_servers: int
    propagated_count: int
    results: list[PropagationResult] = field(default_factory=list)
    
    @property
    def propagation_percentage(self) -> float:
        if self.total_servers == 0:
            return 0.0
        return (self.propagated_count / self.total_servers) * 100
    
    @property
    def is_fully_propagated(self) -> bool:
        return self.propagated_count == self.total_servers
class PropagationChecker:
    """Check DNS propagation across multiple global DNS servers."""
    
    def __init__(
        self,
        servers: dict[str, list[str]] | None = None,
        timeout: float = 5.0,
    ):
        self.servers = servers or PUBLIC_DNS_SERVERS
        self.timeout = timeout
    
    def check(
        self,
        domain: str,
        record_type: str = "A",
        expected_value: str | None = None,
        parallel: bool = True,
    ) -> PropagationReport:
        """
        Check DNS propagation across all configured servers.
        
        Args:
            domain: Domain to check
            record_type: DNS record type
            expected_value: Expected record value (for determining propagation)
            parallel: Run checks in parallel
        
        Returns:
            PropagationReport with results from all servers
        """
        domain = normalize_domain(domain)
        
        # Flatten server list
        server_list = []
        for name, ips in self.servers.items():
            for ip in ips:
                server_list.append((name, ip))
        
        results = []
        
        if parallel:
            with ThreadPoolExecutor(max_workers=len(server_list)) as executor:
                futures = {
                    executor.submit(
                        self._check_server, domain, record_type, name, ip, expected_value
                    ): (name, ip)
                    for name, ip in server_list
                }
                for future in as_completed(futures):
                    results.append(future.result())
        else:
            for name, ip in server_list:
                results.append(
                    self._check_server(domain, record_type, name, ip, expected_value)
                )
        
        propagated_count = sum(1 for r in results if r.propagated)
        
        return PropagationReport(
            domain=domain,
            record_type=record_type,
            expected_value=expected_value,
            total_servers=len(results),
            propagated_count=propagated_count,
            results=results,
        )
    
    def _check_server(
        self,
        domain: str,
        record_type: str,
        server_name: str,
        server_ip: str,
        expected_value: str | None,
    ) -> PropagationResult:
        """Check a single DNS server."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server_ip]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        import time
        start = time.perf_counter()
        
        try:
            answers = resolver.resolve(domain, record_type)
            response_time = (time.perf_counter() - start) * 1000
            
            records = [str(r) for r in answers]
            
            # Determine if propagated
            propagated = True
            if expected_value:
                propagated = expected_value in records
            
            return PropagationResult(
                server_name=server_name,
                server_ip=server_ip,
                records=records,
                ttl=answers.rrset.ttl if answers.rrset else None,
                response_time_ms=response_time,
                propagated=propagated,
            )
            
        except Exception as e:
            response_time = (time.perf_counter() - start) * 1000
            return PropagationResult(
                server_name=server_name,
                server_ip=server_ip,
                response_time_ms=response_time,
                error=str(e),
                propagated=False,
            )
    
    def check_multiple_records(
        self,
        domain: str,
        record_types: list[str],
    ) -> dict[str, PropagationReport]:
        """Check propagation for multiple record types."""
        results = {}
        for rt in record_types:
            results[rt] = self.check(domain, rt)
        return results
    
    def add_custom_server(self, name: str, ips: list[str]) -> None:
        """Add a custom DNS server for propagation checks."""
        self.servers[name] = ips
    
    def get_inconsistencies(self, report: PropagationReport) -> dict[str, list[str]]:
        """Find inconsistencies in propagation results."""
        value_to_servers: dict[tuple, list[str]] = {}
        
        for result in report.results:
            if result.error:
                continue
            key = tuple(sorted(result.records))
            if key not in value_to_servers:
                value_to_servers[key] = []
            value_to_servers[key].append(f"{result.server_name} ({result.server_ip})")
        
        if len(value_to_servers) <= 1:
            return {}
        
        return {
            str(list(records)): servers
            for records, servers in value_to_servers.items()
        }
class AsyncPropagationChecker:
    """Async version of propagation checker for high-performance checks."""
    
    def __init__(
        self,
        servers: dict[str, list[str]] | None = None,
        timeout: float = 5.0,
    ):
        self.servers = servers or PUBLIC_DNS_SERVERS
        self.timeout = timeout
    
    async def check(
        self,
        domain: str,
        record_type: str = "A",
        expected_value: str | None = None,
    ) -> PropagationReport:
        """Async propagation check."""
        domain = normalize_domain(domain)
        
        tasks = []
        for name, ips in self.servers.items():
            for ip in ips:
                tasks.append(
                    self._check_server_async(domain, record_type, name, ip, expected_value)
                )
        
        results = await asyncio.gather(*tasks)
        propagated_count = sum(1 for r in results if r.propagated)
        
        return PropagationReport(
            domain=domain,
            record_type=record_type,
            expected_value=expected_value,
            total_servers=len(results),
            propagated_count=propagated_count,
            results=list(results),
        )
    
    async def _check_server_async(
        self,
        domain: str,
        record_type: str,
        server_name: str,
        server_ip: str,
        expected_value: str | None,
    ) -> PropagationResult:
        """Async check for a single server."""
        # Run sync DNS query in thread pool
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._check_server_sync,
            domain, record_type, server_name, server_ip, expected_value
        )
    
    def _check_server_sync(
        self,
        domain: str,
        record_type: str,
        server_name: str,
        server_ip: str,
        expected_value: str | None,
    ) -> PropagationResult:
        """Sync DNS check (called from executor)."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server_ip]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        import time
        start = time.perf_counter()
        
        try:
            answers = resolver.resolve(domain, record_type)
            response_time = (time.perf_counter() - start) * 1000
            
            records = [str(r) for r in answers]
            propagated = expected_value in records if expected_value else True
            
            return PropagationResult(
                server_name=server_name,
                server_ip=server_ip,
                records=records,
                ttl=answers.rrset.ttl if answers.rrset else None,
                response_time_ms=response_time,
                propagated=propagated,
            )
        except Exception as e:
            response_time = (time.perf_counter() - start) * 1000
            return PropagationResult(
                server_name=server_name,
                server_ip=server_ip,
                response_time_ms=response_time,
                error=str(e),
                propagated=False,
            )
