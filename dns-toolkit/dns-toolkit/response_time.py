"""DNS response time measurement and benchmarking."""
import time
import statistics
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
from .utils import PUBLIC_DNS_SERVERS, normalize_domain
@dataclass
class TimingResult:
    """Result of a single timing measurement."""
    server: str
    server_ip: str
    response_time_ms: float
    success: bool
    error: str | None = None
@dataclass
class BenchmarkResult:
    """Result of benchmarking a DNS server."""
    server: str
    server_ip: str
    measurements: list[float] = field(default_factory=list)
    failed_count: int = 0
    
    @property
    def min_ms(self) -> float | None:
        return min(self.measurements) if self.measurements else None
    
    @property
    def max_ms(self) -> float | None:
        return max(self.measurements) if self.measurements else None
    
    @property
    def avg_ms(self) -> float | None:
        return statistics.mean(self.measurements) if self.measurements else None
    
    @property
    def median_ms(self) -> float | None:
        return statistics.median(self.measurements) if self.measurements else None
    
    @property
    def stdev_ms(self) -> float | None:
        if len(self.measurements) >= 2:
            return statistics.stdev(self.measurements)
        return None
    
    @property
    def success_rate(self) -> float:
        total = len(self.measurements) + self.failed_count
        if total == 0:
            return 0.0
        return len(self.measurements) / total
class ResponseTimer:
    """Measure DNS response times and benchmark servers."""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    def measure(
        self,
        domain: str,
        server_ip: str,
        server_name: str = "",
        record_type: str = "A",
    ) -> TimingResult:
        """
        Measure response time for a single DNS query.
        
        Args:
            domain: Domain to query
            server_ip: DNS server IP address
            server_name: Human-readable server name
            record_type: DNS record type
        
        Returns:
            TimingResult with response time
        """
        domain = normalize_domain(domain)
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server_ip]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        start = time.perf_counter()
        
        try:
            resolver.resolve(domain, record_type)
            response_time = (time.perf_counter() - start) * 1000
            
            return TimingResult(
                server=server_name or server_ip,
                server_ip=server_ip,
                response_time_ms=response_time,
                success=True,
            )
        except Exception as e:
            response_time = (time.perf_counter() - start) * 1000
            return TimingResult(
                server=server_name or server_ip,
                server_ip=server_ip,
                response_time_ms=response_time,
                success=False,
                error=str(e),
            )
    
    def benchmark_server(
        self,
        domain: str,
        server_ip: str,
        server_name: str = "",
        iterations: int = 10,
        record_type: str = "A",
    ) -> BenchmarkResult:
        """
        Benchmark a DNS server with multiple queries.
        
        Args:
            domain: Domain to query
            server_ip: DNS server IP address
            server_name: Human-readable server name
            iterations: Number of queries to perform
            record_type: DNS record type
        
        Returns:
            BenchmarkResult with statistics
        """
        result = BenchmarkResult(
            server=server_name or server_ip,
            server_ip=server_ip,
        )
        
        for _ in range(iterations):
            timing = self.measure(domain, server_ip, server_name, record_type)
            if timing.success:
                result.measurements.append(timing.response_time_ms)
            else:
                result.failed_count += 1
            
            # Small delay between queries
            time.sleep(0.1)
        
        return result
    
    def benchmark_all_servers(
        self,
        domain: str,
        servers: dict[str, list[str]] | None = None,
        iterations: int = 5,
        parallel: bool = True,
    ) -> list[BenchmarkResult]:
        """
        Benchmark all configured DNS servers.
        
        Args:
            domain: Domain to query
            servers: Dict of server names to IP lists
            iterations: Number of queries per server
            parallel: Run benchmarks in parallel
        
        Returns:
            List of BenchmarkResults sorted by average response time
        """
        servers = servers or PUBLIC_DNS_SERVERS
        
        # Flatten to list of (name, ip) tuples
        server_list = []
        for name, ips in servers.items():
            for ip in ips:
                server_list.append((name, ip))
        
        results = []
        
        if parallel:
            with ThreadPoolExecutor(max_workers=len(server_list)) as executor:
                futures = {
                    executor.submit(
                        self.benchmark_server, domain, ip, name, iterations
                    ): (name, ip)
                    for name, ip in server_list
                }
                for future in futures:
                    results.append(future.result())
        else:
            for name, ip in server_list:
                results.append(
                    self.benchmark_server(domain, ip, name, iterations)
                )
        
        # Sort by average response time
        results.sort(key=lambda r: r.avg_ms if r.avg_ms else float("inf"))
        
        return results
    
    def find_fastest_server(
        self,
        domain: str,
        servers: dict[str, list[str]] | None = None,
        iterations: int = 3,
    ) -> BenchmarkResult | None:
        """Find the fastest DNS server for a domain."""
        results = self.benchmark_all_servers(domain, servers, iterations)
        return results[0] if results else None
    
    def compare_servers(
        self,
        domain: str,
        server_ips: list[str],
        iterations: int = 5,
    ) -> list[BenchmarkResult]:
        """Compare response times of specific DNS servers."""
        results = []
        for ip in server_ips:
            results.append(self.benchmark_server(domain, ip, ip, iterations))
        
        results.sort(key=lambda r: r.avg_ms if r.avg_ms else float("inf"))
        return results
    
    def latency_report(
        self,
        domain: str,
        servers: dict[str, list[str]] | None = None,
    ) -> dict:
        """Generate a comprehensive latency report."""
        results = self.benchmark_all_servers(domain, servers, iterations=5)
        
        all_times = []
        for r in results:
            all_times.extend(r.measurements)
        
        report = {
            "domain": domain,
            "total_servers_tested": len(results),
            "overall_stats": {
                "min_ms": min(all_times) if all_times else None,
                "max_ms": max(all_times) if all_times else None,
                "avg_ms": statistics.mean(all_times) if all_times else None,
                "median_ms": statistics.median(all_times) if all_times else None,
            },
            "fastest_server": None,
            "slowest_server": None,
            "server_rankings": [],
        }
        
        if results:
            fastest = results[0]
            slowest = max(results, key=lambda r: r.avg_ms if r.avg_ms else 0)
            
            report["fastest_server"] = {
                "name": fastest.server,
                "ip": fastest.server_ip,
                "avg_ms": fastest.avg_ms,
            }
            report["slowest_server"] = {
                "name": slowest.server,
                "ip": slowest.server_ip,
                "avg_ms": slowest.avg_ms,
            }
            report["server_rankings"] = [
                {
                    "rank": i + 1,
                    "server": r.server,
                    "ip": r.server_ip,
                    "avg_ms": round(r.avg_ms, 2) if r.avg_ms else None,
                    "success_rate": round(r.success_rate * 100, 1),
                }
                for i, r in enumerate(results)
            ]
        
        return report
