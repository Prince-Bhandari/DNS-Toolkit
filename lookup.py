"""Core DNS lookup functionality."""
import dns.resolver
import dns.rdatatype
import dns.exception
import time
from typing import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import DNSResult, RECORD_TYPES, normalize_domain
class DNSLookup:
    """Perform DNS lookups with various options."""
    
    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
        lifetime: float = 10.0,
    ):
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime
    
    def lookup(
        self,
        domain: str,
        record_type: str = "A",
        raise_on_error: bool = False,
    ) -> DNSResult:
        """
        Perform a DNS lookup for the specified record type.
        
        Args:
            domain: Domain name to query
            record_type: DNS record type (A, AAAA, MX, etc.)
            raise_on_error: If True, raise exceptions instead of returning error in result
        
        Returns:
            DNSResult containing the query results
        """
        domain = normalize_domain(domain)
        record_type = record_type.upper()
        
        start_time = time.perf_counter()
        
        try:
            answers = self.resolver.resolve(domain, record_type)
            query_time = (time.perf_counter() - start_time) * 1000
            
            records = []
            for rdata in answers:
                if record_type == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == "SOA":
                    records.append(
                        f"{rdata.mname} {rdata.rname} {rdata.serial} "
                        f"{rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}"
                    )
                elif record_type == "SRV":
                    records.append(
                        f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                    )
                elif record_type == "CAA":
                    records.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
                else:
                    records.append(str(rdata))
            
            return DNSResult(
                domain=domain,
                record_type=record_type,
                records=records,
                ttl=answers.rrset.ttl if answers.rrset else None,
                query_time_ms=query_time,
                nameserver=self.resolver.nameservers[0] if self.resolver.nameservers else "",
            )
            
        except dns.resolver.NXDOMAIN:
            error_msg = f"Domain {domain} does not exist"
        except dns.resolver.NoAnswer:
            error_msg = f"No {record_type} records found for {domain}"
        except dns.resolver.NoNameservers:
            error_msg = "No nameservers available"
        except dns.exception.Timeout:
            error_msg = "Query timed out"
        except dns.exception.DNSException as e:
            error_msg = str(e)
        
        query_time = (time.perf_counter() - start_time) * 1000
        
        if raise_on_error:
            raise dns.exception.DNSException(error_msg)
        
        return DNSResult(
            domain=domain,
            record_type=record_type,
            query_time_ms=query_time,
            error=error_msg,
        )
    
    def lookup_all(
        self,
        domain: str,
        record_types: list[str] | None = None,
        parallel: bool = True,
        max_workers: int = 10,
    ) -> dict[str, DNSResult]:
        """
        Look up multiple record types for a domain.
        
        Args:
            domain: Domain name to query
            record_types: List of record types to query (defaults to common types)
            parallel: If True, perform lookups in parallel
            max_workers: Maximum number of parallel workers
        
        Returns:
            Dictionary mapping record types to their results
        """
        if record_types is None:
            record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
        
        results = {}
        
        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_type = {
                    executor.submit(self.lookup, domain, rt): rt
                    for rt in record_types
                }
                for future in as_completed(future_to_type):
                    rt = future_to_type[future]
                    results[rt] = future.result()
        else:
            for rt in record_types:
                results[rt] = self.lookup(domain, rt)
        
        return results
    
    def trace(self, domain: str, record_type: str = "A") -> list[DNSResult]:
        """
        Trace DNS resolution from root servers down.
        
        Returns list of results showing the resolution path.
        """
        domain = normalize_domain(domain)
        trace_results = []
        
        # Start with root servers
        root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12"]
        
        current_servers = root_servers
        parts = domain.split(".")
        
        for i in range(len(parts)):
            query_domain = ".".join(parts[-(i+1):]) if i < len(parts) - 1 else domain
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = current_servers[:3]
            resolver.timeout = 3.0
            
            try:
                start = time.perf_counter()
                
                # Try to get NS records for the zone
                try:
                    ns_answer = resolver.resolve(query_domain, "NS")
                    ns_records = [str(r) for r in ns_answer]
                    
                    # Resolve NS hostnames to IPs
                    new_servers = []
                    for ns in ns_records[:3]:
                        try:
                            a_answer = resolver.resolve(ns.rstrip("."), "A")
                            new_servers.extend(str(r) for r in a_answer)
                        except Exception:
                            pass
                    
                    if new_servers:
                        current_servers = new_servers
                    
                    query_time = (time.perf_counter() - start) * 1000
                    trace_results.append(DNSResult(
                        domain=query_domain,
                        record_type="NS",
                        records=ns_records,
                        query_time_ms=query_time,
                        nameserver=resolver.nameservers[0],
                    ))
                except dns.resolver.NoAnswer:
                    pass
                    
            except Exception as e:
                trace_results.append(DNSResult(
                    domain=query_domain,
                    record_type="NS",
                    error=str(e),
                ))
        
        # Final resolution
        final_result = self.lookup(domain, record_type)
        trace_results.append(final_result)
        
        return trace_results
    
    def iterative_lookup(self, domain: str, record_type: str = "A") -> Iterator[DNSResult]:
        """Generator yielding each step of DNS resolution."""
        for result in self.trace(domain, record_type):
            yield result