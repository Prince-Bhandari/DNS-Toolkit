"""Reverse DNS lookup functionality."""
import dns.resolver
import dns.reversename
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from .utils import DNSResult, is_valid_ipv4, is_valid_ipv6
class ReverseLookup:
    """Perform reverse DNS lookups (PTR records)."""
    
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
    
    def lookup(self, ip: str) -> DNSResult:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip: IPv4 or IPv6 address
        
        Returns:
            DNSResult with PTR records (hostnames)
        """
        ip = ip.strip()
        
        if not (is_valid_ipv4(ip) or is_valid_ipv6(ip)):
            return DNSResult(
                domain=ip,
                record_type="PTR",
                error="Invalid IP address",
            )
        
        try:
            # Convert IP to reverse DNS name
            reverse_name = dns.reversename.from_address(ip)
            
            import time
            start = time.perf_counter()
            answers = self.resolver.resolve(reverse_name, "PTR")
            query_time = (time.perf_counter() - start) * 1000
            
            hostnames = [str(rdata.target).rstrip(".") for rdata in answers]
            
            return DNSResult(
                domain=ip,
                record_type="PTR",
                records=hostnames,
                ttl=answers.rrset.ttl if answers.rrset else None,
                query_time_ms=query_time,
            )
            
        except dns.resolver.NXDOMAIN:
            return DNSResult(
                domain=ip,
                record_type="PTR",
                error="No PTR record found",
            )
        except dns.resolver.NoAnswer:
            return DNSResult(
                domain=ip,
                record_type="PTR",
                error="No PTR record found",
            )
        except Exception as e:
            return DNSResult(
                domain=ip,
                record_type="PTR",
                error=str(e),
            )
    
    def lookup_range(
        self,
        cidr: str,
        max_hosts: int = 256,
        parallel: bool = True,
        max_workers: int = 20,
    ) -> dict[str, DNSResult]:
        """
        Perform reverse lookups for an IP range (CIDR notation).
        
        Args:
            cidr: IP range in CIDR notation (e.g., "192.168.1.0/24")
            max_hosts: Maximum number of hosts to check
            parallel: Perform lookups in parallel
            max_workers: Number of parallel workers
        
        Returns:
            Dictionary mapping IPs to their PTR results
        """
        try:
            network = ip_network(cidr, strict=False)
        except ValueError as e:
            return {"error": DNSResult(domain=cidr, record_type="PTR", error=str(e))}
        
        # Limit number of hosts
        hosts = list(network.hosts())[:max_hosts]
        
        results = {}
        
        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {
                    executor.submit(self.lookup, str(host)): str(host)
                    for host in hosts
                }
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    results[ip] = future.result()
        else:
            for host in hosts:
                results[str(host)] = self.lookup(str(host))
        
        return results
    
    def verify_forward_reverse(self, hostname: str) -> dict[str, any]:
        """
        Verify forward-confirmed reverse DNS (FCrDNS).
        
        Checks if the hostname resolves to an IP, and that IP's 
        PTR record points back to the hostname.
        """
        result = {
            "hostname": hostname,
            "forward_ips": [],
            "reverse_hostnames": {},
            "fcrdns_valid": False,
            "matching_ips": [],
        }
        
        # Forward lookup
        try:
            answers = self.resolver.resolve(hostname, "A")
            result["forward_ips"] = [str(r) for r in answers]
        except Exception:
            pass
        
        try:
            answers = self.resolver.resolve(hostname, "AAAA")
            result["forward_ips"].extend(str(r) for r in answers)
        except Exception:
            pass
        
        if not result["forward_ips"]:
            return result
        
        # Reverse lookup for each IP
        hostname_lower = hostname.lower().rstrip(".")
        
        for ip in result["forward_ips"]:
            ptr_result = self.lookup(ip)
            if not ptr_result.error and ptr_result.records:
                result["reverse_hostnames"][ip] = ptr_result.records
                
                # Check if any PTR matches the original hostname
                for ptr_hostname in ptr_result.records:
                    if ptr_hostname.lower().rstrip(".") == hostname_lower:
                        result["matching_ips"].append(ip)
                        break
        
        result["fcrdns_valid"] = len(result["matching_ips"]) > 0
        return result
    
    def bulk_lookup(
        self,
        ips: list[str],
        parallel: bool = True,
        max_workers: int = 20,
    ) -> dict[str, DNSResult]:
        """
        Perform reverse lookups for multiple IPs.
        
        Args:
            ips: List of IP addresses
            parallel: Perform lookups in parallel
            max_workers: Number of parallel workers
        
        Returns:
            Dictionary mapping IPs to their PTR results
        """
        results = {}
        
        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {
                    executor.submit(self.lookup, ip): ip
                    for ip in ips
                }
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    results[ip] = future.result()
        else:
            for ip in ips:
                results[ip] = self.lookup(ip)
        
        return results