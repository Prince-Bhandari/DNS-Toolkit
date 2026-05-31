#!/usr/bin/env python3
"""DNS Toolkit CLI - Comprehensive DNS analysis tool."""
import json
import sys
from datetime import datetime
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from dns_toolkit import (
    DNSLookup,
    RecordFetcher,
    ReverseLookup,
    DomainValidator,
    WhoisLookup,
    PropagationChecker,
    ResponseTimer,
    DNSSECChecker,
    BlacklistChecker,
    SubdomainEnumerator,
    DNSCache,
)
console = Console()
@click.group()
@click.version_option(version="1.0.0")
def main():
    """DNS Toolkit - Comprehensive DNS analysis tool."""
    pass
@main.command()
@click.argument("domain")
@click.option("-t", "--type", "record_type", default="A", help="Record type (A, AAAA, MX, etc.)")
@click.option("-s", "--server", help="DNS server to use")
@click.option("--all", "all_records", is_flag=True, help="Fetch all record types")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def lookup(domain: str, record_type: str, server: str, all_records: bool, json_output: bool):
    """Perform DNS lookup for a domain."""
    nameservers = [server] if server else None
    dns = DNSLookup(nameservers=nameservers)
    
    if all_records:
        results = dns.lookup_all(domain)
        
        if json_output:
            output = {rt: r.to_dict() for rt, r in results.items()}
            console.print_json(json.dumps(output, indent=2))
        else:
            for rt, result in results.items():
                if not result.error and result.records:
                    table = Table(title=f"{rt} Records")
                    table.add_column("Value", style="cyan")
                    table.add_column("TTL", style="green")
                    
                    for record in result.records:
                        table.add_row(record, str(result.ttl or "-"))
                    
                    console.print(table)
    else:
        result = dns.lookup(domain, record_type)
        
        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2))
        else:
            if result.error:
                console.print(f"[red]Error:[/red] {result.error}")
            else:
                table = Table(title=f"{record_type} Records for {domain}")
                table.add_column("Record", style="cyan")
                table.add_column("TTL", style="green")
                table.add_column("Query Time", style="yellow")
                
                for record in result.records:
                    table.add_row(
                        record,
                        str(result.ttl or "-"),
                        f"{result.query_time_ms:.2f}ms"
                    )
                
                console.print(table)
@main.command()
@click.argument("ip")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def reverse(ip: str, json_output: bool):
    """Perform reverse DNS lookup for an IP address."""
    rlookup = ReverseLookup()
    result = rlookup.lookup(ip)
    
    if json_output:
        console.print_json(json.dumps(result.to_dict(), indent=2))
    else:
        if result.error:
            console.print(f"[red]Error:[/red] {result.error}")
        else:
            console.print(Panel(
                "\n".join(result.records),
                title=f"PTR Records for {ip}"
            ))
@main.command()
@click.argument("domain")
@click.option("--check-dns/--no-check-dns", default=True, help="Check DNS resolution")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def validate(domain: str, check_dns: bool, json_output: bool):
    """Validate a domain name."""
    validator = DomainValidator()
    result = validator.validate(domain, check_dns=check_dns)
    
    if json_output:
        console.print_json(json.dumps({
            "domain": result.domain,
            "is_valid_format": result.is_valid_format,
            "is_resolvable": result.is_resolvable,
            "is_registered": result.is_registered,
            "tld": result.tld,
            "subdomain": result.subdomain,
            "registered_domain": result.registered_domain,
            "is_idn": result.is_idn,
            "punycode": result.punycode,
            "issues": result.issues,
        }, indent=2))
    else:
        table = Table(title=f"Validation Results for {domain}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Valid Format", "✓" if result.is_valid_format else "✗")
        table.add_row("Resolvable", "✓" if result.is_resolvable else "✗")
        table.add_row("Registered", "✓" if result.is_registered else "✗")
        table.add_row("TLD", result.tld)
        table.add_row("Subdomain", result.subdomain or "-")
        table.add_row("Registered Domain", result.registered_domain)
        table.add_row("IDN", "Yes" if result.is_idn else "No")
        
        if result.punycode:
            table.add_row("Punycode", result.punycode)
        
        if result.issues:
            table.add_row("Issues", "\n".join(result.issues))
        
        console.print(table)
@main.command()
@click.argument("domain")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def whois(domain: str, json_output: bool):
    """Perform WHOIS lookup for a domain."""
    lookup = WhoisLookup()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Querying WHOIS...", total=None)
        result = lookup.lookup(domain)
    
    if json_output:
        output = {
            "domain": result.domain,
            "registrar": result.registrar,
            "creation_date": result.creation_date.isoformat() if result.creation_date else None,
            "expiration_date": result.expiration_date.isoformat() if result.expiration_date else None,
            "updated_date": result.updated_date.isoformat() if result.updated_date else None,
            "name_servers": result.name_servers,
            "status": result.status,
            "registrant": result.registrant,
            "dnssec": result.dnssec,
            "days_until_expiry": result.days_until_expiry,
            "domain_age_days": result.domain_age_days,
            "error": result.error,
        }
        console.print_json(json.dumps(output, indent=2, default=str))
    else:
        if result.error:
            console.print(f"[red]Error:[/red] {result.error}")
            return
        
        table = Table(title=f"WHOIS Information for {domain}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Registrar", result.registrar or "-")
        table.add_row("Created", str(result.creation_date or "-"))
        table.add_row("Expires", str(result.expiration_date or "-"))
        table.add_row("Updated", str(result.updated_date or "-"))
        
        if result.days_until_expiry is not None:
            color = "red" if result.days_until_expiry < 30 else "green"
            table.add_row("Days Until Expiry", f"[{color}]{result.days_until_expiry}[/{color}]")
        
        if result.domain_age_days is not None:
            table.add_row("Domain Age", f"{result.domain_age_days} days")
        
        table.add_row("Name Servers", "\n".join(result.name_servers) or "-")
        table.add_row("Status", "\n".join(result.status) or "-")
        table.add_row("DNSSEC", result.dnssec or "-")
        
        console.print(table)
@main.command()
@click.argument("domain")
@click.option("-t", "--type", "record_type", default="A", help="Record type to check")
@click.option("--expected", help="Expected value to verify")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def propagation(domain: str, record_type: str, expected: str, json_output: bool):
    """Check DNS propagation across global servers."""
    checker = PropagationChecker()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Checking propagation...", total=None)
        report = checker.check(domain, record_type, expected)
    
    if json_output:
        output = {
            "domain": report.domain,
            "record_type": report.record_type,
            "expected_value": report.expected_value,
            "total_servers": report.total_servers,
            "propagated_count": report.propagated_count,
            "propagation_percentage": report.propagation_percentage,
            "is_fully_propagated": report.is_fully_propagated,
            "results": [
                {
                    "server": r.server_name,
                    "ip": r.server_ip,
                    "records": r.records,
                    "propagated": r.propagated,
                    "response_time_ms": r.response_time_ms,
                    "error": r.error,
                }
                for r in report.results
            ],
        }
        console.print_json(json.dumps(output, indent=2))
    else:
        table = Table(title=f"Propagation Status for {domain} ({record_type})")
        table.add_column("Server", style="cyan")
        table.add_column("IP", style="dim")
        table.add_column("Records", style="white")
        table.add_column("Status", style="green")
        table.add_column("Time", style="yellow")
        
        for r in report.results:
            status = "[green]✓[/green]" if r.propagated else "[red]✗[/red]"
            if r.error:
                status = f"[red]{r.error[:20]}[/red]"
            
            table.add_row(
                r.server_name,
                r.server_ip,
                ", ".join(r.records) or "-",
                status,
                f"{r.response_time_ms:.1f}ms"
            )
        
        console.print(table)
        console.print(f"\n[bold]Propagation:[/bold] {report.propagated_count}/{report.total_servers} "
                     f"({report.propagation_percentage:.1f}%)")
@main.command()
@click.argument("domain")
@click.option("-n", "--iterations", default=5, help="Number of queries per server")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def benchmark(domain: str, iterations: int, json_output: bool):
    """Benchmark DNS server response times."""
    timer = ResponseTimer()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Benchmarking servers...", total=None)
        results = timer.benchmark_all_servers(domain, iterations=iterations)
    
    if json_output:
        output = [
            {
                "server": r.server,
                "ip": r.server_ip,
                "avg_ms": r.avg_ms,
                "min_ms": r.min_ms,
                "max_ms": r.max_ms,
                "success_rate": r.success_rate,
            }
            for r in results
        ]
        console.print_json(json.dumps(output, indent=2))
    else:
        table = Table(title=f"DNS Server Benchmark for {domain}")
        table.add_column("Rank", style="cyan")
        table.add_column("Server", style="white")
        table.add_column("Avg (ms)", style="green")
        table.add_column("Min (ms)", style="dim")
        table.add_column("Max (ms)", style="dim")
        table.add_column("Success", style="yellow")
        
        for i, r in enumerate(results, 1):
            table.add_row(
                str(i),
                f"{r.server} ({r.server_ip})",
                f"{r.avg_ms:.2f}" if r.avg_ms else "-",
                f"{r.min_ms:.2f}" if r.min_ms else "-",
                f"{r.max_ms:.2f}" if r.max_ms else "-",
                f"{r.success_rate * 100:.0f}%"
            )
        
        console.print(table)
@main.command()
@click.argument("domain")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def dnssec(domain: str, json_output: bool):
    """Check DNSSEC configuration for a domain."""
    checker = DNSSECChecker()
    result = checker.check(domain)
    
    if json_output:
        output = {
            "domain": result.domain,
            "dnssec_enabled": result.dnssec_enabled,
            "validated": result.validated,
            "algorithm": result.algorithm,
            "nsec_type": result.nsec_type,
            "has_dnskey": len(result.dnskey_records) > 0,
            "has_ds": len(result.ds_records) > 0,
            "errors": result.errors,
        }
        console.print_json(json.dumps(output, indent=2))
    else:
        status = "[green]Enabled[/green]" if result.dnssec_enabled else "[red]Disabled[/red]"
        console.print(Panel(
            f"DNSSEC: {status}\n"
            f"Validated: {'Yes' if result.validated else 'No'}\n"
            f"Algorithm: {result.algorithm or 'N/A'}\n"
            f"NSEC Type: {result.nsec_type or 'N/A'}\n"
            f"DNSKEY Records: {len(result.dnskey_records)}\n"
            f"DS Records: {len(result.ds_records)}",
            title=f"DNSSEC Status for {domain}"
        ))
@main.command()
@click.argument("ip")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def blacklist(ip: str, json_output: bool):
    """Check if an IP is on DNS blacklists."""
    checker = BlacklistChecker()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Checking blacklists...", total=None)
        report = checker.check(ip)
    
    if json_output:
        output = {
            "ip": report.ip,
            "is_clean": report.is_clean,
            "listed_count": report.listed_count,
            "total_checked": report.total_checked,
            "listed_on": report.listed_on,
            "results": [
                {
                    "blacklist": r.blacklist,
                    "listed": r.listed,
                    "reason": r.reason,
                }
                for r in report.results
            ],
        }
        console.print_json(json.dumps(output, indent=2))
    else:
        table = Table(title=f"Blacklist Check for {ip}")
        table.add_column("Blacklist", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Reason", style="yellow")
        
        for r in report.results:
            status = "[red]LISTED[/red]" if r.listed else "[green]Clean[/green]"
            if r.error:
                status = f"[dim]{r.error[:15]}[/dim]"
            
            table.add_row(r.blacklist, status, r.reason or "-")
        
        console.print(table)
        
        if report.is_clean:
            console.print(f"\n[green]✓ IP is clean - not listed on any blacklist[/green]")
        else:
            console.print(f"\n[red]✗ IP is listed on {report.listed_count} blacklist(s)[/red]")
@main.command()
@click.argument("domain")
@click.option("--wordlist", "-w", help="Path to wordlist file")
@click.option("--comprehensive", "-c", is_flag=True, help="Use all discovery methods")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def subdomains(domain: str, wordlist: str, comprehensive: bool, json_output: bool):
    """Enumerate subdomains for a domain."""
    enumerator = SubdomainEnumerator()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Discovering subdomains...", total=None)
        
        if comprehensive:
            report = enumerator.comprehensive_scan(domain)
        elif wordlist:
            report = enumerator.enumerate_from_file(domain, wordlist)
        else:
            report = enumerator.enumerate(domain)
    
    if json_output:
        output = {
            "domain": report.domain,
            "total_checked": report.total_checked,
            "found_count": report.found_count,
            "subdomains": report.found_subdomains,
        }
        console.print_json(json.dumps(output, indent=2))
    else:
        if report.found_count == 0:
            console.print("[yellow]No subdomains found[/yellow]")
            return
        
        table = Table(title=f"Subdomains for {domain}")
        table.add_column("Subdomain", style="cyan")
        table.add_column("A Records", style="green")
        table.add_column("CNAME", style="yellow")
        
        for s in report.subdomains:
            if s.exists:
                table.add_row(
                    s.full_domain,
                    ", ".join(s.a_records) or "-",
                    ", ".join(s.cname_records) or "-"
                )
        
        console.print(table)
        console.print(f"\n[bold]Found:[/bold] {report.found_count} subdomains")
@main.command()
@click.argument("domain")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def email(domain: str, json_output: bool):
    """Check email-related DNS records (MX, SPF, DKIM, DMARC)."""
    fetcher = RecordFetcher()
    result = fetcher.check_email_records(domain)
    
    if json_output:
        console.print_json(json.dumps(result, indent=2))
    else:
        table = Table(title=f"Email DNS Configuration for {domain}")
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="white")
        
        mx_status = "[green]✓[/green]" if result["mx_configured"] else "[red]✗[/red]"
        table.add_row("MX Records", mx_status, ", ".join(result["mx_records"]) or "-")
        
        spf_status = "[green]✓[/green]" if result["spf_configured"] else "[red]✗[/red]"
        table.add_row("SPF Record", spf_status, result["spf_record"] or "-")
        
        dmarc_status = "[green]✓[/green]" if result["dmarc_configured"] else "[red]✗[/red]"
        table.add_row("DMARC Record", dmarc_status, result["dmarc_record"] or "-")
        
        dkim_info = ", ".join(result["dkim_selector_hints"]) if result["dkim_selector_hints"] else "-"
        table.add_row("DKIM Selectors", "[dim]found[/dim]" if result["dkim_selector_hints"] else "[dim]-[/dim]", dkim_info)
        
        console.print(table)
        
        if result["issues"]:
            console.print("\n[yellow]Issues:[/yellow]")
            for issue in result["issues"]:
                console.print(f"  • {issue}")
@main.command()
@click.argument("domain")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def full(domain: str, json_output: bool):
    """Comprehensive DNS analysis (all checks)."""
    results = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Validation
        task = progress.add_task("Validating domain...", total=6)
        validator = DomainValidator()
        results["validation"] = validator.validate(domain, check_dns=True)
        progress.update(task, advance=1)
        
        # DNS Records
        progress.update(task, description="Fetching DNS records...")
        fetcher = RecordFetcher()
        results["records"] = fetcher.get_all_records(domain)
        progress.update(task, advance=1)
        
        # WHOIS
        progress.update(task, description="Querying WHOIS...")
        whois_lookup = WhoisLookup()
        results["whois"] = whois_lookup.lookup(domain)
        progress.update(task, advance=1)
        
        # DNSSEC
        progress.update(task, description="Checking DNSSEC...")
        dnssec_checker = DNSSECChecker()
        results["dnssec"] = dnssec_checker.check(domain)
        progress.update(task, advance=1)
        
        # Email records
        progress.update(task, description="Checking email config...")
        results["email"] = fetcher.check_email_records(domain)
        progress.update(task, advance=1)
        
        # Propagation
        progress.update(task, description="Checking propagation...")
        prop_checker = PropagationChecker()
        results["propagation"] = prop_checker.check(domain)
        progress.update(task, advance=1)
    
    if json_output:
        output = {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat(),
            "validation": {
                "is_valid": results["validation"].is_valid_format,
                "is_resolvable": results["validation"].is_resolvable,
                "tld": results["validation"].tld,
            },
            "whois": {
                "registrar": results["whois"].registrar,
                "created": str(results["whois"].creation_date) if results["whois"].creation_date else None,
                "expires": str(results["whois"].expiration_date) if results["whois"].expiration_date else None,
                "days_until_expiry": results["whois"].days_until_expiry,
            },
            "dnssec": {
                "enabled": results["dnssec"].dnssec_enabled,
                "validated": results["dnssec"].validated,
            },
            "email": results["email"],
            "propagation": {
                "percentage": results["propagation"].propagation_percentage,
                "fully_propagated": results["propagation"].is_fully_propagated,
            },
            "records": {
                rt: [str(r.value) for r in records]
                for rt, records in results["records"].items()
            },
        }
        console.print_json(json.dumps(output, indent=2, default=str))
    else:
        # Display comprehensive results
        console.print(Panel(
            f"[bold]Domain:[/bold] {domain}\n"
            f"[bold]Valid:[/bold] {'✓' if results['validation'].is_valid_format else '✗'}\n"
            f"[bold]Resolvable:[/bold] {'✓' if results['validation'].is_resolvable else '✗'}\n"
            f"[bold]TLD:[/bold] {results['validation'].tld}",
            title="Domain Info"
        ))
        
        if results["whois"].registrar:
            console.print(Panel(
                f"[bold]Registrar:[/bold] {results['whois'].registrar}\n"
                f"[bold]Created:[/bold] {results['whois'].creation_date or '-'}\n"
                f"[bold]Expires:[/bold] {results['whois'].expiration_date or '-'}\n"
                f"[bold]Days Until Expiry:[/bold] {results['whois'].days_until_expiry or '-'}",
                title="WHOIS"
            ))
        
        dnssec_status = "[green]Enabled[/green]" if results["dnssec"].dnssec_enabled else "[red]Disabled[/red]"
        console.print(Panel(f"Status: {dnssec_status}", title="DNSSEC"))
        
        email = results["email"]
        console.print(Panel(
            f"MX: {'✓' if email['mx_configured'] else '✗'} | "
            f"SPF: {'✓' if email['spf_configured'] else '✗'} | "
            f"DMARC: {'✓' if email['dmarc_configured'] else '✗'}",
            title="Email Config"
        ))
        
        prop = results["propagation"]
        console.print(Panel(
            f"Propagation: {prop.propagation_percentage:.1f}% "
            f"({prop.propagated_count}/{prop.total_servers} servers)",
            title="Propagation"
        ))
        
        # DNS Records table
        table = Table(title="DNS Records")
        table.add_column("Type", style="cyan")
        table.add_column("Records", style="green")
        
        for rt, records in results["records"].items():
            values = ", ".join(r.value for r in records[:3])
            if len(records) > 3:
                values += f" (+{len(records) - 3} more)"
            table.add_row(rt, values)
        
        console.print(table)
if __name__ == "__main__":
    main()
