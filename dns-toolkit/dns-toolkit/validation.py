"""Domain name validation and analysis."""
import re
import socket
from dataclasses import dataclass
import tldextract
import validators
from .lookup import DNSLookup
from .utils import normalize_domain
@dataclass
class ValidationResult:
    """Result of domain validation."""
    domain: str
    is_valid_format: bool
    is_resolvable: bool
    is_registered: bool
    tld: str
    subdomain: str
    registered_domain: str
    punycode: str | None = None
    is_idn: bool = False
    issues: list[str] = None
    
    def __post_init__(self):
        if self.issues is None:
            self.issues = []
class DomainValidator:
    """Validate and analyze domain names."""
    
    # Valid TLD pattern (letters only, 2-63 chars)
    TLD_PATTERN = re.compile(r"^[a-zA-Z]{2,63}$")
    
    # Valid label pattern (letters, digits, hyphens; no leading/trailing hyphens)
    LABEL_PATTERN = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")
    
    # IDN/Punycode pattern
    PUNYCODE_PATTERN = re.compile(r"^xn--[a-zA-Z0-9-]+$")
    
    def __init__(self):
        self.lookup = DNSLookup()
    
    def validate(self, domain: str, check_dns: bool = True) -> ValidationResult:
        """
        Validate a domain name.
        
        Args:
            domain: Domain name to validate
            check_dns: Whether to check DNS resolution
        
        Returns:
            ValidationResult with validation details
        """
        domain = normalize_domain(domain)
        
        # Extract domain components
        ext = tldextract.extract(domain)
        
        result = ValidationResult(
            domain=domain,
            is_valid_format=False,
            is_resolvable=False,
            is_registered=False,
            tld=ext.suffix,
            subdomain=ext.subdomain,
            registered_domain=ext.registered_domain,
        )
        
        # Check format validity
        format_valid, issues = self._validate_format(domain, ext)
        result.is_valid_format = format_valid
        result.issues = issues
        
        # Check for IDN (internationalized domain name)
        if self._is_idn(domain):
            result.is_idn = True
            try:
                result.punycode = domain.encode("idna").decode("ascii")
            except Exception:
                result.issues.append("Invalid IDN encoding")
        
        if not format_valid:
            return result
        
        # Check DNS resolution
        if check_dns:
            result.is_resolvable = self._check_resolvable(domain)
            result.is_registered = self._check_registered(domain)
        
        return result
    
    def _validate_format(
        self,
        domain: str,
        ext: tldextract.tldextract.ExtractResult,
    ) -> tuple[bool, list[str]]:
        """Validate domain format and return issues."""
        issues = []
        
        # Check overall length
        if len(domain) > 253:
            issues.append("Domain exceeds 253 characters")
        
        # Check TLD
        if not ext.suffix:
            issues.append("No valid TLD found")
        
        # Check each label
        labels = domain.split(".")
        for label in labels:
            if not label:
                issues.append("Empty label (consecutive dots)")
                continue
            
            if len(label) > 63:
                issues.append(f"Label '{label}' exceeds 63 characters")
            
            # Check for valid characters (allowing punycode)
            if not self.LABEL_PATTERN.match(label) and not self.PUNYCODE_PATTERN.match(label):
                # Check if it's valid IDN
                try:
                    label.encode("idna")
                except Exception:
                    issues.append(f"Invalid characters in label '{label}'")
        
        # Use validators library as additional check
        if not validators.domain(domain):
            if not issues:
                issues.append("Invalid domain format")
        
        return len(issues) == 0, issues
    
    def _is_idn(self, domain: str) -> bool:
        """Check if domain contains non-ASCII characters."""
        try:
            domain.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True
    
    def _check_resolvable(self, domain: str) -> bool:
        """Check if domain resolves to any IP."""
        for record_type in ["A", "AAAA"]:
            result = self.lookup.lookup(domain, record_type)
            if not result.error and result.records:
                return True
        return False
    
    def _check_registered(self, domain: str) -> bool:
        """Check if domain is registered (has NS records)."""
        result = self.lookup.lookup(domain, "NS")
        return not result.error and bool(result.records)
    
    def is_valid(self, domain: str) -> bool:
        """Quick check if domain format is valid."""
        domain = normalize_domain(domain)
        return validators.domain(domain) is True
    
    def extract_parts(self, domain: str) -> dict[str, str]:
        """Extract domain components."""
        domain = normalize_domain(domain)
        ext = tldextract.extract(domain)
        return {
            "subdomain": ext.subdomain,
            "domain": ext.domain,
            "tld": ext.suffix,
            "registered_domain": ext.registered_domain,
            "fqdn": ext.fqdn,
        }
    
    def compare_domains(self, domain1: str, domain2: str) -> dict[str, any]:
        """Compare two domains for similarity and relationship."""
        d1 = normalize_domain(domain1)
        d2 = normalize_domain(domain2)
        
        ext1 = tldextract.extract(d1)
        ext2 = tldextract.extract(d2)
        
        return {
            "domain1": d1,
            "domain2": d2,
            "same_registered_domain": ext1.registered_domain == ext2.registered_domain,
            "same_tld": ext1.suffix == ext2.suffix,
            "same_domain": ext1.domain == ext2.domain,
            "is_subdomain_of": (
                ext1.registered_domain == ext2.registered_domain and
                ext1.subdomain and not ext2.subdomain
            ),
            "levenshtein_distance": self._levenshtein(ext1.domain, ext2.domain),
        }
    
    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        
        if len(s2) == 0:
            return len(s1)
        
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        
        return prev_row[-1]
    
    def suggest_typos(self, domain: str) -> list[str]:
        """Generate common typo variations of a domain."""
        domain = normalize_domain(domain)
        ext = tldextract.extract(domain)
        name = ext.domain
        
        suggestions = set()
        
        # Character swaps
        for i in range(len(name) - 1):
            swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
            suggestions.add(f"{swapped}.{ext.suffix}")
        
        # Missing characters
        for i in range(len(name)):
            missing = name[:i] + name[i+1:]
            if missing:
                suggestions.add(f"{missing}.{ext.suffix}")
        
        # Double characters
        for i in range(len(name)):
            doubled = name[:i] + name[i] + name[i:]
            suggestions.add(f"{doubled}.{ext.suffix}")
        
        # Common replacements
        replacements = {
            "o": "0", "0": "o",
            "l": "1", "1": "l",
            "i": "1", 
            "s": "5", "5": "s",
            "a": "4",
        }
        for i, char in enumerate(name):
            if char in replacements:
                replaced = name[:i] + replacements[char] + name[i+1:]
                suggestions.add(f"{replaced}.{ext.suffix}")
        
        # Alternative TLDs
        alt_tlds = ["com", "net", "org", "io", "co"]
        for tld in alt_tlds:
            if tld != ext.suffix:
                suggestions.add(f"{name}.{tld}")
        
        suggestions.discard(domain)
        return sorted(suggestions)
