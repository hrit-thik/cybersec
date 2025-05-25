class Vulnerability:
    """
    Base class for different types of vulnerabilities.
    """
    def __init__(self, name: str, description: str, default_criticality: str, cwe_id: str):
        """
        Initializes a new Vulnerability instance.

        Args:
            name: The common name of the vulnerability (e.g., "SQL Injection").
            description: A brief explanation of the vulnerability.
            default_criticality: The typical criticality level (e.g., "High", "Medium", "Low").
            cwe_id: The Common Weakness Enumeration (CWE) ID.
        """
        self.name = name
        self.description = description
        self.default_criticality = default_criticality
        self.cwe_id = cwe_id

    def __str__(self):
        return f"{self.name} ({self.cwe_id}) - Criticality: {self.default_criticality}"

class SQLInjectionVulnerability(Vulnerability):
    """
    Represents a SQL Injection vulnerability.
    """
    def __init__(self):
        super().__init__(
            name="SQL Injection",
            description="Allows attackers to execute arbitrary SQL queries on the database, potentially leading to unauthorized data access, modification, or deletion.",
            default_criticality="High",
            cwe_id="CWE-89"
        )

class XSSVulnerability(Vulnerability):
    """
    Represents a Cross-Site Scripting (XSS) vulnerability.
    """
    def __init__(self):
        super().__init__(
            name="Cross-Site Scripting (XSS)",
            description="Allows attackers to inject malicious scripts into web pages viewed by other users, potentially leading to session hijacking, data theft, or defacement.",
            default_criticality="High", # Typically for reflected/stored XSS. DOM-based might vary.
            cwe_id="CWE-79"
        )

class MissingCSRFTokenVulnerability(Vulnerability):
    """
    Represents a vulnerability due to missing anti-CSRF tokens in forms.
    """
    def __init__(self):
        super().__init__(
            name="Missing Anti-CSRF Token",
            description="Web application does not use anti-CSRF tokens in one or more forms, making it vulnerable to Cross-Site Request Forgery (CSRF) attacks. CSRF can trick a victim's browser into making unintended requests.",
            default_criticality="Medium",
            cwe_id="CWE-352"
        )

# Example Usage (can be removed or kept for testing)
if __name__ == '__main__':
    sqli = SQLInjectionVulnerability()
    xss = XSSVulnerability()
    csrf = MissingCSRFTokenVulnerability()

    print(sqli)
    print(f"  Description: {sqli.description}\n")

    print(xss)
    print(f"  Description: {xss.description}\n")

    print(csrf)
    print(f"  Description: {csrf.description}\n")

    # Demonstrating direct instantiation of base class (though less common in practice)
    generic_vuln = Vulnerability(
        name="Generic Security Misconfiguration",
        description="A generic security misconfiguration that needs to be addressed.",
        default_criticality="Low",
        cwe_id="CWE-16" # Example: Configuration
    )
    print(generic_vuln)
    print(f"  Description: {generic_vuln.description}\n")
