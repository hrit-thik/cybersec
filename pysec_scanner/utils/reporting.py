def format_finding(finding_dict: dict) -> str:
    """
    Formats a single finding dictionary into a human-readable string.

    Args:
        finding_dict: A dictionary representing a single vulnerability finding.
                      Expected keys: 'vulnerability_type', 'cwe_id', 'criticality', 'url', 'details'.
                      The 'details' dict can vary:
                      - For SQLi/XSS: 'parameter', 'payload', 'evidence'
                      - For CSRF: 'form_details', 'evidence', 'raw_form_snippet' (optional)

    Returns:
        A formatted string representing the finding.
    """
    if not finding_dict:
        return "Error: Empty finding dictionary provided."

    lines = ["-----------------------------------------"]
    
    lines.append(f"Vulnerability: {finding_dict.get('vulnerability_type', 'N/A')} ({finding_dict.get('cwe_id', 'N/A')})")
    lines.append(f"Criticality: {finding_dict.get('criticality', 'N/A')}")
    lines.append(f"URL: {finding_dict.get('url', 'N/A')}")

    details = finding_dict.get('details', {})
    if isinstance(details, dict):
        # Common details structure for SQLi/XSS
        if 'parameter' in details:
            lines.append(f"Parameter: {details.get('parameter', 'N/A')}")
        if 'payload' in details:
            lines.append(f"Payload: {details.get('payload', 'N/A')}")
        
        # Common details structure for CSRF
        if 'form_details' in details:
            lines.append(f"Form Details: {details.get('form_details', 'N/A')}")

        # Common evidence field
        if 'evidence' in details:
            lines.append(f"Evidence: {details.get('evidence', 'N/A')}")
        
        # Optional raw form snippet for CSRF
        if 'raw_form_snippet' in details:
            lines.append(f"Raw Form Snippet (first 500 chars): {details.get('raw_form_snippet', 'N/A')}")

        # Handle any other details that might not fit the common patterns
        other_details = {
            k: v for k, v in details.items() 
            if k not in ['parameter', 'payload', 'form_details', 'evidence', 'raw_form_snippet', 'vulnerability', 'url']
        }
        if other_details:
            for key, value in other_details.items():
                 lines.append(f"{key.replace('_', ' ').capitalize()}: {value}")

    elif isinstance(details, str): # Fallback if details is just a string
        lines.append(f"Details: {details}")
        
    lines.append("-----------------------------------------")
    return "\n".join(lines)

def print_scan_report(findings_list: list, target_url: str):
    """
    Prints a formatted scan report.

    Args:
        findings_list: A list of finding dictionaries.
        target_url: The base URL that was targeted for the scan.
    """
    print("\n=========================================")
    print(f"Scan Report for: {target_url}")
    print("=========================================\n")

    if not findings_list:
        print("No vulnerabilities found.")
    else:
        print(f"Found {len(findings_list)} vulnerability/vulnerabilities:\n")
        for finding in findings_list:
            print(format_finding(finding))
            print() # Add a blank line between findings

    print("=========================================")
    print("End of report.")
    print("=========================================\n")

if __name__ == '__main__':
    print("--- Testing reporting module ---")

    sample_sqli_finding = {
        'vulnerability_type': 'SQL Injection',
        'cwe_id': 'CWE-89',
        'criticality': 'High',
        'url': 'http://example.com/product.php?id=1',
        'details': {
            'vulnerability': 'SQL Injection', # This can be a bit redundant with top-level key
            'parameter': 'id',
            'payload': "' OR 1=1 --",
            'url': "http://example.com/product.php?id=1' OR 1=1 --", # Test URL
            'evidence': "Detected SQL error pattern: 'you have an error in your sql syntax' in response."
        }
    }

    sample_xss_finding = {
        'vulnerability_type': 'Cross-Site Scripting (XSS)',
        'cwe_id': 'CWE-79',
        'criticality': 'High',
        'url': 'http://example.com/search?query=test',
        'details': {
            'vulnerability': 'Cross-Site Scripting (XSS)',
            'parameter': 'query',
            'payload': "<script>alert('XSS')</script>",
            'url': "http://example.com/search?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            'evidence': "Search results for: test<script>alert('XSS')</script>"
        }
    }
    
    sample_csrf_finding = {
        'vulnerability_type': 'Missing Anti-CSRF Token',
        'cwe_id': 'CWE-352',
        'criticality': 'Medium',
        'url': 'http://example.com/profile.php',
        'details': {
            'vulnerability': 'Missing Anti-CSRF Token',
            'form_details': "action='update.php', method='POST', id='profileForm'",
            'evidence': 'No common anti-CSRF token input field name found in this form.',
            'raw_form_snippet': '<form action="update.php" method="POST" id="profileForm">...'
        }
    }

    sample_finding_other_details = {
        'vulnerability_type': 'Open Redirect',
        'cwe_id': 'CWE-601',
        'criticality': 'Medium',
        'url': 'http://example.com/redirect?url=http://malicious.com',
        'details': {
            'parameter': 'url',
            'redirect_location': 'http://malicious.com',
            'notes': 'The application redirects without validation.'
        }
    }
    
    empty_finding = {}

    print("\n--- Testing format_finding ---")
    print(format_finding(sample_sqli_finding))
    print(format_finding(sample_xss_finding))
    print(format_finding(sample_csrf_finding))
    print(format_finding(sample_finding_other_details))
    print(format_finding(empty_finding))


    print("\n--- Testing print_scan_report (with findings) ---")
    findings = [sample_sqli_finding, sample_xss_finding, sample_csrf_finding, sample_finding_other_details]
    print_scan_report(findings, "http://example.com")

    print("\n--- Testing print_scan_report (no findings) ---")
    print_scan_report([], "http://example.com")
    
    print("\n--- Testing print_scan_report (one finding) ---")
    print_scan_report([sample_sqli_finding], "http://example.com/product.php?id=1")
