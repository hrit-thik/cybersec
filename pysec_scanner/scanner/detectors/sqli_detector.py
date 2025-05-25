import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

# Common SQL error patterns (simple examples, can be expanded)
SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"warning: mysql_fetch_array\(\)", re.IGNORECASE),
    re.compile(r"ORA-\d{5}:", re.IGNORECASE),  # Oracle errors
    re.compile(r"SQLSTATE\[\d+\]: Syntax error or access violation", re.IGNORECASE), # General SQL errors
    re.compile(r"\[SQLServer\]", re.IGNORECASE), # MS SQL Server
    re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.IGNORECASE),
    re.compile(r"nvarchar to int", re.IGNORECASE), # MS SQL Server specific error
]

# Common SQLi test payloads
SQLI_PAYLOADS = [
    "'",
    "\"",
    "--",
    ";",
    " OR 1=1 --",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 'a'='a",
    "\" OR \"a\"=\"a",
    "1' OR '1'='1", # Numeric specific
    "' OR 1=1#",
    "\" OR 1=1#",
    "' OR '1'='1'; --",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
]

def check_sqli(url: str, params: dict, http_client_fetch_page_func) -> dict | None:
    """
    Checks for SQL Injection vulnerabilities in URL parameters.

    Args:
        url: The base URL.
        params: A dictionary of query parameters.
        http_client_fetch_page_func: A function to fetch web page content and headers.
                                     Expected signature: fetch_page(url) -> (text_content, headers)

    Returns:
        A dictionary with vulnerability details if SQLi is detected, otherwise None.
    """
    parsed_url = urlparse(url)

    for param_name, original_value in params.items():
        for payload in SQLI_PAYLOADS:
            # Create a mutable copy of the original parameters
            current_params = params.copy()
            current_params[param_name] = str(original_value) + payload

            # Reconstruct the query string and the full URL
            query_string = urlencode(current_params)
            test_url_parts = list(parsed_url)
            test_url_parts[4] = query_string  # Index 4 is the query component
            test_url = urlunparse(test_url_parts)

            # print(f"Testing URL: {test_url}") # For debugging

            response_text, _ = http_client_fetch_page_func(test_url)

            if response_text:
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern.search(response_text):
                        return {
                            'vulnerability': 'SQL Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'evidence': f"Detected SQL error pattern: '{pattern.pattern}' in response.",
                        }
                # TODO: Add checks for significant content changes as an alternative detection method.
                # This would require a baseline request for comparison.

    return None

if __name__ == '__main__':
    # Example Usage (for testing the detector directly)
    # You would need a dummy fetch_page function and a vulnerable target for this to work.

    def mock_fetch_page_vulnerable(test_url):
        print(f"Mock fetching: {test_url}")
        if "OR 1=1" in test_url and "id" in test_url:
            return "Error: You have an error in your SQL syntax near '' OR 1=1 --' at line 1", {}
        if "error_param" in test_url and "'" in test_url:
             return "Unclosed quotation mark before ' LIMIT 1", {}
        return "<html><body>Normal page</body></html>", {}

    def mock_fetch_page_clean(test_url):
        print(f"Mock fetching: {test_url}")
        return "<html><body>Normal page for all params</body></html>", {}

    print("--- Testing with a potentially vulnerable scenario ---")
    target_url_vuln = "http://testphp.vulnweb.com/listproducts.php" # Example, not a live test target for this script
    params_vuln = {"artist": "1", "cat": "2"}
    
    # Test with a mock function that simulates a vulnerability
    result_vuln = check_sqli(target_url_vuln, params_vuln.copy(), mock_fetch_page_vulnerable)
    if result_vuln:
        print(f"Potential SQLi found: {result_vuln}")
    else:
        print("No SQLi detected (vulnerable mock).")

    print("\n--- Testing with another potentially vulnerable scenario ---")
    target_url_vuln2 = "http://example.com/search"
    params_vuln2 = {"query": "test", "error_param": "trigger"}
    result_vuln2 = check_sqli(target_url_vuln2, params_vuln2.copy(), mock_fetch_page_vulnerable)
    if result_vuln2:
        print(f"Potential SQLi found: {result_vuln2}")
    else:
        print("No SQLi detected (vulnerable mock 2).")


    print("\n--- Testing with a clean scenario ---")
    target_url_clean = "http://example.com/index.php"
    params_clean = {"id": "10", "category": "books"}
    result_clean = check_sqli(target_url_clean, params_clean.copy(), mock_fetch_page_clean)
    if result_clean:
        print(f"Potential SQLi found: {result_clean}")
    else:
        print("No SQLi detected (clean mock).")

    print("\n--- Testing with empty params ---")
    result_empty = check_sqli(target_url_clean, {}, mock_fetch_page_clean)
    if result_empty:
        print(f"Potential SQLi found: {result_empty}")
    else:
        print("No SQLi detected (empty params).")

    print("\n--- Testing specific payload that might cause issues if not handled ---")
    params_specific = {"input": "user"}
    # Ensure the mock function handles all payloads gracefully or simulates specific errors
    result_specific = check_sqli(target_url_vuln, params_specific.copy(), mock_fetch_page_vulnerable)
    if result_specific:
        print(f"Potential SQLi found: {result_specific}")
    else:
        print("No SQLi detected (specific payload).")

    # Example of how it might be called from the main scanner
    # from pysec_scanner.utils.http_client import fetch_page # Assume this is the actual client
    # real_vulnerabilities = check_sqli("http://actualvulnerablesite.com/product.php", {"id": "1"}, fetch_page)
    # if real_vulnerabilities:
    # print(f"Real SQLi found: {real_vulnerabilities}")
