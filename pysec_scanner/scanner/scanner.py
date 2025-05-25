import re
from urllib.parse import urlparse, parse_qs, urljoin

# Utility imports
from pysec_scanner.utils.http_client import fetch_page

# Detector imports
from pysec_scanner.scanner.detectors.sqli_detector import check_sqli
from pysec_scanner.scanner.detectors.xss_detector import check_xss
from pysec_scanner.scanner.detectors.csrf_detector import check_csrf_forms

# Vulnerability class imports
from pysec_scanner.scanner.vulnerabilities import (
    SQLInjectionVulnerability,
    XSSVulnerability,
    MissingCSRFTokenVulnerability
)

# Reporting import
from pysec_scanner.utils.reporting import print_scan_report

# Basic regex for links (href attributes)
LINK_REGEX = re.compile(r"""<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1""", re.IGNORECASE)

# Basic regex for forms and their attributes
FORM_REGEX = re.compile(r"""<form\s*(.*?)>(.*?)</form>""", re.IGNORECASE | re.DOTALL)
ACTION_REGEX = re.compile(r"""action=(["'])(.*?)\1""", re.IGNORECASE)
METHOD_REGEX = re.compile(r"""method=(["'])(post|get)\1""", re.IGNORECASE) # Default to GET if not specified

# Basic regex for input, textarea, and select names within forms
INPUT_REGEX = re.compile(r"""<input\s+.*?name=(["'])(.*?)\1.*?>""", re.IGNORECASE | re.DOTALL)
TEXTAREA_REGEX = re.compile(r"""<textarea\s+.*?name=(["'])(.*?)\1.*?>""", re.IGNORECASE | re.DOTALL)
SELECT_REGEX = re.compile(r"""<select\s+.*?name=(["'])(.*?)\1.*?>""", re.IGNORECASE | re.DOTALL)


class Scanner:
    def __init__(self, base_url: str):
        """
        Initializes the Scanner.

        Args:
            base_url: The starting URL for the scan.
        """
        self.base_url = base_url
        self.findings = []

        # Instantiate vulnerability types for associating with findings
        self.sqli_vuln = SQLInjectionVulnerability()
        self.xss_vuln = XSSVulnerability()
        self.missing_csrf_vuln = MissingCSRFTokenVulnerability()
        
        self.processed_urls = set() # To avoid re-scanning same URL in more complex crawl scenarios

    def discover_inputs_and_links(self, page_url: str, html_content: str) -> dict:
        """
        Performs basic parsing of HTML content to find links, forms, and URL parameters.

        Args:
            page_url: The URL of the page from which the HTML content was fetched.
            html_content: The HTML content of the page.

        Returns:
            A dictionary containing:
            - 'links': A set of unique absolute URLs found on the page.
            - 'forms': A list of dictionaries, each representing a form with its action, method, and inputs.
            - 'url_params': A dictionary of parameters extracted from the page_url itself.
        """
        absolute_links = set()
        forms_details = []

        # Extract Links
        for match in LINK_REGEX.finditer(html_content):
            href = match.group(2).strip()
            if href and not href.startswith(('javascript:', '#', 'mailto:')):
                absolute_link = urljoin(page_url, href)
                absolute_links.add(absolute_link)

        # Extract Forms and Parameters
        for form_match in FORM_REGEX.finditer(html_content):
            form_attributes_str = form_match.group(1)
            form_content_str = form_match.group(2)
            
            action_match = ACTION_REGEX.search(form_attributes_str)
            action = action_match.group(2) if action_match else ""
            action_url = urljoin(page_url, action) # Resolve relative action URLs

            method_match = METHOD_REGEX.search(form_attributes_str)
            method = method_match.group(2).lower() if method_match else "get" # Default to GET

            inputs = {} # Using dict to store input names and placeholder values
            
            for input_m in INPUT_REGEX.finditer(form_content_str):
                inputs[input_m.group(2)] = "test_value" # Placeholder value
            for textarea_m in TEXTAREA_REGEX.finditer(form_content_str):
                inputs[textarea_m.group(2)] = "test_text_area_value" # Placeholder
            for select_m in SELECT_REGEX.finditer(form_content_str):
                inputs[select_m.group(2)] = "test_select_value" # Placeholder

            forms_details.append({
                'action': action_url,
                'method': method,
                'inputs': inputs
            })
            
        # Extract URL Parameters from the current page_url
        parsed_page_url = urlparse(page_url)
        url_params = parse_qs(parsed_page_url.query)
        # parse_qs returns lists for values, simplify if only one value
        url_params_simplified = {k: v[0] if len(v) == 1 else v for k, v in url_params.items()}

        return {
            'links': absolute_links,
            'forms': forms_details,
            'url_params': url_params_simplified
        }

    def scan_page(self, page_url: str) -> set:
        """
        Scans a single page for vulnerabilities.

        Args:
            page_url: The URL of the page to scan.

        Returns:
            A set of discovered absolute links on the page.
        """
        if page_url in self.processed_urls:
            print(f"Skipping already processed URL: {page_url}")
            return set()
        
        print(f"Scanning URL: {page_url}")
        self.processed_urls.add(page_url)

        html_content, headers = fetch_page(page_url)

        if html_content is None:
            print(f"Error: Could not fetch content for {page_url}. Skipping scan for this page.")
            return set()

        discovered_elements = self.discover_inputs_and_links(page_url, html_content)
        
        # --- URL Parameter Checks (SQLi, XSS) ---
        if discovered_elements['url_params']:
            print(f"  Checking URL parameters for SQLi/XSS: {discovered_elements['url_params']}")
            # SQLi Check
            sqli_finding = check_sqli(page_url, discovered_elements['url_params'], fetch_page)
            if sqli_finding:
                self.findings.append({
                    'vulnerability_type': self.sqli_vuln.name,
                    'cwe_id': self.sqli_vuln.cwe_id,
                    'details': sqli_finding,
                    'url': page_url, # The URL where params were tested, not necessarily the finding URL
                    'criticality': self.sqli_vuln.default_criticality
                })
                print(f"    [!] SQLi vulnerability found: {sqli_finding['parameter']} in {page_url}")

            # XSS Check
            xss_finding = check_xss(page_url, discovered_elements['url_params'], fetch_page)
            if xss_finding:
                self.findings.append({
                    'vulnerability_type': self.xss_vuln.name,
                    'cwe_id': self.xss_vuln.cwe_id,
                    'details': xss_finding,
                    'url': page_url, # As above
                    'criticality': self.xss_vuln.default_criticality
                })
                print(f"    [!] XSS vulnerability found: {xss_finding['parameter']} in {page_url}")
        else:
            print(f"  No URL parameters found in {page_url} for SQLi/XSS checks.")


        # --- CSRF Check (Page-level) ---
        print(f"  Checking for missing Anti-CSRF tokens in forms on {page_url}...")
        csrf_form_findings = check_csrf_forms(html_content)
        if csrf_form_findings:
            for csrf_item in csrf_form_findings:
                self.findings.append({
                    'vulnerability_type': self.missing_csrf_vuln.name,
                    'cwe_id': self.missing_csrf_vuln.cwe_id,
                    'details': csrf_item, # This contains form_details and evidence
                    'url': page_url,
                    'criticality': self.missing_csrf_vuln.default_criticality
                })
                print(f"    [!] Missing Anti-CSRF token found in form: {csrf_item['form_details']} on {page_url}")
        else:
            print(f"  No forms missing Anti-CSRF tokens found on {page_url}.")
            

        # --- Form Parameter Checks (SQLi, XSS) - Placeholder ---
        # TODO: Implement scanning of form parameters. This is more complex:
        # 1. For GET forms: Similar to URL parameters, construct URL with query string.
        # 2. For POST forms: Requires making POST requests with payloads in form data.
        #    - This means the http_client might need a way to send POST data.
        #    - The `check_sqli` and `check_xss` might need adaptation or new functions
        #      to handle form data submissions instead of just URL parameters.
        #    - Need to decide if we test all forms or only those with specific methods.
        print(f"  Form parameter scanning (SQLi, XSS) is a TODO for forms on {page_url}.")
        # For now, we'll just print the forms discovered:
        if discovered_elements['forms']:
            print(f"  Forms discovered on {page_url}:")
            for form_info in discovered_elements['forms']:
                print(f"    - Action: {form_info['action']}, Method: {form_info['method']}, Inputs: {list(form_info['inputs'].keys())}")
        else:
            print(f"  No forms discovered on {page_url}.")


        return discovered_elements['links']

    def start_scan(self):
        """
        Starts the vulnerability scan, beginning with the base_url.
        (Currently scans only the base_url, crawling is a future enhancement).
        """
        print(f"Starting scan for base URL: {self.base_url}")
        
        # In the future, this will manage a queue of URLs to crawl
        # For now, just scan the base_url
        discovered_links_on_base = self.scan_page(self.base_url)
        
        # Basic crawling (scan 1 level deep for now, as an example)
        # print(f"\nDiscovered links on base page to potentially crawl: {discovered_links_on_base}")
        # for link in discovered_links_on_base:
        #    if urlparse(link).netloc == urlparse(self.base_url).netloc: # Stay on the same domain
        #        self.scan_page(link) # Recursive call, careful with depth in real crawler
        #    else:
        #        print(f"  Skipping external link: {link}")

        # Use the new reporting function
        print_scan_report(self.findings, self.base_url)


if __name__ == '__main__':
    # This is a placeholder for testing.
    # To run this effectively, you'd need a test web server with known vulnerabilities.
    # For example, a local instance of DVWA (Damn Vulnerable Web Application) or similar.

    # Replace with a URL you have permission to test, or a local test environment.
    # IMPORTANT: Do NOT run this against websites you do not have explicit permission to test.
    # test_url = "http://testphp.vulnweb.com/" # Example site, often used for testing
                                            # Be mindful of their terms of service.
    
    # A safer local example (if you set up a simple vulnerable page):
    # test_url = "http://localhost:8000/vulnerable_page.html?id=1&name=test"
    
    # For the purpose of this example, let's assume a very simple structure
    # and mock the fetch_page for controlled testing without external calls.
    
    original_fetch_page = fetch_page # Save original
    
    MOCK_PAGES = {
        "http://example.com/index.html": (
            """
            <html><head><title>Test Page</title></head>
            <body>
                <h1>Welcome</h1>
                <a href="page1.html">Page 1</a>
                <a href="/page2.html?id=10">Page 2 with param</a>
                <a href="http://external.com/ext_page">External Page</a>
                <form action="submit.php" method="post">
                    <input type="text" name="username">
                    <input type="password" name="password">
                    <input type="submit" value="Login">
                </form>
                <form action="search.php" method="get">
                    <input type="text" name="query">
                    <input type="submit" value="Search">
                </form>
            </body></html>
            """, {"Content-Type": "text/html"}
        ),
        "http://example.com/page1.html": (
            "<html><body>Page 1 Content. <a href='index.html'>Back</a></body></html>",
            {"Content-Type": "text/html"}
        ),
        "http://example.com/page2.html?id=10": ( # This is how fetch_page would be called
             "<html><body>Page 2 Content for id=10. Your ID is 10.</body></html>",
            {"Content-Type": "text/html"}
        ),
         "http://example.com/page2.html?id=10'": ( # Mocking SQLi detection
             "<html><body>SQL Error: You have an error in your SQL syntax near ''' at line 1 for id=10'.</body></html>",
            {"Content-Type": "text/html"}
        ),
        "http://example.com/page2.html?id=10<script>alert('XSS')</script>": ( # Mocking XSS detection
             "<html><body>Page 2 Content for id=10<script>alert('XSS')</script>. Your ID is 10<script>alert('XSS')</script>.</body></html>",
            {"Content-Type": "text/html"}
        ),
        "http://example.com/search.php?query=test<script>alert('XSS')</script>": ( # Mocking XSS detection in form
             "<html><body>Search results for query=test<script>alert('XSS')</script>. Found: test<script>alert('XSS')</script>.</body></html>",
            {"Content-Type": "text/html"}
        ),
    }

    def mock_fetch_page_for_scanner(url: str):
        # print(f"MOCK fetch_page called for: {url}") # Debug
        # Simulate SQLi/XSS by checking if a payload is in the URL for specific params
        parsed_url_for_mock = urlparse(url)
        query_params_for_mock = parse_qs(parsed_url_for_mock.query)

        if "id" in query_params_for_mock:
            id_val = query_params_for_mock["id"][0]
            if "'" in id_val and "script" not in id_val: # Basic SQLi trigger
                return MOCK_PAGES.get(f"http://example.com/page2.html?id={id_val}", (f"SQL Error for id={id_val}", {}))
            if "<script>" in id_val: # Basic XSS trigger
                 return MOCK_PAGES.get(f"http://example.com/page2.html?id={id_val}", (f"XSS content for id={id_val}", {}))
        
        if "query" in query_params_for_mock: # For form test
            query_val = query_params_for_mock["query"][0]
            if "<script>" in query_val:
                return MOCK_PAGES.get(f"http://example.com/search.php?query={query_val}", (f"XSS content for query={query_val}", {}))


        return MOCK_PAGES.get(url, ("Default mock content: Page not found in mock.", {}))


    # Monkey patch fetch_page for this test run
    import pysec_scanner.utils.http_client
    pysec_scanner.utils.http_client.fetch_page = mock_fetch_page_for_scanner
    
    # Also need to path fetch_page for the detectors if they import it directly
    import pysec_scanner.scanner.detectors.sqli_detector
    pysec_scanner.scanner.detectors.sqli_detector.fetch_page = mock_fetch_page_for_scanner # if it used it
    # Actually, detectors receive fetch_page as an argument, so this is fine.

    print("--- Starting Scanner Test with Mocked Data ---")
    # Test with a URL that has parameters to trigger SQLi/XSS checks in the mock
    # The `discover_inputs_and_links` will get url_params from `scan_page`'s `page_url`
    scanner = Scanner("http://example.com/page2.html?id=10&name=testuser")
    # scanner = Scanner("http://example.com/index.html") # Alternative starting point
    
    scanner.start_scan()
    
    print("\n--- Verifying Findings (Example) ---")
    found_sqli = any(f['vulnerability_type'] == 'SQL Injection' for f in scanner.findings)
    found_xss = any(f['vulnerability_type'] == 'Cross-Site Scripting (XSS)' for f in scanner.findings)
    # CSRF might be found based on the forms in index.html if it's scanned and forms don't have tokens
    # For the current setup, `start_scan` only scans `base_url`.
    # If base_url is page2.html, it won't have forms for CSRF check from MOCK_PAGES.
    # If base_url is index.html, it will find forms and likely flag them.

    print(f"SQLi detected in mock: {found_sqli}")
    print(f"XSS detected in mock: {found_xss}")

    # Restore original fetch_page if other tests in the same execution might need it
    pysec_scanner.utils.http_client.fetch_page = original_fetch_page
    print("\n--- Scanner Test Complete ---")
