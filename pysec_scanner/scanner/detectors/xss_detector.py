import html
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

# Common XSS test payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>", # Case variations
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>", # Using char codes
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS');", # For attributes like href
    "JaVaScRiPt:alert('XSS');",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=", # data URI
    "<details/open/ontoggle=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS');\"></iframe>",
    "<a href=\"javascript:alert('XSS')\">Click me</a>",
    "<object data=\"javascript:alert('XSS')\"></object>",
    "<embed src=\"javascript:alert('XSS')\"></embed>",
    "<form action=\"javascript:alert('XSS')\"><input type=\"submit\"></form>",
    "<marquee onstart=alert('XSS')>XSS</marquee>",
    "<body onload=alert('XSS')>", # Less likely to be reflected directly in a param value but good for general testing
    "<!--<script>alert('XSS')</script>-->" # HTML comment bypass (less common for reflection)
]

def check_xss(url: str, params: dict, http_client_fetch_page_func) -> dict | None:
    """
    Checks for reflected Cross-Site Scripting (XSS) vulnerabilities in URL parameters.

    Args:
        url: The base URL.
        params: A dictionary of query parameters.
        http_client_fetch_page_func: A function to fetch web page content and headers.
                                     Expected signature: fetch_page(url) -> (text_content, headers)

    Returns:
        A dictionary with vulnerability details if XSS is detected, otherwise None.
    """
    parsed_url = urlparse(url)

    for param_name, original_value in params.items():
        for payload in XSS_PAYLOADS:
            # Create a mutable copy of the original parameters
            current_params = params.copy()
            # The payload itself should be URL encoded when forming the query string
            # but we search for its raw form in the response.
            current_params[param_name] = str(original_value) + payload

            # Reconstruct the query string and the full URL
            # urlencode will handle the necessary encoding of the payload within the parameter value
            query_string = urlencode(current_params)
            test_url_parts = list(parsed_url)
            test_url_parts[4] = query_string  # Index 4 is the query component
            test_url = urlunparse(test_url_parts)

            # print(f"Testing URL for XSS: {test_url}") # For debugging

            response_text, _ = http_client_fetch_page_func(test_url)

            if response_text:
                # We are looking for the raw payload reflected.
                # If the payload is HTML escaped (e.g., "<" becomes "&lt;"), it's not a vulnerability.
                # A simple string search is a good first step.
                # More advanced checks might involve parsing HTML and checking DOM properties.
                if payload in response_text:
                    # To provide better evidence, find the snippet
                    snippet_offset = 100
                    payload_start_index = response_text.find(payload)
                    snippet_start = max(0, payload_start_index - snippet_offset)
                    snippet_end = min(len(response_text), payload_start_index + len(payload) + snippet_offset)
                    evidence_snippet = response_text[snippet_start:snippet_end]
                    
                    # Double check that it's not overly escaped in the snippet (basic check)
                    # This is not foolproof, as parts of a payload could be legitimately escaped while others are not.
                    # e.g. <img src="&lt;>" onerror=alert('XSS')> -- here &lt; is fine, but onerror is not.
                    # However, a simple check for the raw payload is a strong indicator.
                    if html.escape(payload) in response_text and payload not in html.escape(payload):
                        # This condition means the escaped version is also present, and the raw version is not a substring of the escaped one.
                        # This is a heuristic. If "<script>" is found, but "&lt;script&gt;" is also found,
                        # it's less likely to be a true positive unless the context is specific.
                        # For now, we'll assume if the raw payload is present, it's a finding.
                        pass


                    return {
                        'vulnerability': 'Cross-Site Scripting (XSS)',
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url,
                        'evidence': evidence_snippet.strip(),
                    }
    return None

if __name__ == '__main__':
    # Example Usage (for testing the detector directly)

    def mock_fetch_page_xss_vulnerable(test_url):
        print(f"Mock XSS fetching (vulnerable): {test_url}")
        q_params = parse_qs(urlparse(test_url).query)
        if 'query' in q_params and "<script>alert('XSS')</script>" in q_params['query'][0]:
            return f"<html><body>Search results for: {q_params['query'][0]}</body></html>", {}
        if 'name' in q_params and "<img src=x onerror=alert('XSS')>" in q_params['name'][0]:
            return f"<html><title>Hello {q_params['name'][0]}</title><body>Welcome!</body></html>", {}
        return "<html><body>Normal page content.</body></html>", {}

    def mock_fetch_page_xss_safe(test_url):
        print(f"Mock XSS fetching (safe): {test_url}")
        q_params = parse_qs(urlparse(test_url).query)
        if 'query' in q_params:
            return f"<html><body>Search results for: {html.escape(q_params['query'][0])}</body></html>", {}
        return "<html><body>Normal page content, all escaped.</body></html>", {}

    print("--- Testing XSS with a potentially vulnerable scenario (script tags) ---")
    target_url_xss1 = "http://example.com/search"
    params_xss1 = {"query": "test"}
    result_xss1 = check_xss(target_url_xss1, params_xss1.copy(), mock_fetch_page_xss_vulnerable)
    if result_xss1:
        print(f"Potential XSS found: {result_xss1}")
    else:
        print("No XSS detected (vulnerable mock, script).")

    print("\n--- Testing XSS with a potentially vulnerable scenario (img tag) ---")
    target_url_xss2 = "http://example.com/greet"
    params_xss2 = {"name": "User"}
    result_xss2 = check_xss(target_url_xss2, params_xss2.copy(), mock_fetch_page_xss_vulnerable)
    if result_xss2:
        print(f"Potential XSS found: {result_xss2}")
    else:
        print("No XSS detected (vulnerable mock, img).")

    print("\n--- Testing XSS with a safe scenario (properly escaped) ---")
    target_url_xss_safe = "http://example.com/search"
    params_xss_safe = {"query": "test"}
    result_xss_safe = check_xss(target_url_xss_safe, params_xss_safe.copy(), mock_fetch_page_xss_safe)
    if result_xss_safe:
        print(f"Potential XSS found: {result_xss_safe}") # Should not happen
    else:
        print("No XSS detected (safe mock).")
    
    print("\n--- Testing XSS with empty params ---")
    result_empty_xss = check_xss(target_url_xss1, {}, mock_fetch_page_xss_vulnerable)
    if result_empty_xss:
        print(f"Potential XSS found: {result_empty_xss}")
    else:
        print("No XSS detected (empty params).")

    # Test one of the more complex payloads
    print("\n--- Testing XSS with data URI payload ---")
    params_xss_data_uri = {"redirectUrl": "http://safe.com/path?returnTo="}
    # Need to adjust mock_fetch_page_xss_vulnerable or add a new one if we want to test this specific payload reflection
    # For now, this will likely result in "No XSS detected" unless the generic part of mock_fetch_page_xss_vulnerable handles it.
    # Let's assume it's not specifically handled and will be part of the "Normal page content"
    def mock_fetch_page_xss_vulnerable_for_data_uri(test_url):
        print(f"Mock XSS fetching (vulnerable for data URI): {test_url}")
        q_params = parse_qs(urlparse(test_url).query)
        payload_to_check = "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
        if 'redirectUrl' in q_params and payload_to_check in q_params['redirectUrl'][0]:
            # Simulating reflection in an attribute
            return f"<html><body><a href='{q_params['redirectUrl'][0]}'>Click if you dare</a></body></html>", {}
        return "<html><body>Normal page content.</body></html>", {}

    result_xss_data_uri = check_xss(target_url_xss1, params_xss_data_uri.copy(), mock_fetch_page_xss_vulnerable_for_data_uri)
    if result_xss_data_uri:
        print(f"Potential XSS found: {result_xss_data_uri}")
    else:
        print("No XSS detected (data URI mock).")
