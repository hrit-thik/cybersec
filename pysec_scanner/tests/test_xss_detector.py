import pytest
from urllib.parse import urlparse, parse_qs # For more advanced mock logic if needed

from pysec_scanner.scanner.detectors.xss_detector import check_xss, XSS_PAYLOADS

# This is needed to ensure that the detector module can be found if tests are run directly
# using `pytest tests/test_xss_detector.py` from the root project directory.
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


# Helper function to simulate fetch_page behavior for XSS testing
def mock_fetch_page_xss(url: str, reflected_payload_in_url=None, reflected_content_in_response=None):
    """
    Simulates fetch_page for XSS.
    - reflected_payload_in_url: The raw payload string that, if found in the URL's query,
                                 triggers the reflection of reflected_content_in_response.
    - reflected_content_in_response: The actual content to be returned in the page body
                                     if reflected_payload_in_url is found in the URL.
    """
    # print(f"Mock XSS fetch called with URL: {url}") # For debugging
    # print(f"  Reflected payload in URL to check for: {reflected_payload_in_url}") # For debugging
    # print(f"  Content to reflect: {reflected_content_in_response}") # For debugging

    # The check_xss function sends URL-encoded payloads.
    # The mock should check if the raw payload (which would have been URL encoded to form `url`)
    # is part of the query string for the purpose of this simulation.
    # However, the `check_xss` detector looks for the *raw* payload in the *response_text*.
    # So, `reflected_content_in_response` is what matters for detection.
    # `reflected_payload_in_url` is just a trigger for the mock's behavior.

    parsed_url = urlparse(url)
    query_string = parsed_url.query
    
    if reflected_payload_in_url and reflected_content_in_response and reflected_payload_in_url in query_string:
        # print(f"  Mocking XSS vulnerable response for: {url} because '{reflected_payload_in_url}' found in query.") # For debugging
        return (f"<html><body>Content including {reflected_content_in_response} here.</body></html>", {'Content-Type': 'text/html'})
    
    # print(f"  Mocking normal (non-reflecting or escaped) response for: {url}") # For debugging
    return ("<html><body>Some normal, non-reflective content or properly escaped content.</body></html>", {'Content-Type': 'text/html'})


def test_xss_no_vulnerability_no_params():
    """
    Test check_xss with a URL that has no parameters.
    """
    result = check_xss("http://example.com", {}, lambda url_arg: mock_fetch_page_xss(url_arg))
    assert result is None

def test_xss_no_vulnerability_with_params_not_reflected():
    """
    Test check_xss with parameters, but the mock does not reflect any XSS payload.
    """
    # mock_fetch_page_xss by default (reflected_payload=None) returns normal content.
    result = check_xss(
        "http://example.com?name=test", 
        {'name': 'test'}, 
        lambda url_arg: mock_fetch_page_xss(url_arg, reflected_payload_in_url=None, reflected_content_in_response=None)
    )
    assert result is None

def test_xss_vulnerable_parameter_reflected():
    """
    Test detection of XSS when a payload is reflected in the response.
    """
    payload = XSS_PAYLOADS[0] # e.g., "<script>alert('XSS')</script>"
    param_name_to_test = 'query'
    original_param_value = 'test'

    # The check_xss function will try various payloads. We need our mock to respond
    # correctly when the specific `payload` is part of the URL query for `param_name_to_test`.
    # The detector appends the payload to the original value, e.g., "test<script>...",
    # then URL-encodes it. So, `reflected_payload_in_url` for the mock should be this raw combined string.
    
    # The `http_client_fetch_page_func` passed to `check_xss` takes only one arg: `test_url`.
    result = check_xss(
        f"http://example.com?{param_name_to_test}={original_param_value}", 
        {param_name_to_test: original_param_value}, 
        lambda test_url: mock_fetch_page_xss(
            test_url, 
            reflected_payload_in_url=f"{original_param_value}{payload}", # Mock looks for original_value + raw_payload in URL
            reflected_content_in_response=payload # Mock returns the raw_payload in response body
        )
    )
    
    assert result is not None
    assert isinstance(result, dict)
    assert result['vulnerability'] == 'Cross-Site Scripting (XSS)'
    assert result['parameter'] == param_name_to_test
    assert result['payload'] == payload # The detector should report the raw payload it used
    assert payload in result['evidence'] # The raw payload should be in the evidence snippet

def test_xss_multiple_params_one_vulnerable():
    """
    Test with multiple parameters, only one of which reflects the XSS payload.
    """
    payload = XSS_PAYLOADS[1] # e.g., "<ScRiPt>alert('XSS')</ScRiPt>"
    vulnerable_param = 'input'
    vulnerable_param_original_value = 'vuln'
    safe_param = 'name'
    safe_param_original_value = 'safe'

    # The mock needs to reflect `payload` only when it's associated with `vulnerable_param`.
    # `check_xss` iterates params one by one. When it tests `vulnerable_param`,
    # it will construct a URL where `vulnerable_param`'s value is `vulnerable_param_original_value + payload`.
    def smart_mock_fetch(test_url: str):
        # Check if the payload for the 'input' param is being tested
        # The URL will contain something like "input=vuln<ScRiPt>..."
        if f"{vulnerable_param}={vulnerable_param_original_value}{payload}" in test_url:
            return mock_fetch_page_xss(test_url, 
                                       reflected_payload_in_url=f"{vulnerable_param_original_value}{payload}", 
                                       reflected_content_in_response=payload)
        # Otherwise, for 'name' param or other cases, don't reflect the chosen payload
        return mock_fetch_page_xss(test_url, reflected_payload_in_url=None, reflected_content_in_response=None)

    result = check_xss(
        f"http://example.com?{safe_param}={safe_param_original_value}&{vulnerable_param}={vulnerable_param_original_value}",
        {safe_param: safe_param_original_value, vulnerable_param: vulnerable_param_original_value},
        smart_mock_fetch
    )
    
    assert result is not None
    assert result['vulnerability'] == 'Cross-Site Scripting (XSS)'
    assert result['parameter'] == vulnerable_param # Should correctly identify 'input'
    assert result['payload'] == payload
    assert payload in result['evidence']

def test_xss_payload_is_escaped_not_detected():
    """
    Test that if a payload is HTML-escaped in the response, it's not detected
    by the current detector (which looks for exact raw payload reflection).
    """
    payload = XSS_PAYLOADS[0] # e.g., "<script>alert('XSS')</script>"
    escaped_payload_in_response = payload.replace("<", "&lt;").replace(">", "&gt;")
    param_name_to_test = 'data'
    original_param_value = 'test'

    # The mock will reflect the *escaped* version of the payload.
    # The detector looks for the *raw* payload in the response.
    result = check_xss(
        f"http://example.com?{param_name_to_test}={original_param_value}", 
        {param_name_to_test: original_param_value}, 
        lambda test_url: mock_fetch_page_xss(
            test_url, 
            reflected_payload_in_url=f"{original_param_value}{payload}", # Mock still triggered by raw payload in URL
            reflected_content_in_response=escaped_payload_in_response # But reflects the escaped version
        )
    )
    
    assert result is None # Because the raw payload is not found in the response

if __name__ == '__main__':
    # This allows running pytest directly on this file if needed.
    # `pytest tests/test_xss_detector.py`
    pytest.main()
