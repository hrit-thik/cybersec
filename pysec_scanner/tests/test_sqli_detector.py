import pytest
from urllib.parse import urlparse, parse_qs

from pysec_scanner.scanner.detectors.sqli_detector import check_sqli, SQLI_PAYLOADS, SQL_ERROR_PATTERNS

# This is needed to ensure that the detector module can be found if tests are run directly
# using `pytest tests/test_sqli_detector.py` from the root project directory.
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


# Helper function to simulate fetch_page behavior for testing
def mock_fetch_page_helper(url: str, expected_url_substring_for_error=None, error_pattern_in_response=None):
    """
    Simulates fetch_page.
    If expected_url_substring_for_error is present in url and error_pattern_in_response is provided,
    returns a response indicating a vulnerability. Otherwise, returns normal content.
    """
    # print(f"Mock fetch called with URL: {url}") # For debugging test behavior
    # print(f"  expected_url_substring_for_error: {expected_url_substring_for_error}") # For debugging
    # print(f"  error_pattern_in_response: {error_pattern_in_response}") # For debugging

    if expected_url_substring_for_error and error_pattern_in_response:
        if expected_url_substring_for_error in url:
            # print(f"  Mocking vulnerable response for: {url}") # For debugging
            return (f"<html><body>{error_pattern_in_response}</body></html>", {'Content-Type': 'text/html'})
    
    # print(f"  Mocking normal response for: {url}") # For debugging
    return ("<html><body>Some normal content</body></html>", {'Content-Type': 'text/html'})


def test_sqli_no_vulnerability_no_params():
    """
    Test check_sqli with a URL that has no parameters.
    """
    result = check_sqli("http://example.com", {}, mock_fetch_page_helper)
    assert result is None

def test_sqli_no_vulnerability_with_params():
    """
    Test check_sqli with parameters but no vulnerability simulated.
    """
    # The mock_fetch_page_helper will return normal content by default
    result = check_sqli("http://example.com?id=1", {'id': '1'}, mock_fetch_page_helper)
    assert result is None

def test_sqli_vulnerable_parameter_error_based():
    """
    Test detection of SQLi based on a specific error pattern in the response.
    """
    # One of the common error patterns defined in sqli_detector
    error_to_simulate = "You have an error in your SQL syntax" 
    # One of the payloads that sqli_detector uses
    triggering_payload = "'" # A single quote is a common basic payload

    # We need to ensure our mock_fetch_page_helper is sensitive to the payload in the URL
    # The check_sqli function will append payloads to the original parameter value.
    # So, if original param is "id=1", with payload "'", test url becomes "id=1'".
    # The expected_url_substring_for_error should reflect this.
    
    result = check_sqli(
        "http://example.com?id=1", 
        {'id': '1'}, 
        lambda url_arg: mock_fetch_page_helper(
            url_arg, 
            expected_url_substring_for_error=f"id=1{triggering_payload}", # Check for param_val + payload
            error_pattern_in_response=error_to_simulate
        )
    )
    
    assert result is not None
    assert isinstance(result, dict)
    assert result['vulnerability'] == 'SQL Injection'
    assert result['parameter'] == 'id'
    assert triggering_payload in result['payload'] # Check if the specific payload is part of reported payload
    assert error_to_simulate in result['evidence']
    # Check that the reported URL contains the payload
    assert f"id=1{triggering_payload}" in result['url'] 

def test_sqli_multiple_params_one_vulnerable():
    """
    Test with multiple parameters, only one of which is vulnerable.
    """
    error_to_simulate = "You have an error in your SQL syntax"
    triggering_payload = "'" # Example payload

    # Vulnerability is on 'id'. 'name' is safe.
    # The expected substring should be specific to the vulnerable parameter and payload.
    result = check_sqli(
        "http://example.com?id=1&name=safe", 
        {'id': '1', 'name': 'safe'}, 
        lambda url_arg: mock_fetch_page_helper(
            url_arg, 
            expected_url_substring_for_error=f"id=1{triggering_payload}", # Vulnerability on id=1'
            error_pattern_in_response=error_to_simulate
        )
    )
    
    assert result is not None
    assert result['vulnerability'] == 'SQL Injection'
    assert result['parameter'] == 'id' # Should correctly identify 'id'
    assert triggering_payload in result['payload']
    assert error_to_simulate in result['evidence']
    assert f"id=1{triggering_payload}" in result['url']
    assert "name=safe" in result['url'] # Make sure other params are still in the reported URL

def test_sqli_different_payload_and_error():
    """
    Test with a different SQLi payload and a different error message.
    """
    # Using a payload from SQLI_PAYLOADS that includes a comment
    triggering_payload = " OR 1=1 --" 
    # Using a different error pattern
    error_to_simulate = "Unclosed quotation mark" 

    # Parameter is 'query', original value 'test'
    # Expected vulnerable URL part: query=test OR 1=1 --
    result = check_sqli(
        "http://example.com?query=test", 
        {'query': 'test'}, 
        lambda url_arg: mock_fetch_page_helper(
            url_arg, 
            expected_url_substring_for_error=f"query=test{triggering_payload.replace(' ', '%20')}", # URL encoding for space
            error_pattern_in_response=error_to_simulate
        )
    )
    
    assert result is not None
    assert result['vulnerability'] == 'SQL Injection'
    assert result['parameter'] == 'query'
    # The check_sqli function reports the payload exactly as used from its list
    assert result['payload'] == triggering_payload 
    assert error_to_simulate in result['evidence']
    # The URL in the result will have the payload URL-encoded
    assert f"query=test{triggering_payload.replace(' ', '%20')}" in result['url']


def test_sqli_payload_with_special_chars_encoding():
    """
    Test that payloads with special characters are correctly appended and checked.
    The sqli_detector itself handles URL encoding of the parameters part of the URL.
    Our mock needs to expect the payload part in the query string.
    """
    error_to_simulate = "ORA-00921: unexpected end of SQL command" # Oracle error
    # Payload that might get URL encoded differently if not careful
    triggering_payload = "\"' OR 1=1 ; --" 
    
    # The mock fetch page's `expected_url_substring_for_error` will see the raw appended payload
    # because `check_sqli` appends the raw payload to the param value, then `urlencode` handles it.
    # So, we search for the raw payload in the constructed `test_url` within `check_sqli`.
    # The key is that `expected_url_substring_for_error` in `mock_fetch_page_helper`
    # should match how the URL looks *after* `check_sqli` has modified it with the raw payload
    # and then `urlencode` has processed it.
    # For simplicity, let's assume the substring check in mock_fetch_page_helper is robust enough
    # or we check for a very specific part of the payload that survives encoding.

    # The `check_sqli` function does:
    # current_params[param_name] = str(original_value) + payload
    # query_string = urlencode(current_params)
    # So, if param_name='data', original_value='input', payload="' OR 1=1",
    # current_params['data'] becomes "input' OR 1=1"
    # urlencode will then turn this into "data=input%27+OR+1%3D1"
    # Our `expected_url_substring_for_error` should look for "input' OR 1=1" within the fully formed URL string.

    result = check_sqli(
        "http://example.com?data=input", 
        {'data': 'input'},
        lambda url_arg: mock_fetch_page_helper(
            url_arg,
            expected_url_substring_for_error=f"data=input{triggering_payload}", # Test this matching logic
            error_pattern_in_response=error_to_simulate
        )
    )

    assert result is not None
    assert result['vulnerability'] == 'SQL Injection'
    assert result['parameter'] == 'data'
    assert result['payload'] == triggering_payload
    assert error_to_simulate in result['evidence']
    # The reported URL should contain the URL-encoded version of the payload
    from urllib.parse import quote_plus
    assert quote_plus(triggering_payload) in result['url'] or triggering_payload.replace(" ", "%20") in result['url']


if __name__ == '__main__':
    # This allows running pytest directly on this file if needed.
    # `pytest tests/test_sqli_detector.py`
    pytest.main()
