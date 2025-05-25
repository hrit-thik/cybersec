import pytest
import requests # Required for requests.exceptions.RequestException
from pysec_scanner.utils.http_client import fetch_page

# This is needed to ensure that the http_client module can be found if tests are run directly
# using `pytest tests/test_http_client.py` from the root project directory.
# Not strictly necessary if running `pytest` from root, which handles PYTHONPATH.
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


@pytest.fixture
def mock_response(mocker):
    """Fixture to create a generic mock response object."""
    mock_resp = mocker.Mock(spec=requests.Response)
    mock_resp.raise_for_status = mocker.Mock() # Ensure this is also a mock
    return mock_resp

def test_fetch_page_success(mocker, mock_response):
    """
    Test successful page fetch.
    """
    mock_content = "mock content"
    mock_headers = {'Content-Type': 'text/html'}
    
    mock_response.text = mock_content
    mock_response.headers = mock_headers
    mock_response.status_code = 200
    
    # Configure the mock for requests.get
    mock_requests_get = mocker.patch('requests.get', return_value=mock_response)
    
    url = "http://example.com"
    content, headers = fetch_page(url)
    
    mock_requests_get.assert_called_once_with(url, timeout=10)
    mock_response.raise_for_status.assert_called_once() # Check that raise_for_status was called
    assert content == mock_content
    assert headers == mock_headers

def test_fetch_page_http_error(mocker, mock_response, capsys):
    """
    Test handling of HTTP errors (e.g., 404).
    """
    url = "http://example.com/notfound"
    
    # Configure the mock response for an HTTP error
    mock_response.status_code = 404
    # Configure raise_for_status to simulate an HTTPError
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(f"404 Client Error: Not Found for url: {url}")
    
    mock_requests_get = mocker.patch('requests.get', return_value=mock_response)
    
    content, headers = fetch_page(url)
    
    mock_requests_get.assert_called_once_with(url, timeout=10)
    mock_response.raise_for_status.assert_called_once()
    assert content is None
    assert headers is None
    
    captured = capsys.readouterr()
    assert "HTTP error occurred" in captured.out or "HTTP error occurred" in captured.err
    assert "404" in captured.out or "404" in captured.err
    assert url in captured.out or url in captured.err


def test_fetch_page_connection_error(mocker, capsys):
    """
    Test handling of connection errors.
    """
    url = "http://example.com/connectionerror"
    
    # Configure requests.get to raise a ConnectionError
    mock_requests_get = mocker.patch('requests.get', side_effect=requests.exceptions.ConnectionError("Test connection error"))
    
    content, headers = fetch_page(url)
    
    mock_requests_get.assert_called_once_with(url, timeout=10)
    assert content is None
    assert headers is None
    
    captured = capsys.readouterr()
    assert "Connection error occurred" in captured.out or "Connection error occurred" in captured.err
    assert "Test connection error" in captured.out or "Test connection error" in captured.err
    assert url in captured.out or url in captured.err


def test_fetch_page_timeout_error(mocker, capsys):
    """
    Test handling of timeout errors.
    """
    url = "http://example.com/timeouterror"
    
    # Configure requests.get to raise a Timeout
    mock_requests_get = mocker.patch('requests.get', side_effect=requests.exceptions.Timeout("Test timeout error"))
    
    content, headers = fetch_page(url)
    
    mock_requests_get.assert_called_once_with(url, timeout=10)
    assert content is None
    assert headers is None
    
    captured = capsys.readouterr()
    assert "Timeout error occurred" in captured.out or "Timeout error occurred" in captured.err
    assert "Test timeout error" in captured.out or "Test timeout error" in captured.err
    assert url in captured.out or url in captured.err


def test_fetch_page_request_exception(mocker, capsys):
    """
    Test handling of generic RequestException.
    """
    url = "http://example.com/networkerror"
    
    # Configure requests.get to raise a generic RequestException
    mock_requests_get = mocker.patch('requests.get', side_effect=requests.exceptions.RequestException("Test network error"))
    
    content, headers = fetch_page(url)
    
    mock_requests_get.assert_called_once_with(url, timeout=10)
    assert content is None
    assert headers is None
    
    captured = capsys.readouterr()
    # The http_client prints a generic message for RequestException
    assert "An unexpected error occurred during the request" in captured.out or "An unexpected error occurred during the request" in captured.err
    assert "Test network error" in captured.out or "Test network error" in captured.err
    assert url in captured.out or url in captured.err

if __name__ == '__main__':
    # This allows running pytest directly on this file if needed, e.g. for debugging.
    # `pytest tests/test_http_client.py`
    pytest.main()
