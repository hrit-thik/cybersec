import requests

def fetch_page(url: str) -> tuple[str | None, dict | None]:
    """
    Fetches the content and headers of a web page.

    Args:
        url: The URL of the web page to fetch.

    Returns:
        A tuple containing the response text (HTML content) and response headers.
        Returns (None, None) if an error occurs.
    """
    try:
        response = requests.get(url, timeout=10)  # Added a timeout
        response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)
        return response.text, response.headers
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - URL: {url}")
        return None, None
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err} - URL: {url}")
        return None, None
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err} - URL: {url}")
        return None, None
    except requests.exceptions.RequestException as req_err:
        print(f"An unexpected error occurred during the request: {req_err} - URL: {url}")
        return None, None
