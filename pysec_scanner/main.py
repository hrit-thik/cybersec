import argparse
from pysec_scanner.scanner.scanner import Scanner

# This is a placeholder for testing if direct execution is attempted from a non-package context
# For actual execution, it's better to run as a module: python -m pysec_scanner.main <url>
# However, to make it directly runnable for simplicity in this context:
import sys
import os
# Get the absolute path to the project root (assuming main.py is in pysec_scanner/ and project root is its parent)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


def main():
    """
    Main function to run the PySec Scanner CLI.
    """
    parser = argparse.ArgumentParser(description="PySec Scanner - A basic web vulnerability scanner.")
    parser.add_argument("url", help="The base URL of the website to scan (e.g., http://example.com)")

    args = parser.parse_args()
    target_url = args.url

    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        print(f"Error: Invalid URL scheme. Please provide a full URL (e.g., http://{target_url} or https://{target_url})")
        sys.exit(1)

    print(f"Starting security scan for: {target_url}")

    try:
        # In a real scenario with external sites, you'd use the actual fetch_page.
        # For the existing test structure in Scanner, it might use a mocked one if __main__ is run there.
        # Here, we want to ensure the real http_client.fetch_page is used.
        # This might require ensuring that the Scanner's __main__ block or its test setup
        # doesn't globally patch fetch_page in a way that affects this CLI usage.
        # For now, we assume Scanner uses the http_client.fetch_page by default.
        
        scanner_instance = Scanner(base_url=target_url)
        scanner_instance.start_scan()

    except ImportError as e:
        print(f"Error: Could not import scanner components. Ensure you are running from the project root or have installed the package.")
        print(f"Details: {e}")
        print("If running from source, try: python -m pysec_scanner.main <url>")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during the scan: {e}")
        # Consider more specific error handling or logging here
        sys.exit(1)

    print(f"\nScan complete for: {target_url}")

if __name__ == "__main__":
    # The following is a simple mock setup for http_client.fetch_page
    # to allow the CLI to run without making actual external HTTP requests
    # during this development/testing phase of the CLI itself.
    # In a real deployment, this mock would NOT be here.
    
    # Check if a specific environment variable is set to run with actual requests
    USE_REAL_REQUESTS = os.environ.get("PYSEC_SCANNER_REAL_REQUESTS", "false").lower() == "true"

    if not USE_REAL_REQUESTS and 'pytest' not in sys.modules: # Don't mock if under pytest or if real requests are desired
        try:
            from pysec_scanner.utils import http_client
            
            # Store the original fetch_page
            original_fetch_page = http_client.fetch_page

            MOCK_CLI_PAGES = {
                "http://cli-test.com": (
                    "<html><head><title>CLI Test Page</title></head><body><h1>Welcome to CLI Test</h1>"
                    "<p>This is a test page for the command line interface.</p>"
                    "<a href='page1.html'>Page 1</a>"
                    "<form action='submit.php' method='post'><input type='text' name='data'><input type='submit'></form>"
                    "</body></html>", {"Content-Type": "text/html"}
                ),
                "http://cli-test.com/page1.html": (
                    "<html><body>Page 1 content. <a href='http://cli-test.com'>Back</a></body></html>", 
                    {"Content-Type": "text/html"}
                ),
                 # Mock for SQLi detection based on common payload in URL (from scanner's own test)
                "http://cli-test.com?id=10'": (
                    "<html><body>SQL Error: You have an error in your SQL syntax near ''' for id=10'.</body></html>",
                    {"Content-Type": "text/html"}
                ),
                # Mock for XSS detection
                "http://cli-test.com?name=User<script>alert('XSS')</script>": (
                    "<html><body>Hello User<script>alert('XSS')</script>!</body></html>",
                    {"Content-Type": "text/html"}
                ),
            }
            print("--- CLI MAIN: USING MOCKED HTTP REQUESTS ---")

            def mock_cli_fetch_page(url: str):
                from urllib.parse import urlparse, parse_qs
                # print(f"MOCK_CLI fetch_page called for: {url}") # Debug
                
                # Check for specific payloads in URL for SQLi/XSS simulation
                parsed_url_for_mock = urlparse(url)
                query_params_for_mock = parse_qs(parsed_url_for_mock.query)

                if "id" in query_params_for_mock:
                    id_val = query_params_for_mock["id"][0]
                    if "'" in id_val and "script" not in id_val: # Basic SQLi trigger
                        key_url = f"http://cli-test.com?id={id_val}" # Construct key as per MOCK_CLI_PAGES
                        return MOCK_CLI_PAGES.get(key_url, (f"Mock SQL Error for id={id_val}", {}))
                
                if "name" in query_params_for_mock:
                    name_val = query_params_for_mock["name"][0]
                    if "<script>" in name_val: # Basic XSS trigger
                        key_url = f"http://cli-test.com?name={name_val}"
                        return MOCK_CLI_PAGES.get(key_url, (f"Mock XSS content for name={name_val}", {}))

                # Fallback to exact URL match
                return MOCK_CLI_PAGES.get(url, (f"Mock content: Page not found in CLI mock for {url}.", {}))

            http_client.fetch_page = mock_cli_fetch_page
            
            # Also patch it for the detectors if they import fetch_page directly
            # This is generally bad practice (detectors should use the passed function)
            # but to be safe for this self-contained CLI test:
            try:
                from pysec_scanner.scanner.detectors import sqli_detector, xss_detector
                if hasattr(sqli_detector, 'fetch_page'): # Check if they even have it as a global
                    sqli_detector.fetch_page = mock_cli_fetch_page
                if hasattr(xss_detector, 'fetch_page'):
                    xss_detector.fetch_page = mock_cli_fetch_page
            except ImportError:
                pass # Detectors might not be structured that way or may not exist yet

        except ImportError:
            print("Warning: Could not import http_client for mocking in main.py. Running with actual HTTP requests if Scanner defaults to it.")
            original_fetch_page = None # Ensure it's defined
        except Exception as e:
            print(f"Error setting up mock for CLI: {e}")
            original_fetch_page = None

    main()

    # Restore original fetch_page if it was mocked and stored
    if not USE_REAL_REQUESTS and 'pytest' not in sys.modules and 'original_fetch_page' in locals() and original_fetch_page is not None:
        try:
            from pysec_scanner.utils import http_client
            http_client.fetch_page = original_fetch_page
            # Also restore for detectors if patched
            try:
                from pysec_scanner.scanner.detectors import sqli_detector, xss_detector
                if hasattr(sqli_detector, 'fetch_page'):
                     sqli_detector.fetch_page = original_fetch_page
                if hasattr(xss_detector, 'fetch_page'):
                    xss_detector.fetch_page = original_fetch_page
            except ImportError:
                pass
            print("--- CLI MAIN: RESTORED ORIGINAL HTTP REQUESTS ---")
        except ImportError:
            pass
        except Exception as e:
            print(f"Error restoring original fetch_page: {e}")
else:
    # This message is for clarity if someone tries `python pysec_scanner/main.py` without `-m`
    print(f"Note: {__file__} is part of a package. For direct execution, use 'python -m pysec_scanner.main <url>' from the project root.")
