import re

# Common anti-CSRF token field names (as regex patterns to be flexible)
CSRF_TOKEN_NAMES_PATTERNS = [
    re.compile(r"csrf_token", re.IGNORECASE),
    re.compile(r"CSRFToken", re.IGNORECASE), # Explicitly listed though covered by above
    re.compile(r"authenticity_token", re.IGNORECASE),
    re.compile(r"_token", re.IGNORECASE),
    re.compile(r"xsrf_token", re.IGNORECASE), # XSRF variant
    re.compile(r"nonce", re.IGNORECASE), # Sometimes used
    re.compile(r"__RequestVerificationToken", re.IGNORECASE) # .NET
]

# Regex to find forms and capture their content.
# This is a simplified regex and might struggle with complex/malformed HTML.
# It captures everything between <form...> and </form> non-greedily.
FORM_REGEX = re.compile(r"<form(.*?)>(.*?)</form>", re.IGNORECASE | re.DOTALL)

# Regex to find input fields within a form, particularly hidden ones.
# It captures the whole input tag.
INPUT_FIELD_REGEX = re.compile(r"<input(.*?)>", re.IGNORECASE | re.DOTALL)

# Regex to get attributes from a tag string
ATTR_REGEX = re.compile(r"""\b(name|id|action|method)\s*=\s*([\"'])(.*?)\2""", re.IGNORECASE)


def get_tag_attributes(tag_attributes_string: str) -> dict:
    """Helper to extract key attributes from a tag's attribute string."""
    attributes = {}
    for match in ATTR_REGEX.finditer(tag_attributes_string):
        attributes[match.group(1).lower()] = match.group(3)
    return attributes

def check_csrf_forms(html_content: str) -> list:
    """
    Checks for missing anti-CSRF tokens in HTML forms using regex.

    Args:
        html_content: The HTML content of a page.

    Returns:
        A list of dictionaries, where each dictionary represents a form
        found without a recognizable anti-CSRF token. Returns an empty
        list if no such forms are found or no forms exist.
    """
    findings = []
    forms_found = 0

    if not html_content:
        return []

    for form_match in FORM_REGEX.finditer(html_content):
        forms_found += 1
        form_attributes_str = form_match.group(1)
        form_content = form_match.group(2)

        form_details_map = get_tag_attributes(form_attributes_str)
        form_identifier = (
            f"action='{form_details_map.get('action', 'N/A')}', "
            f"method='{form_details_map.get('method', 'POST').upper()}', "
            f"id='{form_details_map.get('id', 'N/A')}'"
        )

        has_csrf_token = False
        # Look for input fields within this specific form's content
        for input_match in INPUT_FIELD_REGEX.finditer(form_content):
            input_tag_str = input_match.group(0) # The whole <input ...> tag
            input_attributes_str = input_match.group(1) # Attributes part of the input tag

            # Check type="hidden" (optional, but common for CSRF tokens)
            # For simplicity, we'll check all input names, not just hidden ones,
            # as sometimes tokens are not strictly hidden or type is omitted.
            # A more robust check would parse type attribute.
            
            input_attrs = get_tag_attributes(input_attributes_str)
            input_name = input_attrs.get('name')

            if input_name:
                for token_pattern in CSRF_TOKEN_NAMES_PATTERNS:
                    if token_pattern.search(input_name):
                        has_csrf_token = True
                        break # Found a token in this input field
            if has_csrf_token:
                break # Found a token for this form

        if not has_csrf_token:
            findings.append({
                'vulnerability': 'Missing Anti-CSRF Token',
                'form_details': form_identifier,
                'evidence': 'No common anti-CSRF token input field name (e.g., csrf_token, authenticity_token, _token) found in this form.',
                'raw_form_snippet': form_match.group(0)[:500] + "..." # First 500 chars of form
            })

    if forms_found == 0:
        # print("No <form> elements found in the HTML content.") # For debugging
        pass
        
    return findings

if __name__ == '__main__':
    print("--- Testing CSRF Detector ---")

    html_with_csrf_token = """
    <html><body>
        <form action="/submit" method="post">
            <input type="text" name="username">
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <input type="submit" value="Submit">
        </form>
        <form action="/search" method="get" id="searchForm">
            <input type="text" name="query">
            <input type="hidden" name="_token" value="def456uvw">
            <input type="submit" value="Search">
        </form>
    </html></body>
    """
    results = check_csrf_forms(html_with_csrf_token)
    print(f"\nResults for HTML with CSRF tokens (should be empty): {results}")
    assert not results

    html_missing_csrf_token = """
    <html><body>
        <form action="/login" method="post" id="loginForm">
            <input type="text" name="user">
            <input type="password" name="pass">
            <input type="submit" value="Login">
        </form>
        <form action="/update" method="post">
            <!-- No CSRF token here -->
            <input type="text" name="data">
            <input type="submit">
        </form>
    </html></body>
    """
    results = check_csrf_forms(html_missing_csrf_token)
    print(f"\nResults for HTML missing CSRF tokens (should find 2): {results}")
    assert len(results) == 2
    if results:
        assert results[0]['form_details'] == "action='/login', method='POST', id='loginForm'"
        assert results[1]['form_details'] == "action='/update', method='POST', id='N/A'"


    html_no_forms = """
    <html><body>
        <p>This page has no forms.</p>
    </html></body>
    """
    results = check_csrf_forms(html_no_forms)
    print(f"\nResults for HTML with no forms (should be empty): {results}")
    assert not results

    html_empty_content = ""
    results = check_csrf_forms(html_empty_content)
    print(f"\nResults for empty HTML content (should be empty): {results}")
    assert not results
    
    html_form_with_different_token_name = """
    <html><body>
        <form action="/process" method="post">
            <input type="text" name="field">
            <input type="hidden" name="my_special_csrf_guard" value="secure123">
            <input type="submit" value="Process">
        </form>
    </html></body>
    """
    results = check_csrf_forms(html_form_with_different_token_name)
    print(f"\nResults for HTML with non-standard CSRF token name (should find 1): {results}")
    assert len(results) == 1
    if results:
        assert "my_special_csrf_guard" not in str(CSRF_TOKEN_NAMES_PATTERNS) # Ensure our patterns don't match this

    html_with_csrf_in_value_not_name = """
    <html><body>
        <form action="/submit" method="post">
            <input type="text" name="username">
            <input type="hidden" name="some_field" value="csrf_token_is_here_but_not_name">
            <input type="submit" value="Submit">
        </form>
    </html></body>
    """
    results = check_csrf_forms(html_with_csrf_in_value_not_name)
    print(f"\nResults for HTML with CSRF pattern in value, not name (should find 1): {results}")
    assert len(results) == 1

    print("\n--- All CSRF detector tests passed (basic regex version) ---")
