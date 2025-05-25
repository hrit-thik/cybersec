# PySec Scanner

## Brief Description
PySec Scanner is a basic web application security scanner designed to identify common vulnerabilities. It is built with Python and includes foundational elements for future integration of Markov Decision Process (MDP) based automated security decision-making. This tool is intended for educational purposes to explore web security concepts and automated scanning techniques.

## Features (Current)
*   **Basic SQL Injection (SQLi) Detection**: Identifies potential SQLi vulnerabilities in URL parameters using error-based detection techniques.
*   **Basic Cross-Site Scripting (XSS) Detection**: Detects reflected XSS vulnerabilities in URL parameters by checking if payloads are directly reflected in the HTTP response.
*   **Basic Anti-CSRF Token Check**: Scans HTML forms to check for the presence of common anti-CSRF token patterns.
*   **Command-Line Interface (CLI)**: Allows users to initiate scans and specify target URLs directly from the command line.
*   **Reporting**: Generates a formatted report of all identified vulnerabilities at the end of the scan.

## Setup and Installation

1.  **Clone the Repository**:
    ```bash
    # (Placeholder: Instructions for cloning will be added once the project is on a Git hosting platform)
    # git clone <repository_url>
    # cd pysec-scanner 
    ```

2.  **Create a Virtual Environment (Recommended)**:
    It's highly recommended to create and activate a virtual environment to manage project dependencies.
    ```bash
    python -m venv venv
    ```
    Activate the environment:
    *   On Windows: `.\venv\Scripts\activate`
    *   On macOS/Linux: `source venv/bin/activate`

3.  **Install Dependencies**:
    Install the necessary Python packages using pip:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
To run the scanner, use the `main.py` script located in the `pysec_scanner` directory. It's best run as a module from the project root directory.

**Basic Command**:
```bash
python -m pysec_scanner.main <target_url>
```

**Example**:
```bash
python -m pysec_scanner.main http://example.com
```
Replace `http://example.com` with the actual URL you intend to scan.

## Disclaimer
**Important**: PySec Scanner is a basic tool created for educational and demonstrative purposes only. It is not a substitute for professional security assessments or tools. 
*   **Use Responsibly**: Only use this tool on web applications for which you have explicit, written permission from the system owner to perform security scanning. 
*   **Potential Impact**: Automated scanning tools can generate significant traffic and may potentially disrupt normal operations of a web application. Understand the risks before using it.
*   **No Guarantees**: This tool may produce false positives or false negatives. Findings should always be manually verified.

The developers of PySec Scanner are not responsible for any misuse of this tool or any damage caused by its use.

## Future Work
This project has several areas for potential enhancement:
*   **Web Crawler**: Implement a crawler to discover and scan multiple pages of a website automatically.
*   **POST Request Scanning**: Extend vulnerability detection to include parameters submitted via POST requests.
*   **Advanced Vulnerability Detection**: Incorporate more sophisticated detection techniques (e.g., blind SQLi, DOM-based XSS).
*   **MDP Integration**: Fully develop and integrate the Markov Decision Process agent for intelligent decision-making regarding scan actions, threat prioritization, and adaptive scanning strategies.
*   **Configuration Options**: Allow users to configure scanner behavior (e.g., intensity, specific tests to run, output formats).
*   **Improved Reporting**: Enhance reporting with different formats (e.g., HTML, JSON) and more detailed explanations.
*   **Session Handling**: Add support for authenticated scans.
*   **Plugin System**: Allow for easy extension with new vulnerability detection modules.
