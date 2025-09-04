# 🕵️ Phishing Email Analyzer

An intelligent tool designed to analyze email files (`.eml`) to detect signs of phishing. The analyzer uses a multi-layered approach, combining heuristic-based checks with external API integrations to provide a comprehensive risk score. The project features both a command-line interface (CLI) and a user-friendly web application built with Streamlit.

## Demo

![Phishing Analyzer Screenshot](screenshot.png)

---

## Key Features

The analyzer assesses emails based on a variety of security indicators:

* **Header Analysis**:
    * Verifies **SPF**, **DKIM**, and **DMARC** email authentication standards to check for sender spoofing.

* **Content & URL Analysis**:
    * **URL Mismatch Detection**: Intelligently checks if link domains match the sender's domain.
    * **Microsoft Safelinks Handling**: Automatically "unwraps" Microsoft Safelinks to analyze the true destination URL.
    * **Trusted Domain Allowlist**: Reduces false positives by recognizing legitimate external services like GitHub and SharePoint.
    * **Suspicious Keyword Detection**: Scans the email body for common phishing keywords (e.g., "urgent," "verify," "password").

* **External API Integrations**:
    * **Domain Age Check**: Uses a WHOIS lookup to flag newly created, suspicious domains.
    * **URL Reputation Check**: Leverages the **Google Web Risk API** to check if links are on known blacklists for malware or social engineering.

* **Attachment Analysis**:
    * Identifies and flags high-risk attachment types (e.g., `.exe`, `.js`, `.bat`).
    * Classifies archive files (e.g., `.zip`, `.rar`) as suspicious, recommending manual inspection.

* **User Interfaces**:
    * **Web Application**: A clean, interactive UI built with **Streamlit** that allows users to upload `.eml` files or paste raw email source code.
    * **Command-Line Interface**: A fully functional CLI for terminal-based analysis.

---

## Technology Stack

* **Language**: Python 3
* **Core Libraries**:
    * `streamlit`: For the interactive web application.
    * `requests`: For making API calls to the Google Web Risk API.
    * `python-whois`: For performing WHOIS lookups to determine domain age.
    * `beautifulsoup4`: For parsing HTML content within emails.
* **APIs**: Google Web Risk API

---

## Setup and Usage

### Prerequisites

* Python 3.10+
* A Google Cloud Platform account with the **Web Risk API** enabled and an **API key**.

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd PhishingAnalyzer
```

### 2. Set Up the Environment
Create and activate a Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```
Install the required dependencies:
```bash
pip install -r requirements.txt
```

### 3. Add Your API Key
Create a file named `api_key.txt` in the root of the project folder and paste your Google Web Risk API key into it.

### 4. Run the Application
You can run either the web application or the command-line tool.
**To run the Streamlit Web App:**
```bash
streamlit run app.py
```
**To run the Command-Line Interface (CLI):**
```bash
python main.py
```

---

## Project Structure

The project is organized into modular files for better readability and maintenance:
```
PhishingAnalyzer/
├── app.py              # Main Streamlit web application
├── main.py             # Original Command-Line Interface (CLI)
├── analyzer.py         # Core analysis engine and parsing logic
├── checks.py           # All individual analysis functions (modules)
├── utils.py            # Helper functions (e.g., clear_screen)
├── requirements.txt    # Project dependencies
├── api_key.txt         # Stores the Google Web Risk API key
└── screenshot.png      # Demo image for the README
```
