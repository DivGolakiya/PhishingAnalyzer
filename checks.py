# checks.py
from email.utils import parseaddr
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime
import whois
import os
import requests

# A list of common, trusted domains to prevent false positives
DOMAIN_ALLOWLIST = {
    'google.com',
    'microsoft.com',
    'windows.net',
    'office.com',
    'sharepoint.com',
    'github.com',
    'surrey.ac.uk',
    'unimelb.edu.au'
}

def analyze_headers_and_score(msg):
    """Analyzes email headers for SPF, DKIM, and DMARC authentication results."""
    phishing_score = 0
    findings = []
    auth_results = msg.get('Authentication-Results', '')

    if 'spf=pass' in auth_results:
        findings.append({'check': 'SPF', 'result': 'Pass', 'message': 'SPF check passed.'})
    elif 'spf=fail' in auth_results:
        phishing_score += 1
        findings.append({'check': 'SPF', 'result': 'Fail', 'message': 'SPF check failed.'})
    else:
        phishing_score += 0.5
        findings.append({'check': 'SPF', 'result': 'Neutral/Missing', 'message': 'SPF record is missing or neutral.'})

    if 'dkim=pass' in auth_results:
        findings.append({'check': 'DKIM', 'result': 'Pass', 'message': 'DKIM signature is valid.'})
    elif 'dkim=fail' in auth_results:
        phishing_score += 1
        findings.append({'check': 'DKIM', 'result': 'Fail', 'message': 'DKIM signature failed to verify.'})
    else:
        findings.append({'check': 'DKIM', 'result': 'Missing', 'message': 'No DKIM signature found.'})

    if 'dmarc=pass' in auth_results:
        findings.append({'check': 'DMARC', 'result': 'Pass', 'message': 'DMARC alignment passed.'})
    elif 'dmarc=fail' in auth_results:
        phishing_score += 2
        findings.append({'check': 'DMARC', 'result': 'Fail', 'message': 'DMARC check failed.'})
    else:
        findings.append({'check': 'DMARC', 'result': 'Missing', 'message': 'DMARC policy not found.'})
        
    return phishing_score, findings

def analyze_content(body_text, links, sender):
    """Analyzes email body for suspicious keywords and mismatched links, considering Safelinks and an allowlist."""
    score = 0
    findings = []
    suspicious_keywords = ['verify', 'password', 'urgent', 'expiring', 'login', 'suspended', 'confirm', 'immediate']
    found_keywords = []
    for keyword in suspicious_keywords:
        if keyword in body_text.lower():
            found_keywords.append(keyword)

    if found_keywords:
        score += 0.5 * len(found_keywords)
        findings.append({'check': 'Keywords', 'result': 'Suspicious', 'message': f"Found suspicious keywords: {', '.join(found_keywords)}"})

    _, sender_email = parseaddr(sender)
    if '@' in sender_email:
        sender_domain = sender_email.split('@')[1]
        
        for link in links:
            try:
                if "safelinks.protection.outlook.com" in link:
                    parsed_link = urlparse(link)
                    query_params = parse_qs(parsed_link.query)
                    original_url = unquote(query_params.get('url', [''])[0]) if 'url' in query_params else link
                    link_domain = urlparse(original_url).netloc
                else:
                    link_domain = urlparse(link).netloc
                
                is_mismatched = not link_domain.endswith(sender_domain)
                is_allowed = any(link_domain.endswith(allowed) for allowed in DOMAIN_ALLOWLIST)
                
                if is_mismatched and not is_allowed:
                    score += 3
                    findings.append({'check': 'URL Mismatch', 'result': 'Fail', 'message': f"Link domain ({link_domain}) doesn't match sender ({sender_domain}) and is not on the allowlist."})
                    break
            except Exception:
                continue
                
    return score, findings

def analyze_domain_age(links):
    """Checks the creation date of the first domain in a list of links."""
    score = 0
    findings = []
    if not links:
        return score, findings

    domain_name = urlparse(links[0]).netloc
    if not domain_name:
        return score, findings

    try:
        domain_info = whois.whois(domain_name)
        if not domain_info or not domain_info.creation_date:
            raise ValueError("Incomplete WHOIS data returned.")
        
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        domain_age = (datetime.now() - creation_date).days
        if domain_age < 180:
            score += 3
            findings.append({'check': 'Domain Age', 'result': 'Fail', 'message': f"Domain '{domain_name}' is new ({domain_age} days old)."})
        else:
            findings.append({'check': 'Domain Age', 'result': 'Pass', 'message': f"Domain '{domain_name}' is established ({domain_age} days old)."})
            
    except Exception as e:
        findings.append({'check': 'Domain Age', 'result': 'Neutral/Missing', 'message': f"Could not check age for '{domain_name}'."})
        
    return score, findings

def analyze_attachments(msg):
    """Checks for suspicious attachments by file extension."""
    score = 0
    findings = []
    attachments = []
    
    high_risk_extensions = ['.exe', '.msi', '.bat', '.cmd', '.scr', '.js', '.vbs', '.ps1', '.docm', '.xlsm', '.pptm']
    archive_extensions = ['.zip', '.rar', '.7z', '.jar']

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
            continue
            
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            file_ext = os.path.splitext(filename)[1].lower()
            
            if file_ext in high_risk_extensions:
                score += 4
                findings.append({'check': 'Attachment', 'result': 'Fail', 'message': f"Found high-risk attachment: '{filename}'."})
            elif file_ext in archive_extensions:
                score += 1
                findings.append({'check': 'Attachment', 'result': 'Suspicious', 'message': f"Found archive attachment. Inspect contents carefully: '{filename}'."})

    if attachments and not findings:
        findings.append({'check': 'Attachment', 'result': 'Pass', 'message': f"Found {len(attachments)} attachment(s), no high-risk types detected."})
    
    return score, findings

def check_url_reputation(links, api_key):
    """Checks URL reputation using the Google Web Risk API."""
    score = 0
    findings = []
    if not links or not api_key:
        return score, findings

    url = f"https://webrisk.googleapis.com/v1/uris:search?key={api_key}"
    links_to_check = links[:5]

    try:
        for link in links_to_check:
            body = {'uri': link, 'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING']}
            response = requests.get(url, params=body)
            
            if response.status_code == 200:
                data = response.json()
                if 'threat' in data:
                    threat_type = data['threat'].get('threatTypes', ['UNKNOWN'])[0]
                    score += 5
                    findings.append({'check': 'URL Reputation', 'result': 'Fail', 'message': f"URL '{link[:50]}...' is on a known blacklist for {threat_type}."})
                    return score, findings
            elif response.status_code == 400:
                 findings.append({'check': 'URL Reputation', 'result': 'Neutral/Missing', 'message': "Google API Error. Check if your API key is valid and the Web Risk API is enabled."})
                 return score, findings
                 
    except requests.exceptions.RequestException as e:
        findings.append({'check': 'URL Reputation', 'result': 'Neutral/Missing', 'message': "Could not connect to Google Web Risk API."})
        return score, findings

    if not findings:
        findings.append({'check': 'URL Reputation', 'result': 'Pass', 'message': "URLs were not found on any known blacklists."})

    return score, findings
