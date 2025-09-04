# analyzer.py
import email
from email.header import decode_header
from bs4 import BeautifulSoup
import re
import os

from checks import analyze_headers_and_score, analyze_content, analyze_domain_age, analyze_attachments, check_url_reputation

def analyze_email_from_string(eml_content, api_key):
    """
    The core analysis engine. Takes email content as a string.
    Returns a dictionary with the analysis results.
    """
    msg = email.message_from_string(eml_content)

    # 1. Parse email content
    sender = msg.get('From', '')
    recipient = msg.get('To', '')
    subject_header = decode_header(msg.get('Subject', ''))
    subject = subject_header[0][0]
    if isinstance(subject, bytes):
        subject = subject.decode(subject_header[0][1] or 'utf-8')

    links, body_text = [], ""
    for part in msg.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            try:
                payload = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                if "text/html" in part.get_content_type():
                    soup = BeautifulSoup(payload, 'lxml')
                    body_text += soup.get_text(separator='\n', strip=True)
                    for a in soup.find_all('a', href=True): links.append(a['href'])
                else:
                    body_text += payload
            except Exception:
                continue

    plain_text_urls = re.findall(r'(https?://[^\s]+)', body_text)
    all_links = list(set(links + plain_text_urls))

    # 2. Run all checks
    header_score, header_findings = analyze_headers_and_score(msg)
    content_score, content_findings = analyze_content(body_text, all_links, sender)
    age_score, age_findings = analyze_domain_age(all_links)
    attachment_score, attachment_findings = analyze_attachments(msg)
    reputation_score, reputation_findings = check_url_reputation(all_links, api_key)

    total_score = header_score + content_score + age_score + attachment_score + reputation_score
    all_findings = header_findings + content_findings + age_findings + attachment_findings + reputation_findings

    # 3. Return results as a dictionary
    return {
        "score": total_score,
        "findings": all_findings,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "links": all_links,
        "body_snippet": body_text[:400] + "..."
    }


def analyze_email_from_file(eml_file_path, api_key):
    """
    Legacy function for the command-line tool.
    Reads an email from a file and prints the results.
    """
    with open(eml_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        eml_content = f.read()
    
    results = analyze_email_from_string(eml_content, api_key)

    # Print the results for the CLI
    print(f"--- 🔍 Analysis for: {os.path.basename(eml_file_path)} ---")
    print(f"**Phishing Score: {results['score']}** (Higher is more suspicious)\n")
    for finding in results['findings']:
        icon = {"Pass": "✅", "Fail": "❌"}.get(finding['result'], "⚠️")
        print(f"{icon} **{finding['check']}**: {finding['message']}")
    
    print("\n" + "="*50 + "\n")
    print("--- 📧 Basic Email Headers ---")
    print(f"**Sender:** {results['sender']}")
    print(f"**Recipient:** {results['recipient']}")
    print(f"**Subject:** {results['subject']}\n")
    print("--- 🔗 URLs Found ---")
    if results['links']:
        for i, link in enumerate(results['links'], 1): print(f"{i}. {link}")
    else: print("No URLs found in the email body.")
    print("\n--- 📝 Body Text Snippet ---")
    print(results['body_snippet'])

# Rename the old function to avoid confusion
analyze_email = analyze_email_from_file
