import streamlit as st
import os
from analyzer import analyze_email_from_string

def get_api_key():
    """Reads the API key from api_key.txt."""
    if os.path.exists('.streamlit/secrets.toml'):
        with open('.streamlit/secrets.toml', 'r') as f:
            return f.read().strip()
    return None

# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="Phishing Email Analyzer",
    page_icon="🕵️",
    layout="wide"
)

st.title("🕵️ Phishing Email Analyzer")
st.write("Upload an `.eml` file or paste the full email source below to analyze it for signs of phishing.")

# --- API Key Handling ---
api_key = get_api_key()
if not api_key:
    st.warning("API key not found. The Google Web Risk URL reputation check will be skipped.", icon="⚠️")

# --- UI Elements ---
# NEW: File uploader for .eml files
uploaded_file = st.file_uploader(
    "Upload an email file (.eml)",
    type=['eml']
)

st.write("--- OR ---")

# Text area for pasting email source
email_source_text = st.text_area(
    "Paste Email Source Here:",
    height=300,
    placeholder="From: ...\nSubject: ...\n\n..."
)

if st.button("Analyze Email", type="primary"):
    email_source = ""
    
    # NEW: Prioritize the uploaded file
    if uploaded_file is not None:
        # To convert the uploaded file to a string, we read it.
        email_source = uploaded_file.getvalue().decode("utf-8")
    elif email_source_text:
        email_source = email_source_text

    # Run analysis only if we have some source content
    if email_source:
        with st.spinner("Analyzing... This may take a moment."):
            results = analyze_email_from_string(email_source, api_key)

        st.divider()
        st.header("Analysis Results")

        score = results['score']
        st.metric(label="Phishing Score", value=f"{score:.1f}", help="A higher score indicates a higher likelihood of phishing. Scores above 4.0 are highly suspicious.")
        
        for finding in results['findings']:
            icon = {"Pass": "✅", "Fail": "❌"}.get(finding['result'], "⚠️")
            st.markdown(f"{icon} **{finding['check']}**: {finding['message']}")

        with st.expander("Show Email Details"):
            st.subheader("Basic Headers")
            st.markdown(f"**From:** `{results['sender']}`")
            st.markdown(f"**To:** `{results['recipient']}`")
            st.markdown(f"**Subject:** {results['subject']}")
            
            st.subheader("URLs Found")
            if results['links']:
                for link in results['links']:
                    st.code(link, language=None)
            else:
                st.write("No URLs found.")

    else:
        st.error("Please upload an email file or paste the source into the text box to analyze.")
