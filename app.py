from flask import Flask, request, render_template
import re
import requests
from urllib.parse import urlparse

app = Flask(__name__)

# Function to check if URL is suspicious based on patterns
def is_suspicious_url(url):
    # Define suspicious patterns
    suspicious_patterns = [
        r'http[s]?://[^/]*\.[a-zA-Z]{2,3}/[^/]+/[^/]+',  # URL with multiple directories
        r'http[s]?://[^/]*\.[a-zA-Z]{2,3}/\w+\.\w+\.\w+',  # URL with subdomains
        r'http[s]?://[^/]*\.[a-zA-Z]{2,3}/[^/]+\?[^=]+=[^&]+&[^=]+=[^&]+',  # URL with multiple query parameters
        r'http[s]?://[^/]*\.[a-zA-Z]{2,3}/[a-zA-Z0-9]{30,}',  # URL with long path
        r'http[s]?://[^/]*\.[a-zA-Z]{2,3}/[a-zA-Z0-9]{10,}\.[a-zA-Z]{2,3}',  # URL with encoded path
    ]
    
    # Check URL against patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    
    return False

# Function to check if URL is accessible
def is_url_accessible(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

# Main function to check if URL is phishing
def check_phishing_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        return False, "Invalid URL"
    
    if is_suspicious_url(url):
        return True, "Suspicious URL pattern detected"
    
    if not is_url_accessible(url):
        return True, "URL not accessible"
    
    return False, "URL seems safe"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        is_phishing, reason = check_phishing_url(url)
        return render_template('index.html', url=url, is_phishing=is_phishing, reason=reason)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
