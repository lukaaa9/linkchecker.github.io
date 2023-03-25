from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Replace with your API key
API_KEY = 'fecb9dd86c09ca2051319543236846bd417f4e1602a72cde208de8bbe4d98f5f'

# URL of the Virustotal API endpoint
VT_API_URL = 'https://www.virustotal.com/api/v3/urls'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        result = scan_url(url)
        return render_template('result.html', **result)
    else:
        return render_template('index3.html')


def scan_url(url):
    """Scan a URL for viruses using Virustotal API"""
    headers = {
        'x-apikey': API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        'url': url,
        'scan_types': ['proactive', 'behaviour', 'static', 'dynamic']
    }
    response = requests.post(VT_API_URL, headers=headers, json=data)
    if response.status_code == 200:
        json_data = response.json()
        attributes = json_data['data'][0]['attributes']
        if attributes['last_analysis_stats']['malicious'] > 0:
            is_malicious = True
            score = attributes['last_analysis_stats']['malicious']
            reasons = [a['name'] for a in attributes['last_analysis_results'].values() if a['category'] == 'malicious']
        else:
            is_malicious = False
            score = None
            reasons = None
        return {'url': url, 'is_malicious': is_malicious, 'score': score, 'reasons': reasons}
    else:
        return {'url': url, 'is_malicious': None, 'score': None, 'reasons': None}
