# ✅ FINAL UPDATED app.py with full URL typosquatting detection
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import joblib
import re
import datetime
import whois
from urllib.parse import urlparse
from difflib import SequenceMatcher
import ipaddress
import requests

app = Flask(__name__)
CORS(app)

model = joblib.load('phishing_model_53.pkl')
scaler = joblib.load('scaler_53.pkl')

# 📌 WHITELIST (truncated for brevity)
whitelist_domains = [
    'gov.rw', 'rra.gov.rw', 'rbc.gov.rw', 'reb.rw', 'newtimes.co.rw', 'igihe.com', 'ur.ac.rw', 'psf.org.rw',
    'igihe.com', 'inyarwanda.com', 'kigalitoday.com', 'rwandashow.com', 'ktpress.rw', 'umuseke.rw',
    'facebook.com', 'google.com', 'paypal.com', 'twitter.com', 'instagram.com', 'loda.gov.rw/ubudehe/' , 'linkedin.com', 'youtube.com'
    # ... (full list kept in original file)
]

phishing_keywords = [
    'account', 'alert', 'bank', 'billing', 'bit.ly', 'buff.ly', 'check', 'confirm', 'edu', 'facebook',
    'free', 'github', 'goo.gl', 'google', 'gov.rw', 'important', 'is.gd', 'login', 'nirda', 'org', 'ow.ly',
    'password', 'payment', 'rbc', 'secure', 'security', 'signin', 'support', 't.co', 'tinyurl', 'unlock',
    'update', 'user', 'validate', 'verify', 'webmail', 'wikipedia', 'win'
]

trusted_brands = [
    'google', 'paypal', 'facebook', 'yahoo', 'amazon', 'mtn', 'airtel',
    'irembo', 'rbc', 'hec', 'gov.rw', 'reb', 'rssb', 'bankofamerica'
]

def get_days_between_dates(start, end):
    if isinstance(start, list): start = start[0]
    if isinstance(end, list): end = end[0]
    if isinstance(start, datetime.datetime) and isinstance(end, datetime.datetime):
        return (end - start).days
    return 365

def is_typosquatting_or_abuse(domain):
    domain = domain.lower().replace("www.", "")
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        return True
    for part in domain.split('.'):
        for brand in trusted_brands:
            similarity = SequenceMatcher(None, part, brand).ratio()
            if similarity > 0.8 and part != brand:
                return True
            if brand in part and not domain.endswith(brand + '.com') and not domain.endswith(brand + '.rw'):
                return True
    return False

def is_url_path_suspicious(url):
    url = url.lower()
    for brand in trusted_brands:
        if brand in url:
            for d in whitelist_domains:
                if brand in d:
                    if d not in url:
                        return True
    if re.search(r'(.)\1{3,}', url):  # Detect char repetition like rrraaa.gov.rw
        return True
    return False

def is_safe_local_ip(domain):
    try:
        ip = ipaddress.ip_address(domain)
        return ip.is_private
    except ValueError:
        return domain in ['localhost']

def extract_structural_features(url):
    features = {}
    ip_pattern = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
    features['use_of_ip'] = 1 if ip_pattern.search(url) else 0
    features['url_length'] = len(url)
    features['short_url'] = 1 if re.search(r"(bit\.ly|goo\.gl|tinyurl|is\.gd|ow\.ly|t\.co|buff\.ly)", url) else 0
    features['at_symbol'] = 1 if '@' in url else 0
    features['double_slash'] = 1 if url.count('//') > 1 else 0
    domain = urlparse(url).netloc
    features['prefix_suffix'] = 1 if '-' in domain else 0
    features['sub_domain'] = domain.count('.') - 1
    features['https_domain'] = 1 if urlparse(url).scheme == 'https' else 0
    try:
        domain_info = whois.whois(domain)
        features['domain_reg_len'] = get_days_between_dates(domain_info.creation_date, domain_info.expiration_date)
        features['dns_record'] = 1 if domain_info.name_servers else 0
    except:
        features['domain_reg_len'] = 0
        features['dns_record'] = 0
    features['forwarding'] = 0
    features['iframe'] = 0
    features['mouse_over'] = 0
    features['right_click'] = 0
    return features

def extract_keyword_features(url):
    url = url.lower()
    keyword_feats = {}
    for word in phishing_keywords:
        fname = f"has_{word.replace('.', '_')}"
        keyword_feats[fname] = 1 if word in url else 0
    return keyword_feats

@app.route('/')
def home():
    return "✅ Phishing Detector API is running"

@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.json
        url = data.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        if not url.lower().startswith(("http://", "https://")):
            return jsonify({'url': url, 'is_phishing': True, 'probability': 0.99, 'manual_override': True,
                            'reason': '❌ Malformed URL: Invalid protocol',
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            url = response.url
        except:
            pass

        parsed = urlparse(url)
        domain = parsed.hostname.lower() if parsed.hostname else ""

        if is_safe_local_ip(domain):
            return jsonify({'url': url, 'is_phishing': False, 'probability': 0.0, 'manual_override': True,
                            'reason': "✅ Safe: Localhost or private IP used for testing.",
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

        if any(domain == d or domain.endswith("." + d) for d in whitelist_domains):
            return jsonify({'url': url, 'is_phishing': False, 'probability': 0.0, 'manual_override': False,
                            'reason': "✅ Safe: Domain is officially trusted.",
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

        # ✅ Check for typosquatting OR full URL misuse
        if is_typosquatting_or_abuse(domain) or is_url_path_suspicious(url):
            return jsonify({'url': url, 'is_phishing': True, 'probability': 0.99, 'manual_override': True,
                            'reason': "❌ Suspicious: The URL mimics trusted brand or has unusual characters.",
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

        struct_feats = extract_structural_features(url)
        keyword_feats = extract_keyword_features(url)
        all_feats = {**struct_feats, **keyword_feats}

        if struct_feats['domain_reg_len'] == 0 or struct_feats['dns_record'] == 0:
            return jsonify({'url': url, 'is_phishing': True, 'probability': 0.99, 'manual_override': True,
                            'reason': "❌ Domain not registered or WHOIS lookup failed.",
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

        feature_order = [
            'at_symbol', 'dns_record', 'domain_reg_len', 'double_slash', 'forwarding',
            'has_account', 'has_alert', 'has_bank', 'has_billing', 'has_bit_ly', 'has_buff_ly', 'has_check',
            'has_confirm', 'has_edu', 'has_facebook', 'has_free', 'has_github', 'has_goo_gl', 'has_google',
            'has_gov_rw', 'has_important', 'has_is_gd', 'has_login', 'has_nirda', 'has_org', 'has_ow_ly',
            'has_password', 'has_payment', 'has_rbc', 'has_secure', 'has_security', 'has_signin', 'has_support',
            'has_t_co', 'has_tinyurl', 'has_unlock', 'has_update', 'has_user', 'has_validate', 'has_verify',
            'has_webmail', 'has_wikipedia', 'has_win', 'https_domain', 'iframe', 'label', 'mouse_over',
            'prefix_suffix', 'right_click', 'short_url', 'sub_domain', 'url_length', 'use_of_ip']

        vector = np.array([[all_feats.get(f, 0) for f in feature_order]])
        scaled = scaler.transform(vector)
        prediction = model.predict(scaled)[0]
        prob = model.predict_proba(scaled)[0][1]

        return jsonify({'url': url, 'is_phishing': bool(prediction), 'probability': float(prob),
                        'manual_override': False,
                        'reason': "✅ Safe: No phishing indicators." if not prediction else "⚠️ Detected by ML model.",
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
