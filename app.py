from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import requests
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import os
import hashlib

# Load environment variables
load_dotenv()
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"

app = Flask(__name__)
app.secret_key = 'replace_this_with_a_secure_random_secret_key'

# Rate limiting setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

# Updated Email validator (relaxed pattern to allow all valid domains)
EMAIL_REGEX = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

# HIBP endpoint
HIBP_ENDPOINT = "https://haveibeenpwned.com/api/v3/breachedaccount/"

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
@limiter.limit("5 per minute")
def check_email():
    email = request.form.get('email', '').strip()

    # Validate email format
    if not re.match(EMAIL_REGEX, email):
        flash("❌ Invalid email format. Please enter a valid email address.", "error")
        return redirect(url_for('index'))

    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "Breach-A-Mail Checker"
    }

    response = requests.get(
        f"{HIBP_ENDPOINT}{email}",
        headers=headers,
        params={"truncateResponse": False}
    )

    if response.status_code == 200:
        breaches = response.json()
        message = f"⚠️ Oh no! It seems like {email} was involved in a data breach. Please review the details below."
        # Show results only on POST, not after redirect
        return render_template('index.html', breaches=breaches, message=message, email=email)

    elif response.status_code == 404:
        flash("🎉 Good news! No breach found for this email.", "success")
        return redirect(url_for('index'))

    elif response.status_code == 429:
        flash("⚠️ Too many requests. Please wait a minute and try again.", "error")
        return redirect(url_for('index'))

    else:
        flash(f"Error checking breach: {response.status_code} - {response.text}", "error")
        return redirect(url_for('index'))

@app.route('/breachinfo', methods=['POST'])
def breach_lookup():
    data = request.json
    breach_name = data.get("breach")

    if not breach_name:
        return jsonify({"reply": "Please provide a breach name to look up."})

    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "Chatbot-Breach-Fetcher"
    }

    # Try to get breach info from HIBP
    response = requests.get(f"https://haveibeenpwned.com/api/v3/breach/{breach_name}", headers=headers)

    if response.status_code == 200:
        result = response.json()
        message = (
            f"🔎 **{result['Name']}** breach occurred on **{result['BreachDate']}**.\n\n"
            f"**Data exposed:** {', '.join(result['DataClasses'])}\n"
            f"**Records affected:** {result['PwnCount']:,}\n"
            f"**Description:** {result['Description']}\n\n"
            f"More info: https://haveibeenpwned.com/PwnedWebsites#{result['Name']}"
        )
    else:
        message = f"Sorry, I couldn't find breach details for '{breach_name}'. Please check the spelling or try a different breach name."

    return jsonify({"reply": message})

@app.route('/latest-breaches', methods=['GET'])
def get_latest_breaches():
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "Breach-A-Mail Checker"
    }

    # Get all breaches and sort by date
    response = requests.get("https://haveibeenpwned.com/api/v3/breaches", headers=headers)
    
    if response.status_code == 200:
        breaches = response.json()
        
        # Sort by breach date (most recent first) and get the latest 10
        sorted_breaches = sorted(breaches, key=lambda x: x.get('BreachDate', ''), reverse=True)[:10]
        
        latest_info = []
        for breach in sorted_breaches:
            breach_info = {
                'name': breach['Name'],
                'date': breach['BreachDate'],
                'pwn_count': breach['PwnCount'],
                'data_classes': breach['DataClasses'],
                'description': breach['Description']
            }
            latest_info.append(breach_info)
        
        return jsonify({"latest_breaches": latest_info})
    else:
        return jsonify({"error": "Could not fetch breach data"}), 500

@app.route('/check-password-breach', methods=['POST'])
def check_password_breach():
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    hibp_url = f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        resp = requests.get(hibp_url, timeout=5)
        if resp.status_code != 200:
            return jsonify({'error': 'HIBP API error'}), 502
        hashes = resp.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return jsonify({'breached': True, 'count': int(count)})
        return jsonify({'breached': False, 'count': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
