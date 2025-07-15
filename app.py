from flask import Flask, render_template, request
import requests
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import os

# Load environment variables
load_dotenv()
HIBP_API_KEY = os.getenv("HIBP_API_KEY")

app = Flask(__name__)

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
@limiter.limit("5 per minute")
def check_email():
    email = request.form.get('email', '').strip()

    # Validate email format
    if not re.match(EMAIL_REGEX, email):
        error = "❌ Invalid email format. Please enter a valid email address."
        return render_template('index.html', error=error)

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
        return render_template('index.html', breaches=breaches, message=message, email=email)

    elif response.status_code == 404:
        message = "🎉 Good news! No breach found for this email."
        return render_template('index.html', message=message)

    elif response.status_code == 429:
        error = "⚠️ Too many requests. Please wait a minute and try again."
        return render_template('index.html', error=error)

    else:
        error = f"Error checking breach: {response.status_code} - {response.text}"
        return render_template('index.html', error=error)

if __name__ == '__main__':
    app.run(debug=True)
