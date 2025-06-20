from flask import Flask, render_template, request
import requests

app = Flask(__name__)

HIBP_API_KEY = "0d76c98219db4a039366021719867573"
HIBP_ENDPOINT = "https://haveibeenpwned.com/api/v3/breachedaccount/"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_email():
    email = request.form['email']
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
        return render_template('index.html', breaches=breaches, email=email)
    elif response.status_code == 404:
        message = "🎉 Good news! No breach found for this email."
        return render_template('index.html', message=message, email=email)
    else:
        error = f"Error checking breach: {response.status_code} - {response.text}"
        return render_template('index.html', error=error, email=email)

if __name__ == '__main__':
    app.run(debug=True)
