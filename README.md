# Breach_a_Mail 🔒

Breach_a_Mail is a cybersecurity tool that allows users to check if their **email addresses or passwords** have been involved in a **data breach**. It uses the **Have I Been Pwned (HIBP) API** to provide real-time results and security recommendations. This tool is designed to help users assess the safety of their credentials and improve their cybersecurity awareness.

---

## ✨ Features

- **Email Breach Checking:** Verify if an email has been part of a known data breach.  
- **Password Breach Checking:** Test if a password has been exposed in past breaches.  
- **Real-Time Results:** Uses the HIBP API for up-to-date information.  
- **Bulk Checking:** Supports checking multiple email permutations efficiently.  
- **Security Tips:** Provides advice based on breach severity.  
- **Web Interface:** Displays results in a user-friendly web page.

---

## 🚀 Getting Started

Follow these instructions to get a local copy of the project running on your machine.

### Prerequisites

- Python 3.9+ installed  
- `pip` package manager  
- Internet connection (for HIBP API)  
- A web browser to view results  

---

### Installation & Setup

1. **Clone the repository**
```bash
git clone https://github.com/VeeNyanjau/Breach_a_Mail.git
cd Breach_a_Mail
python -m venv venv
# Activate the environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
pip install -r requirements.txt
HIBP_API_KEY=your_api_key_here
python app.py




