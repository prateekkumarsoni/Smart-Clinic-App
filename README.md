# Smart Clinic

Integrated Clinic Management System with Role-Based and Relationship-Based Access Control,
Intelligent Appointment Scheduling, and Consent-Gated Encrypted Health Records.

Four roles (patient, doctor, receptionist, admin) in one Streamlit app: scheduling with waitlist and
walk-in queue, notifications, encrypted health records, billing, search, analytics and compliance tools.

## Run on Windows

1. Install Python 3.11 or newer from python.org (tick "Add Python to PATH").
2. Open Command Prompt in this folder and run:

       python -m venv .venv
       .venv\Scripts\activate
       pip install -r requirements.txt
       streamlit run app.py

3. The app opens in your browser. Out of the box it runs in **Simulated** mode (no keys needed).
   Sign in with a demo account (password `Demo@1234`):
   admin@clinic.demo, reception@clinic.demo, priya.sharma@clinic.demo, aman.gupta@clinic.demo,
   neha.verma@clinic.demo, rahul.singh@clinic.demo

## Turn on live services

Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in what you want to use,
then switch on **Live services** in the sidebar.

| Service | What you need |
|---|---|
| Email | A Gmail account with 2-step verification, then Google Account > Security > App passwords. Put the address in `GMAIL_USER` and the 16-character password in `GMAIL_APP_PASSWORD`. |
| Push | Install the ntfy app, subscribe to a long random topic name, and put the same name in `NTFY_TOPIC`. |
| SMS | A Twilio trial account. Verify your phone number in Twilio, then fill the three `TWILIO_` values. Register or edit a patient with that number. |
| Payments | A Razorpay account in **Test Mode**. Copy the test Key ID and Secret. Test payment details are in Razorpay's documentation. |

Payment flow in Live mode: the patient clicks Pay, opens the Razorpay page, pays with a test card or UPI,
returns and clicks "I have paid, check status".

The insurer is always simulated. Without internet, switch Live services off and everything still works.

## Deploy on Streamlit Community Cloud

1. Create a GitHub repository and upload `app.py`, `requirements.txt` and `.gitignore`
   (never upload `.streamlit/secrets.toml`).
2. At share.streamlit.io choose "Create app", select the repository, branch `main` and file `app.py`.
3. Open Advanced settings > Secrets and paste the contents of your filled-in `secrets.toml`. Deploy.

Note: Community Cloud storage is temporary. The database and uploaded files reset when the app restarts,
and the demo accounts are recreated automatically. Set `FERNET_KEY` in Secrets so the encryption key stays stable.
Set `SHOW_DEMO_ACCOUNTS = "false"` once you stop demonstrating.

## Before presenting

- Test every live service once from the deployed URL on real devices.
- Admin > Analytics > "Load two weeks of sample data" fills the dashboard with demonstration data.
- Keep Live services off as a fallback in case the venue Wi-Fi fails.
