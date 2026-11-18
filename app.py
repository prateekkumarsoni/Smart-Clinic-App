"""
Smart Clinic
Integrated Clinic Management System with Role-Based and Relationship-Based Access Control,
Intelligent Appointment Scheduling, and Consent-Gated Encrypted Health Records.

Run locally:   streamlit run app.py
Deploy:        Streamlit Community Cloud (add the keys listed in the README to the app's Secrets).
"""
import hashlib
import hmac
import io
import json
import os
import random
import re
import secrets
import smtplib
import sqlite3
import uuid
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from enum import Enum
from functools import wraps

import pandas as pd
import requests
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

st.set_page_config(page_title="Smart Clinic", page_icon=":material/medical_services:", layout="wide")

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
DATA_DIR = os.environ.get("CLINIC_DATA_DIR", "data")
DB_PATH = os.path.join(DATA_DIR, "smart_clinic.db")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
PDF_DIR = os.path.join(DATA_DIR, "pdf")
KEY_FILE = os.path.join(DATA_DIR, "vault.key")
for _d in (DATA_DIR, UPLOAD_DIR, PDF_DIR):
    os.makedirs(_d, exist_ok=True)

MAX_FAILED_ATTEMPTS = 3
LOCK_MINUTES = 15
GST_RATE = 0.18
IST = timezone(timedelta(hours=5, minutes=30))
CLINIC_NAME = "Smart Clinic"


def now() -> datetime:
    """Current clinic time (IST) as a naive datetime."""
    return datetime.now(IST).replace(tzinfo=None)


def ts(dt: datetime = None) -> str:
    return (dt or now()).strftime("%Y-%m-%d %H:%M:%S")


def slot_str(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M")


def secret(name: str, default=None):
    """Read a key from Streamlit secrets, falling back to environment variables."""
    try:
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.environ.get(name, default)


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL,
    phone TEXT, age INTEGER, specialization TEXT, license_number TEXT,
    city TEXT, consultation_fee REAL DEFAULT 0,
    is_active INTEGER DEFAULT 1, failed_attempts INTEGER DEFAULT 0, locked_until TEXT,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT, action TEXT NOT NULL,
    details TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS doctor_availability (
    id INTEGER PRIMARY KEY AUTOINCREMENT, doctor_email TEXT NOT NULL,
    day_of_week INTEGER NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL,
    slot_minutes INTEGER NOT NULL DEFAULT 20, buffer_minutes INTEGER NOT NULL DEFAULT 5);
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_email TEXT NOT NULL, doctor_email TEXT NOT NULL,
    start_dt TEXT NOT NULL, end_dt TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'scheduled',
    visit_type TEXT NOT NULL DEFAULT 'regular', recurrence_id TEXT,
    reminder_sent INTEGER DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_email TEXT NOT NULL, doctor_email TEXT NOT NULL,
    preferred_date TEXT NOT NULL, fulfilled INTEGER DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS queue_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_email TEXT NOT NULL, doctor_email TEXT NOT NULL,
    kind TEXT NOT NULL, priority INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'waiting',
    arrived_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT NOT NULL, channel TEXT NOT NULL,
    notif_type TEXT NOT NULL, subject TEXT, body TEXT, status TEXT, detail TEXT,
    is_read INTEGER DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS patient_profile (
    patient_email TEXT PRIMARY KEY, blood_group TEXT, allergies_enc TEXT, conditions_enc TEXT,
    consent_given INTEGER DEFAULT 0, updated_at TEXT);
CREATE TABLE IF NOT EXISTS medical_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_email TEXT NOT NULL, doctor_email TEXT NOT NULL,
    diagnosis_enc TEXT, notes_enc TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS prescriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_email TEXT NOT NULL, doctor_email TEXT NOT NULL,
    medications TEXT NOT NULL, notes TEXT, pdf_path TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lab_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_email TEXT NOT NULL, uploaded_by TEXT NOT NULL,
    filename TEXT NOT NULL, description TEXT, file_path TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT, appointment_id INTEGER NOT NULL, patient_email TEXT NOT NULL,
    subtotal REAL NOT NULL, tax REAL NOT NULL, total_amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', payment_id TEXT, receipt_path TEXT,
    created_at TEXT NOT NULL, paid_at TEXT);
CREATE TABLE IF NOT EXISTS payment_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_id INTEGER NOT NULL, provider TEXT NOT NULL,
    order_id TEXT NOT NULL, link_url TEXT, status TEXT NOT NULL DEFAULT 'created',
    signature TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS insurance_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_id INTEGER NOT NULL, patient_email TEXT NOT NULL,
    insurer TEXT, policy_number TEXT, claimed_amount REAL, approved_amount REAL,
    status TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS doctor_ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, appointment_id INTEGER NOT NULL UNIQUE,
    doctor_email TEXT NOT NULL, patient_email TEXT NOT NULL, rating INTEGER NOT NULL,
    comment TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, accessor_email TEXT NOT NULL, patient_email TEXT NOT NULL,
    action TEXT NOT NULL, status TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL);
"""


def connect():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def q(sql, params=(), one=False):
    con = connect()
    try:
        rows = con.execute(sql, params).fetchall()
    finally:
        con.close()
    if one:
        return dict(rows[0]) if rows else None
    return [dict(r) for r in rows]


def ex(sql, params=()):
    con = connect()
    try:
        cur = con.execute(sql, params)
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


@st.cache_resource
def init_database():
    con = connect()
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    return True


def audit(email, action, details=""):
    ex("INSERT INTO audit_log (user_email, action, details, created_at) VALUES (?,?,?,?)",
       (email, action, details, ts()))


# ----------------------------------------------------------------------------
# Roles and permissions
# ----------------------------------------------------------------------------
class Role(Enum):
    PATIENT = "patient"
    DOCTOR = "doctor"
    RECEPTIONIST = "receptionist"
    ADMIN = "admin"


PERMISSIONS = {
    Role.PATIENT: {"book_appointment", "view_own_appointments", "cancel_own_appointment",
                   "view_own_medical_records", "update_own_profile", "make_payment",
                   "rate_doctor", "manage_consent", "search_doctors"},
    Role.DOCTOR: {"view_own_schedule", "view_assigned_patient_records", "update_appointment_status",
                  "add_prescription", "set_availability", "report_delay"},
    Role.RECEPTIONIST: {"register_walkin_patient", "book_appointment_for_patient", "view_all_appointments",
                        "manage_queue", "collect_payment", "issue_refund", "send_reminders"},
    Role.ADMIN: {"create_user", "deactivate_user", "reactivate_user", "assign_role", "reset_user_password",
                 "view_all_users", "view_audit_log", "view_system_analytics", "process_erasure",
                 "run_retention", "generate_compliance_report"},
}


class PermissionDeniedError(Exception):
    pass


class AccountLockedError(Exception):
    pass


class ClinicError(Exception):
    """A business-rule violation that should be shown to the user as a message."""


def can(user: dict, permission: str) -> bool:
    return permission in PERMISSIONS.get(Role(user["role"]), set())


def requires(permission):
    """Decorator: the first argument of the wrapped function must be the acting user."""
    def wrap(fn):
        @wraps(fn)
        def inner(actor, *args, **kwargs):
            if not can(actor, permission):
                audit(actor["email"], "PERMISSION_DENIED", f"{permission} via {fn.__name__}")
                raise PermissionDeniedError(f"Your role ({actor['role']}) does not have permission: {permission}")
            return fn(actor, *args, **kwargs)
        return inner
    return wrap


# ----------------------------------------------------------------------------
# Passwords and field encryption
# ----------------------------------------------------------------------------
PBKDF2_ROUNDS = 150_000


def hash_password(password: str, salt: str = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ROUNDS).hex()
    return digest, salt


def verify_password(password, salt, stored_hash) -> bool:
    return secrets.compare_digest(hash_password(password, salt)[0], stored_hash)


def password_problem(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain a digit."
    if not re.search(r"[^\w\s]", password):
        return "Password must contain a special character."
    return None


def valid_email(email: str) -> bool:
    return re.match(r"^[\w.\-+]+@[\w\-]+(\.[\w\-]+)+$", email or "") is not None


@st.cache_resource
def get_vault():
    key = secret("FERNET_KEY")
    if not key:
        if os.path.exists(KEY_FILE):
            key = open(KEY_FILE).read().strip()
        else:
            key = Fernet.generate_key().decode()
            with open(KEY_FILE, "w") as f:
                f.write(key)
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(text):
    return get_vault().encrypt(text.encode()).decode() if text else None


def decrypt(token):
    if not token:
        return ""
    try:
        return get_vault().decrypt(token.encode()).decode()
    except InvalidToken:
        return "[unreadable]"


# ----------------------------------------------------------------------------
# Accounts and authentication
# ----------------------------------------------------------------------------
PUBLIC_FIELDS = "id, full_name, email, role, phone, age, specialization, license_number, city, consultation_fee, is_active"


def get_user(email: str):
    return q(f"SELECT {PUBLIC_FIELDS} FROM users WHERE email = ?", (email.strip().lower(),), one=True)


def create_account(full_name, email, password, role, phone=None, age=None, specialization=None,
                   license_number=None, city=None, fee=0, actor=None):
    email = email.strip().lower()
    if not full_name.strip():
        raise ClinicError("Full name is required.")
    if not valid_email(email):
        raise ClinicError("Please enter a valid email address.")
    problem = password_problem(password)
    if problem:
        raise ClinicError(problem)
    if Role(role) == Role.DOCTOR and not specialization:
        raise ClinicError("Doctors need a specialization.")
    if q("SELECT 1 FROM users WHERE email = ?", (email,), one=True):
        raise ClinicError("An account with this email already exists.")
    pw_hash, salt = hash_password(password)
    ex("""INSERT INTO users (full_name, email, password_hash, salt, role, phone, age, specialization,
          license_number, city, consultation_fee, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
       (full_name.strip(), email, pw_hash, salt, role, phone or None, age, specialization,
        license_number, city, float(fee or 0), ts()))
    audit(actor["email"] if actor else email, "USER_CREATED", f"{email} as {role}")
    return get_user(email)


@requires("create_user")
def admin_create_user(actor, **kwargs):
    return create_account(actor=actor, **kwargs)


def register_patient(full_name, email, password, phone=None, age=None, city=None):
    return create_account(full_name, email, password, "patient", phone=phone, age=age, city=city)


def login(email: str, password: str):
    email = email.strip().lower()
    row = q("SELECT * FROM users WHERE email = ?", (email,), one=True)
    if not row:
        raise ClinicError("Invalid email or password.")
    if not row["is_active"]:
        raise ClinicError("This account has been deactivated. Please contact the administrator.")
    if row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > now():
        mins = int((datetime.fromisoformat(row["locked_until"]) - now()).total_seconds() // 60) + 1
        audit(email, "LOGIN_BLOCKED", "account locked")
        raise AccountLockedError(f"Account locked after repeated failed attempts. Try again in about {mins} minute(s).")
    if not verify_password(password, row["salt"], row["password_hash"]):
        attempts = row["failed_attempts"] + 1
        if attempts >= MAX_FAILED_ATTEMPTS:
            ex("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE email = ?",
               (ts(now() + timedelta(minutes=LOCK_MINUTES)), email))
            audit(email, "ACCOUNT_LOCKED", f"{MAX_FAILED_ATTEMPTS} failed attempts")
            raise AccountLockedError(f"Too many failed attempts. The account is locked for {LOCK_MINUTES} minutes.")
        ex("UPDATE users SET failed_attempts = ? WHERE email = ?", (attempts, email))
        audit(email, "LOGIN_FAILED", f"attempt {attempts}/{MAX_FAILED_ATTEMPTS}")
        raise ClinicError(f"Invalid email or password. Attempt {attempts} of {MAX_FAILED_ATTEMPTS}.")
    ex("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = ?", (email,))
    audit(email, "LOGIN", "success")
    return get_user(email)


def change_password(user, old_password, new_password):
    row = q("SELECT salt, password_hash FROM users WHERE email = ?", (user["email"],), one=True)
    if not verify_password(old_password, row["salt"], row["password_hash"]):
        raise ClinicError("Current password is incorrect.")
    problem = password_problem(new_password)
    if problem:
        raise ClinicError(problem)
    h, s = hash_password(new_password)
    ex("UPDATE users SET password_hash = ?, salt = ? WHERE email = ?", (h, s, user["email"]))
    audit(user["email"], "PASSWORD_CHANGED", "")


def update_contact(user, phone, city=None):
    ex("UPDATE users SET phone = ?, city = COALESCE(?, city) WHERE email = ?", (phone or None, city, user["email"]))
    audit(user["email"], "PROFILE_UPDATED", "contact details")


@requires("deactivate_user")
def deactivate_user(actor, email):
    if email == actor["email"]:
        raise ClinicError("You cannot deactivate your own account.")
    ex("UPDATE users SET is_active = 0 WHERE email = ?", (email,))
    audit(actor["email"], "USER_DEACTIVATED", email)


@requires("reactivate_user")
def reactivate_user(actor, email):
    ex("UPDATE users SET is_active = 1, failed_attempts = 0, locked_until = NULL WHERE email = ?", (email,))
    audit(actor["email"], "USER_REACTIVATED", email)


@requires("assign_role")
def assign_role(actor, email, role):
    if email == actor["email"]:
        raise ClinicError("You cannot change your own role.")
    ex("UPDATE users SET role = ? WHERE email = ?", (role, email))
    audit(actor["email"], "ROLE_CHANGED", f"{email} -> {role}")


@requires("reset_user_password")
def reset_user_password(actor, email):
    temp = "Tmp@" + secrets.token_hex(3) + "9A"
    h, s = hash_password(temp)
    ex("UPDATE users SET password_hash = ?, salt = ?, failed_attempts = 0, locked_until = NULL WHERE email = ?", (h, s, email))
    audit(actor["email"], "PASSWORD_RESET", email)
    return temp


@requires("view_all_users")
def list_users(actor):
    return q(f"SELECT {PUBLIC_FIELDS} FROM users ORDER BY role, full_name")


# ----------------------------------------------------------------------------
# Event bus
# ----------------------------------------------------------------------------
class EventBus:
    """Publish/subscribe hub: services announce events and others react without direct coupling."""

    def __init__(self):
        self._handlers = defaultdict(list)

    def subscribe(self, event, handler):
        self._handlers[event].append(handler)

    def publish(self, event, **payload):
        for handler in self._handlers[event]:
            try:
                handler(**payload)
            except Exception as exc:  # one failing subscriber must never block the others
                audit("system", "EVENT_HANDLER_ERROR", f"{event}: {exc}")


# ----------------------------------------------------------------------------
# Notifications: Email (Gmail), SMS (Twilio) and Push (ntfy)
# ----------------------------------------------------------------------------
def is_live() -> bool:
    return bool(st.session_state.get("live_mode", False))


def enabled_channels():
    return {"email": st.session_state.get("ch_email", True),
            "push": st.session_state.get("ch_push", True),
            "sms": st.session_state.get("ch_sms", False)}


def normalise_phone(phone: str):
    digits = re.sub(r"[^\d+]", "", phone or "")
    if not digits:
        return None
    if digits.startswith("+"):
        return digits
    if len(digits) == 10:
        return "+91" + digits
    return "+" + digits


class EmailChannel:
    name = "email"

    def send(self, user, subject, body):
        sender, pw = secret("GMAIL_USER"), secret("GMAIL_APP_PASSWORD")
        if not (sender and pw):
            return "failed", "Gmail credentials are not configured"
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = f"{CLINIC_NAME} <{sender}>", user["email"], subject
        msg.set_content(body)
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=12) as smtp:
            smtp.starttls()
            smtp.login(sender, pw)
            smtp.send_message(msg)
        return "sent", "delivered to Gmail SMTP"


class SMSChannel:
    name = "sms"

    def send(self, user, subject, body):
        sid, token, sender = secret("TWILIO_ACCOUNT_SID"), secret("TWILIO_AUTH_TOKEN"), secret("TWILIO_FROM_NUMBER")
        if not (sid and token and sender):
            return "failed", "Twilio credentials are not configured"
        to = normalise_phone(user.get("phone"))
        if not to:
            return "failed", "recipient has no phone number"
        r = requests.post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                          data={"To": to, "From": sender, "Body": f"{subject}: {body}"[:300]},
                          auth=(sid, token), timeout=12)
        return ("sent", "accepted by Twilio") if r.status_code in (200, 201) else ("failed", f"Twilio error {r.status_code}")


class PushChannel:
    name = "push"

    def send(self, user, subject, body):
        topic = secret("NTFY_TOPIC")
        if not topic:
            return "failed", "ntfy topic is not configured"
        title = re.sub(r"[^\x20-\x7E]", "", subject)[:80] or "Smart Clinic"
        r = requests.post(f"https://ntfy.sh/{topic}", data=f"To {user['full_name']}: {body}".encode("utf-8"),
                          headers={"Title": title}, timeout=12)
        return ("sent", "published to ntfy") if r.ok else ("failed", f"ntfy error {r.status_code}")


CHANNELS = {"email": EmailChannel(), "sms": SMSChannel(), "push": PushChannel()}


class NotificationService:
    """Writes every message to the in-app inbox and sends it on the selected channels."""

    def notify(self, email, notif_type, subject, body, channels=("email", "push")):
        user = get_user(email)
        if not user:
            return
        self._record(email, "in-app", notif_type, subject, body, "delivered", "shown in inbox")
        enabled = enabled_channels()
        for name in channels:
            if not enabled.get(name):
                continue
            if not is_live():
                self._record(email, name, notif_type, subject, body, "simulated", "simulated mode: not sent")
                continue
            try:
                status, detail = CHANNELS[name].send(user, subject, body)
            except Exception as exc:
                status, detail = "failed", str(exc)[:160]
            self._record(email, name, notif_type, subject, body, status, detail)

    @staticmethod
    def _record(email, channel, ntype, subject, body, status, detail):
        ex("""INSERT INTO notifications (user_email, channel, notif_type, subject, body, status, detail, created_at)
              VALUES (?,?,?,?,?,?,?,?)""", (email, channel, ntype, subject, body, status, detail, ts()))
        if channel == "in-app" and st.session_state.get("user", {}).get("email") == email:
            st.session_state.setdefault("toasts", []).append(subject)


notifier = NotificationService()


def fmt_dt(s: str) -> str:
    return datetime.fromisoformat(s).strftime("%a %d %b %Y, %I:%M %p")


def doctor_label(email: str) -> str:
    d = get_user(email)
    return f"Dr. {d['full_name'].replace('Dr. ', '')}" if d else email


# ----------------------------------------------------------------------------
# Scheduling
# ----------------------------------------------------------------------------
class SchedulingError(ClinicError):
    pass


def _t(s):
    return datetime.strptime(s, "%H:%M").time()


def generate_slots(doctor_email: str, day: date):
    """All slots a doctor's recurring shifts produce on a given day (before removing booked ones)."""
    slots = []
    for shift in q("SELECT * FROM doctor_availability WHERE doctor_email = ? AND day_of_week = ?",
                   (doctor_email, day.weekday())):
        cur = datetime.combine(day, _t(shift["start_time"]))
        end = datetime.combine(day, _t(shift["end_time"]))
        length = timedelta(minutes=shift["slot_minutes"])
        step = length + timedelta(minutes=shift["buffer_minutes"])
        while cur + length <= end:
            slots.append((cur, cur + length))
            cur += step
    return sorted(slots)


def overlaps(column: str, email: str, start: datetime, end: datetime, ignore_id=None) -> bool:
    """Two intervals overlap when each starts before the other ends."""
    sql = f"SELECT 1 FROM appointments WHERE {column} = ? AND status != 'cancelled' AND start_dt < ? AND end_dt > ?"
    params = [email, slot_str(end), slot_str(start)]
    if ignore_id:
        sql += " AND id != ?"
        params.append(ignore_id)
    return q(sql, params, one=True) is not None


def free_slots(doctor_email: str, day: date):
    current = now()
    return [(s, e) for s, e in generate_slots(doctor_email, day)
            if s > current and not overlaps("doctor_email", doctor_email, s, e)]


def next_free_slot(doctor_email: str, after: datetime = None, days: int = 21):
    after = after or now()
    for offset in range(days + 1):
        for s, e in free_slots(doctor_email, (after + timedelta(days=offset)).date()):
            if s > after:
                return s
    return None


def _insert_appointment(patient_email, doctor_email, start, end, visit_type="regular", recurrence_id=None):
    return ex("""INSERT INTO appointments (patient_email, doctor_email, start_dt, end_dt, status, visit_type,
                 recurrence_id, created_at) VALUES (?,?,?,?, 'scheduled', ?,?,?)""",
              (patient_email, doctor_email, slot_str(start), slot_str(end), visit_type, recurrence_id, ts()))


def _validate_booking(patient_email, doctor_email, start):
    patient, doctor = get_user(patient_email), get_user(doctor_email)
    if not patient or patient["role"] != "patient" or not patient["is_active"]:
        raise SchedulingError("Patient account not found or inactive.")
    if not doctor or doctor["role"] != "doctor" or not doctor["is_active"]:
        raise SchedulingError("Doctor not found or inactive.")
    match = [(s, e) for s, e in generate_slots(doctor_email, start.date()) if s == start]
    if not match:
        raise SchedulingError("That time is not one of the doctor's bookable slots.")
    if start <= now():
        raise SchedulingError("That slot is in the past.")
    end = match[0][1]
    if overlaps("doctor_email", doctor_email, start, end):
        nxt = next_free_slot(doctor_email, start)
        hint = f" Next free slot: {fmt_dt(slot_str(nxt))}." if nxt else ""
        raise SchedulingError("This slot is already booked." + hint)
    if overlaps("patient_email", patient_email, start, end):
        raise SchedulingError("The patient already has an appointment at this time.")
    return end


def book_appointment(actor, patient_email, doctor_email, start: datetime, visit_type="regular", recurrence_id=None):
    needed = "book_appointment" if actor["email"] == patient_email else "book_appointment_for_patient"
    if not can(actor, needed):
        audit(actor["email"], "PERMISSION_DENIED", needed)
        raise PermissionDeniedError(f"Your role ({actor['role']}) cannot book this appointment.")
    end = _validate_booking(patient_email, doctor_email, start)
    appt_id = _insert_appointment(patient_email, doctor_email, start, end, visit_type, recurrence_id)
    audit(actor["email"], "APPOINTMENT_BOOKED", f"#{appt_id} {patient_email} with {doctor_email} at {slot_str(start)}")
    bus().publish("appointment_booked", appointment_id=appt_id)
    return appt_id


def book_recurring(actor, patient_email, doctor_email, start: datetime, weeks: int):
    rid = uuid.uuid4().hex[:10]
    booked, skipped = [], []
    for k in range(weeks):
        when = start + timedelta(weeks=k)
        try:
            booked.append(book_appointment(actor, patient_email, doctor_email, when, recurrence_id=rid))
        except SchedulingError as exc:
            skipped.append((when, str(exc)))
    return rid, booked, skipped


def join_waitlist(actor, patient_email, doctor_email, day: date):
    if not (can(actor, "book_appointment") or can(actor, "book_appointment_for_patient")):
        raise PermissionDeniedError("Your role cannot join a waitlist.")
    if q("""SELECT 1 FROM waitlist WHERE patient_email=? AND doctor_email=? AND preferred_date=? AND fulfilled=0""",
         (patient_email, doctor_email, day.isoformat()), one=True):
        raise SchedulingError("You are already on this waitlist.")
    ex("INSERT INTO waitlist (patient_email, doctor_email, preferred_date, created_at) VALUES (?,?,?,?)",
       (patient_email, doctor_email, day.isoformat(), ts()))
    audit(actor["email"], "WAITLIST_JOINED", f"{patient_email} for {doctor_email} on {day}")


def get_appointment(appt_id):
    return q("SELECT * FROM appointments WHERE id = ?", (appt_id,), one=True)


def cancel_appointment(actor, appt_id):
    appt = get_appointment(appt_id)
    if not appt:
        raise SchedulingError("Appointment not found.")
    own = can(actor, "cancel_own_appointment") and appt["patient_email"] == actor["email"]
    if not (own or can(actor, "book_appointment_for_patient")):
        audit(actor["email"], "PERMISSION_DENIED", f"cancel appointment #{appt_id}")
        raise PermissionDeniedError("You may only cancel your own appointments.")
    if appt["status"] != "scheduled":
        raise SchedulingError(f"Only scheduled appointments can be cancelled (this one is {appt['status']}).")
    ex("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appt_id,))
    audit(actor["email"], "APPOINTMENT_CANCELLED", f"#{appt_id}")
    bus().publish("appointment_cancelled", appointment_id=appt_id)
    promote_from_waitlist(appt)


def promote_from_waitlist(freed):
    """Give a freed slot to the patient who has waited longest for that doctor and day."""
    day = freed["start_dt"][:10]
    start = datetime.fromisoformat(freed["start_dt"])
    for entry in q("""SELECT * FROM waitlist WHERE doctor_email = ? AND preferred_date = ? AND fulfilled = 0
                      ORDER BY created_at, id""", (freed["doctor_email"], day)):
        try:
            end = _validate_booking(entry["patient_email"], freed["doctor_email"], start)
        except SchedulingError:
            continue
        new_id = _insert_appointment(entry["patient_email"], freed["doctor_email"], start, end)
        ex("UPDATE waitlist SET fulfilled = 1 WHERE id = ?", (entry["id"],))
        audit("system", "WAITLIST_PROMOTED", f"{entry['patient_email']} -> appointment #{new_id}")
        bus().publish("appointment_booked", appointment_id=new_id)
        bus().publish("waitlist_promoted", appointment_id=new_id)
        return new_id
    return None


def set_appointment_status(actor, appt_id, status):
    if not can(actor, "update_appointment_status"):
        raise PermissionDeniedError("Only doctors can update appointment status.")
    appt = get_appointment(appt_id)
    if not appt or appt["doctor_email"] != actor["email"]:
        audit(actor["email"], "PERMISSION_DENIED", f"status change on appointment #{appt_id}")
        raise PermissionDeniedError("You can only update your own appointments.")
    if status not in ("completed", "no_show"):
        raise ClinicError("Invalid status.")
    ex("UPDATE appointments SET status = ? WHERE id = ?", (status, appt_id))
    audit(actor["email"], "APPOINTMENT_STATUS", f"#{appt_id} -> {status}")
    bus().publish("appointment_status_changed", appointment_id=appt_id, status=status)


def appointment_rows(where="", params=()):
    return q(f"""SELECT a.*, p.full_name AS patient_name, d.full_name AS doctor_name, d.specialization
                 FROM appointments a JOIN users p ON p.email = a.patient_email
                 JOIN users d ON d.email = a.doctor_email {where} ORDER BY a.start_dt""", params)


@requires("set_availability")
def set_availability(actor, days, start_time, end_time, slot_minutes, buffer_minutes):
    if _t(start_time) >= _t(end_time):
        raise ClinicError("Shift end must be after shift start.")
    if slot_minutes < 5:
        raise ClinicError("Slots must be at least 5 minutes long.")
    for d in days:
        ex("DELETE FROM doctor_availability WHERE doctor_email = ? AND day_of_week = ?", (actor["email"], d))
        ex("""INSERT INTO doctor_availability (doctor_email, day_of_week, start_time, end_time, slot_minutes, buffer_minutes)
              VALUES (?,?,?,?,?,?)""", (actor["email"], d, start_time, end_time, slot_minutes, buffer_minutes))
    audit(actor["email"], "AVAILABILITY_SET", f"days={days} {start_time}-{end_time}")


def clear_availability(actor, day):
    if not can(actor, "set_availability"):
        raise PermissionDeniedError("Only doctors can change availability.")
    ex("DELETE FROM doctor_availability WHERE doctor_email = ? AND day_of_week = ?", (actor["email"], day))


# ----------------------------------------------------------------------------
# Walk-in and emergency queue (priority queue kept in the database)
# ----------------------------------------------------------------------------
QUEUE_PRIORITY = {"emergency": 0, "walk_in": 1}
MINUTES_PER_PATIENT = 8


@requires("manage_queue")
def add_to_queue(actor, patient_email, doctor_email, kind):
    if kind not in QUEUE_PRIORITY:
        raise ClinicError("Unknown queue type.")
    if q("SELECT 1 FROM queue_entries WHERE patient_email=? AND doctor_email=? AND status='waiting'",
         (patient_email, doctor_email), one=True):
        raise ClinicError("This patient is already waiting for this doctor.")
    ex("INSERT INTO queue_entries (patient_email, doctor_email, kind, priority, arrived_at) VALUES (?,?,?,?,?)",
       (patient_email, doctor_email, kind, QUEUE_PRIORITY[kind], ts()))
    audit(actor["email"], "QUEUE_ADDED", f"{patient_email} ({kind}) for {doctor_email}")
    bus().publish("queue_changed", doctor_email=doctor_email)


def queue_for(doctor_email):
    return q("""SELECT e.*, u.full_name AS patient_name FROM queue_entries e JOIN users u ON u.email = e.patient_email
                WHERE e.doctor_email = ? AND e.status = 'waiting' ORDER BY e.priority, e.arrived_at, e.id""", (doctor_email,))


@requires("manage_queue")
def serve_next(actor, doctor_email):
    waiting = queue_for(doctor_email)
    if not waiting:
        raise ClinicError("The queue is empty.")
    ex("UPDATE queue_entries SET status = 'served' WHERE id = ?", (waiting[0]["id"],))
    audit(actor["email"], "QUEUE_SERVED", waiting[0]["patient_email"])
    bus().publish("queue_changed", doctor_email=doctor_email)
    return waiting[0]


@requires("report_delay")
def report_delay(actor, minutes):
    today = now().date().isoformat()
    rows = q("""SELECT DISTINCT patient_email FROM appointments WHERE doctor_email = ? AND status = 'scheduled'
                AND substr(start_dt,1,10) = ?""", (actor["email"], today))
    for r in rows:
        notifier.notify(r["patient_email"], "doctor_delay", "Doctor running late",
                        f"{doctor_label(actor['email'])} is running about {minutes} minutes late today. We apologise for the wait.",
                        channels=("push", "sms"))
    audit(actor["email"], "DELAY_BROADCAST", f"{minutes} min to {len(rows)} patient(s)")
    return len(rows)


@requires("send_reminders")
def send_reminders(actor, hours=24):
    horizon = slot_str(now() + timedelta(hours=hours))
    due = q("""SELECT * FROM appointments WHERE status = 'scheduled' AND reminder_sent = 0
               AND start_dt > ? AND start_dt <= ?""", (slot_str(now()), horizon))
    for a in due:
        notifier.notify(a["patient_email"], "reminder", "Appointment reminder",
                        f"Reminder: appointment with {doctor_label(a['doctor_email'])} on {fmt_dt(a['start_dt'])}.",
                        channels=("email", "push", "sms"))
        ex("UPDATE appointments SET reminder_sent = 1 WHERE id = ?", (a["id"],))
    audit(actor["email"], "REMINDERS_SENT", f"{len(due)} reminder(s)")
    return len(due)


# ----------------------------------------------------------------------------
# PDF documents
# ----------------------------------------------------------------------------
def build_pdf(path, title, blocks, subtitle=None):
    """blocks: list of ('p', text) paragraphs or ('t', header_row, rows) tables."""
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm, title=title)
    story = [Paragraph(f"<b>{CLINIC_NAME}</b>", styles["Title"]), Paragraph(title, styles["Heading2"])]
    if subtitle:
        story.append(Paragraph(subtitle, styles["Normal"]))
    story.append(Spacer(1, 6 * mm))
    for block in blocks:
        if block[0] == "p":
            story += [Paragraph(block[1], styles["Normal"]), Spacer(1, 3 * mm)]
        else:
            tbl = Table([block[1]] + block[2], hAlign="LEFT")
            tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDE3EE")),
                                     ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                     ("FONTSIZE", (0, 0), (-1, -1), 9), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story += [tbl, Spacer(1, 4 * mm)]
    doc.build(story)
    return path


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def esc(text):
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ----------------------------------------------------------------------------
# Medical records: relationship-based access, consent gate, encryption, access log
# ----------------------------------------------------------------------------
def has_relationship(doctor_email, patient_email) -> bool:
    return q("""SELECT 1 FROM appointments WHERE doctor_email = ? AND patient_email = ? AND status != 'cancelled'""",
             (doctor_email, patient_email), one=True) is not None


def has_consent(patient_email) -> bool:
    row = q("SELECT consent_given FROM patient_profile WHERE patient_email = ?", (patient_email,), one=True)
    return bool(row and row["consent_given"])


def log_access(accessor, patient, action, status, reason=""):
    ex("INSERT INTO access_log (accessor_email, patient_email, action, status, reason, created_at) VALUES (?,?,?,?,?,?)",
       (accessor, patient, action, status, reason, ts()))


def check_access(actor, patient_email, action):
    """Three-tier rule: role, then relationship; every attempt is logged."""
    role = actor["role"]
    if role == "patient":
        allowed, reason = actor["email"] == patient_email, "patients may only open their own record"
    elif role == "doctor":
        allowed, reason = has_relationship(actor["email"], patient_email), "no appointment between this doctor and the patient"
    else:
        allowed, reason = False, f"the {role} role has no access to clinical records"
    if not allowed:
        log_access(actor["email"], patient_email, action, "denied", reason)
        audit(actor["email"], "PERMISSION_DENIED", f"{action} on {patient_email}: {reason}")
        raise PermissionDeniedError(f"Access denied: {reason}.")
    log_access(actor["email"], patient_email, action, "granted")


def require_consent(patient_email):
    if not has_consent(patient_email):
        raise ClinicError("The patient has not given consent, so this record cannot be written to.")


def save_profile(actor, blood_group, allergies, conditions, consent):
    if not can(actor, "update_own_profile"):
        raise PermissionDeniedError("Only patients can edit their own profile.")
    ex("""INSERT INTO patient_profile (patient_email, blood_group, allergies_enc, conditions_enc, consent_given, updated_at)
          VALUES (?,?,?,?,?,?) ON CONFLICT(patient_email) DO UPDATE SET blood_group=excluded.blood_group,
          allergies_enc=excluded.allergies_enc, conditions_enc=excluded.conditions_enc,
          consent_given=excluded.consent_given, updated_at=excluded.updated_at""",
       (actor["email"], blood_group, encrypt(allergies), encrypt(conditions), int(bool(consent)), ts()))
    audit(actor["email"], "PROFILE_SAVED", f"consent={bool(consent)}")


def set_consent(actor, consent: bool):
    if not can(actor, "manage_consent"):
        raise PermissionDeniedError("Only patients can change their own consent.")
    ex("""INSERT INTO patient_profile (patient_email, consent_given, updated_at) VALUES (?,?,?)
          ON CONFLICT(patient_email) DO UPDATE SET consent_given=excluded.consent_given, updated_at=excluded.updated_at""",
       (actor["email"], int(consent), ts()))
    audit(actor["email"], "CONSENT_GRANTED" if consent else "CONSENT_WITHDRAWN", "")


def get_profile(actor, patient_email):
    check_access(actor, patient_email, "view_profile")
    row = q("SELECT * FROM patient_profile WHERE patient_email = ?", (patient_email,), one=True)
    if not row:
        return {"blood_group": "", "allergies": "", "conditions": "", "consent_given": False}
    return {"blood_group": row["blood_group"] or "", "allergies": decrypt(row["allergies_enc"]),
            "conditions": decrypt(row["conditions_enc"]), "consent_given": bool(row["consent_given"])}


def add_diagnosis(actor, patient_email, diagnosis, notes=""):
    if not can(actor, "view_assigned_patient_records"):
        raise PermissionDeniedError("Only doctors can add diagnoses.")
    check_access(actor, patient_email, "add_diagnosis")
    require_consent(patient_email)
    if not diagnosis.strip():
        raise ClinicError("Diagnosis cannot be empty.")
    ex("""INSERT INTO medical_history (patient_email, doctor_email, diagnosis_enc, notes_enc, created_at)
          VALUES (?,?,?,?,?)""", (patient_email, actor["email"], encrypt(diagnosis), encrypt(notes), ts()))
    bus().publish("record_updated", patient_email=patient_email, doctor_email=actor["email"], what="a new diagnosis")


def get_history(actor, patient_email):
    check_access(actor, patient_email, "view_history")
    rows = q("SELECT * FROM medical_history WHERE patient_email = ? ORDER BY created_at DESC", (patient_email,))
    return [{"date": r["created_at"], "doctor": doctor_label(r["doctor_email"]),
             "diagnosis": decrypt(r["diagnosis_enc"]) or "[erased]", "notes": decrypt(r["notes_enc"])} for r in rows]


def add_prescription(actor, patient_email, medications, notes=""):
    if not can(actor, "add_prescription"):
        raise PermissionDeniedError("Only doctors can issue prescriptions.")
    check_access(actor, patient_email, "add_prescription")
    require_consent(patient_email)
    meds = [m for m in medications if m.get("name", "").strip()]
    if not meds:
        raise ClinicError("Add at least one medication.")
    pid = ex("INSERT INTO prescriptions (patient_email, doctor_email, medications, notes, created_at) VALUES (?,?,?,?,?)",
             (patient_email, actor["email"], json.dumps(meds), notes, ts()))
    patient = get_user(patient_email)
    path = build_pdf(os.path.join(PDF_DIR, f"prescription_{pid}.pdf"), f"Prescription #{pid}",
                     [("p", f"<b>Patient:</b> {esc(patient['full_name'])} ({esc(patient_email)})"),
                      ("p", f"<b>Doctor:</b> {esc(doctor_label(actor['email']))}, {esc(actor.get('specialization') or '')}"),
                      ("t", ["Medicine", "Dose", "Frequency", "Days"],
                       [[esc(m["name"]), esc(m.get("dose", "")), esc(m.get("frequency", "")), str(m.get("days", ""))] for m in meds]),
                      ("p", f"<b>Notes:</b> {esc(notes) or '-'}")], subtitle=f"Issued {fmt_dt(ts())}")
    ex("UPDATE prescriptions SET pdf_path = ? WHERE id = ?", (path, pid))
    bus().publish("record_updated", patient_email=patient_email, doctor_email=actor["email"], what="a new prescription")
    return pid


def get_prescriptions(actor, patient_email):
    check_access(actor, patient_email, "view_prescriptions")
    out = []
    for r in q("SELECT * FROM prescriptions WHERE patient_email = ? ORDER BY created_at DESC", (patient_email,)):
        r["meds"] = json.loads(r["medications"])
        r["doctor"] = doctor_label(r["doctor_email"])
        out.append(r)
    return out


def upload_document(actor, patient_email, filename, data: bytes, description=""):
    check_access(actor, patient_email, "upload_document")
    if actor["role"] == "doctor":
        require_consent(patient_email)
    if len(data) > 5 * 1024 * 1024:
        raise ClinicError("Files must be smaller than 5 MB.")
    safe = re.sub(r"[^\w.\-]", "_", filename)
    folder = os.path.join(UPLOAD_DIR, hashlib.sha256(patient_email.encode()).hexdigest()[:12])
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{uuid.uuid4().hex[:8]}_{safe}")
    with open(path, "wb") as f:
        f.write(data)
    ex("""INSERT INTO lab_documents (patient_email, uploaded_by, filename, description, file_path, created_at)
          VALUES (?,?,?,?,?,?)""", (patient_email, actor["email"], safe, description, path, ts()))
    if actor["email"] != patient_email:
        bus().publish("record_updated", patient_email=patient_email, doctor_email=actor["email"], what=f"a document ({safe})")


def get_documents(actor, patient_email):
    check_access(actor, patient_email, "view_documents")
    return q("SELECT * FROM lab_documents WHERE patient_email = ? ORDER BY created_at DESC", (patient_email,))


def patients_of(doctor_email):
    return q("""SELECT DISTINCT u.email, u.full_name FROM appointments a JOIN users u ON u.email = a.patient_email
                WHERE a.doctor_email = ? AND a.status != 'cancelled' ORDER BY u.full_name""", (doctor_email,))


# ----------------------------------------------------------------------------
# Billing and payments
# ----------------------------------------------------------------------------
SANDBOX_SECRET = secret("SANDBOX_SECRET", "sandbox-signing-secret")


def sign(order_id, payment_id, key=None):
    return hmac.new((key or SANDBOX_SECRET).encode(), f"{order_id}|{payment_id}".encode(), hashlib.sha256).hexdigest()


def verify_signature(order_id, payment_id, signature, key=None) -> bool:
    return hmac.compare_digest(sign(order_id, payment_id, key), signature or "")


def razorpay_ready() -> bool:
    return bool(is_live() and secret("RAZORPAY_KEY_ID") and secret("RAZORPAY_KEY_SECRET"))


def razorpay_auth():
    return (secret("RAZORPAY_KEY_ID"), secret("RAZORPAY_KEY_SECRET"))


def get_invoice(invoice_id):
    return q("SELECT * FROM invoices WHERE id = ?", (invoice_id,), one=True)


def create_invoice(appointment_id):
    appt = get_appointment(appointment_id)
    doctor = get_user(appt["doctor_email"])
    fee = float(doctor.get("consultation_fee") or 0)
    if fee <= 0 or q("SELECT 1 FROM invoices WHERE appointment_id = ?", (appointment_id,), one=True):
        return None
    tax = round(fee * GST_RATE, 2)
    return ex("""INSERT INTO invoices (appointment_id, patient_email, subtotal, tax, total_amount, created_at)
                 VALUES (?,?,?,?,?,?)""", (appointment_id, appt["patient_email"], fee, tax, round(fee + tax, 2), ts()))


def invoice_rows(where="", params=()):
    return q(f"""SELECT i.*, a.start_dt, a.doctor_email, d.full_name AS doctor_name, p.full_name AS patient_name
                 FROM invoices i JOIN appointments a ON a.id = i.appointment_id
                 JOIN users d ON d.email = a.doctor_email JOIN users p ON p.email = i.patient_email
                 {where} ORDER BY i.id DESC""", params)


def start_payment(actor, invoice_id):
    inv = get_invoice(invoice_id)
    if not inv or inv["status"] != "pending":
        raise ClinicError("This invoice is not awaiting payment.")
    if not (inv["patient_email"] == actor["email"] and can(actor, "make_payment")) and not can(actor, "collect_payment"):
        raise PermissionDeniedError("You cannot pay this invoice.")
    if razorpay_ready():
        patient = get_user(inv["patient_email"])
        body = {"amount": int(round(inv["total_amount"] * 100)), "currency": "INR", "accept_partial": False,
                "reference_id": f"inv{invoice_id}-{uuid.uuid4().hex[:6]}",
                "description": f"Consultation invoice #{invoice_id}",
                "customer": {"name": patient["full_name"], "email": patient["email"],
                             **({"contact": normalise_phone(patient["phone"])} if patient.get("phone") else {})},
                "notify": {"sms": False, "email": False}}
        r = requests.post("https://api.razorpay.com/v1/payment_links", json=body, auth=razorpay_auth(), timeout=15)
        if r.status_code not in (200, 201):
            raise ClinicError(f"Razorpay could not create the payment link (error {r.status_code}).")
        link = r.json()
        ex("INSERT INTO payment_orders (invoice_id, provider, order_id, link_url, created_at) VALUES (?,?,?,?,?)",
           (invoice_id, "razorpay", link["id"], link["short_url"], ts()))
        return {"mode": "razorpay", "url": link["short_url"], "order_id": link["id"]}
    order_id = "order_" + uuid.uuid4().hex[:12]
    ex("INSERT INTO payment_orders (invoice_id, provider, order_id, created_at) VALUES (?,?,?,?)",
       (invoice_id, "sandbox", order_id, ts()))
    return {"mode": "sandbox", "order_id": order_id}


def complete_sandbox_payment(invoice_id, order_id):
    """The sandbox gateway confirms with a signed payload; the signature is verified before payment is accepted."""
    payment_id = "pay_" + uuid.uuid4().hex[:12]
    signature = sign(order_id, payment_id)
    if not verify_signature(order_id, payment_id, signature):
        raise ClinicError("Payment signature mismatch. Payment rejected.")
    mark_paid(invoice_id, payment_id, "sandbox", signature)


def check_razorpay_payment(invoice_id):
    order = q("SELECT * FROM payment_orders WHERE invoice_id = ? AND provider = 'razorpay' ORDER BY id DESC",
              (invoice_id,), one=True)
    if not order:
        raise ClinicError("No payment link has been created for this invoice.")
    r = requests.get(f"https://api.razorpay.com/v1/payment_links/{order['order_id']}", auth=razorpay_auth(), timeout=15)
    if r.status_code != 200:
        raise ClinicError(f"Could not check the payment (error {r.status_code}).")
    data = r.json()
    if data.get("status") == "paid":
        pays = data.get("payments") or [{}]
        mark_paid(invoice_id, pays[0].get("payment_id", "rzp_" + order["order_id"]), "razorpay", None)
        return True
    return False


def mark_paid(invoice_id, payment_id, provider, signature):
    inv = get_invoice(invoice_id)
    if inv["status"] == "paid":
        return
    ex("UPDATE invoices SET status='paid', payment_id=?, paid_at=? WHERE id=?", (payment_id, ts(), invoice_id))
    ex("UPDATE payment_orders SET status='paid', signature=? WHERE invoice_id=? AND provider=?", (signature, invoice_id, provider))
    receipt = receipt_pdf(invoice_id)
    ex("UPDATE invoices SET receipt_path = ? WHERE id = ?", (receipt, invoice_id))
    audit(inv["patient_email"], "PAYMENT_RECEIVED", f"invoice #{invoice_id} via {provider}")
    bus().publish("payment_received", invoice_id=invoice_id)


def receipt_pdf(invoice_id):
    inv = invoice_rows("WHERE i.id = ?", (invoice_id,))[0]
    return build_pdf(os.path.join(PDF_DIR, f"receipt_{invoice_id}.pdf"), f"Payment Receipt #{invoice_id}",
                     [("p", f"<b>Patient:</b> {esc(inv['patient_name'])}"),
                      ("p", f"<b>Appointment:</b> {esc(inv['doctor_name'])} on {fmt_dt(inv['start_dt'])}"),
                      ("t", ["Description", "Amount (INR)"],
                       [["Consultation fee", f"{inv['subtotal']:.2f}"], [f"GST @ {int(GST_RATE * 100)}%", f"{inv['tax']:.2f}"],
                        ["Total paid", f"{inv['total_amount']:.2f}"]]),
                      ("p", f"<b>Payment reference:</b> {esc(inv['payment_id'])}")], subtitle=f"Paid {fmt_dt(inv['paid_at'])}")


def _do_refund(invoice_id, reason):
    inv = get_invoice(invoice_id)
    if inv["status"] != "paid":
        raise ClinicError("Only paid invoices can be refunded.")
    note = ""
    if razorpay_ready() and inv["payment_id"] and inv["payment_id"].startswith("pay_") and \
            q("SELECT 1 FROM payment_orders WHERE invoice_id=? AND provider='razorpay'", (invoice_id,), one=True):
        r = requests.post(f"https://api.razorpay.com/v1/payments/{inv['payment_id']}/refund",
                          json={"amount": int(round(inv["total_amount"] * 100))}, auth=razorpay_auth(), timeout=15)
        note = " (refund submitted to Razorpay)" if r.status_code in (200, 201) else f" (Razorpay refund error {r.status_code})"
    ex("UPDATE invoices SET status = 'refunded' WHERE id = ?", (invoice_id,))
    audit("system", "REFUND", f"invoice #{invoice_id}: {reason}{note}")
    bus().publish("refund_issued", invoice_id=invoice_id)


@requires("issue_refund")
def refund_invoice(actor, invoice_id):
    _do_refund(invoice_id, f"manual refund by {actor['email']}")


@requires("collect_payment")
def collect_at_counter(actor, invoice_id):
    inv = get_invoice(invoice_id)
    if not inv or inv["status"] != "pending":
        raise ClinicError("This invoice is not awaiting payment.")
    mark_paid(invoice_id, "counter_" + uuid.uuid4().hex[:8], "counter", None)


def submit_claim(actor, invoice_id, insurer, policy_number):
    inv = get_invoice(invoice_id)
    if not inv or inv["patient_email"] != actor["email"]:
        raise PermissionDeniedError("You can only claim against your own invoices.")
    if inv["status"] != "paid":
        raise ClinicError("Insurance claims can only be made for paid invoices.")
    if q("SELECT 1 FROM insurance_claims WHERE invoice_id = ?", (invoice_id,), one=True):
        raise ClinicError("A claim already exists for this invoice.")
    # The insurer is simulated: a valid policy number is approved up to a fixed coverage limit.
    approved = min(inv["total_amount"], 500.0) if policy_number.strip() else 0.0
    status = "approved" if approved > 0 else "rejected"
    ex("""INSERT INTO insurance_claims (invoice_id, patient_email, insurer, policy_number, claimed_amount,
          approved_amount, status, created_at) VALUES (?,?,?,?,?,?,?,?)""",
       (invoice_id, actor["email"], insurer, policy_number, inv["total_amount"], approved, status, ts()))
    audit(actor["email"], "CLAIM_SUBMITTED", f"invoice #{invoice_id}: {status}")
    return status, approved


# ----------------------------------------------------------------------------
# Doctor search, ratings and symptom-based suggestion
# ----------------------------------------------------------------------------
SYMPTOM_MAP = {
    "Cardiology": ["chest pain", "palpitation", "heart", "breathless", "blood pressure", "hypertension"],
    "Dermatology": ["skin", "rash", "itch", "acne", "eczema", "hair fall", "allergy on skin"],
    "Orthopedics": ["bone", "joint", "fracture", "back pain", "knee", "shoulder", "sprain"],
    "Pediatrics": ["child", "baby", "infant", "vaccination", "toddler"],
    "ENT": ["ear", "throat", "nose", "sinus", "tonsil", "hearing"],
    "Neurology": ["headache", "migraine", "seizure", "numbness", "dizziness"],
    "Gynecology": ["pregnan", "period", "menstrual", "pcos"],
}


def suggest_specialization(text):
    text = (text or "").lower()
    scores = {spec: sum(1 for kw in kws if kw in text) for spec, kws in SYMPTOM_MAP.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "General Medicine"


def search_doctors(specialization=None, city=None, min_rating=0, max_fee=None, on_date=None, sort="rating"):
    sql = """SELECT u.email, u.full_name, u.specialization, u.city, u.consultation_fee,
             COALESCE(AVG(r.rating), 0) AS avg_rating, COUNT(r.id) AS rating_count
             FROM users u LEFT JOIN doctor_ratings r ON r.doctor_email = u.email
             WHERE u.role = 'doctor' AND u.is_active = 1"""
    params = []
    if specialization and specialization != "Any":
        sql += " AND u.specialization = ?"
        params.append(specialization)
    if city and city.strip():
        sql += " AND LOWER(u.city) LIKE ?"
        params.append(f"%{city.strip().lower()}%")
    if max_fee:
        sql += " AND u.consultation_fee <= ?"
        params.append(max_fee)
    sql += " GROUP BY u.email"
    rows = q(sql, params)
    rows = [r for r in rows if r["avg_rating"] >= (min_rating or 0)]
    for r in rows:
        r["avg_rating"] = round(r["avg_rating"], 1)
        if on_date:
            r["slots"] = len(free_slots(r["email"], on_date))
    if on_date:
        rows = [r for r in rows if r["slots"] > 0]
    rows.sort(key=(lambda r: -r["avg_rating"]) if sort == "rating" else (lambda r: r["consultation_fee"]))
    return rows


def rate_doctor(actor, appointment_id, rating, comment=""):
    if not can(actor, "rate_doctor"):
        raise PermissionDeniedError("Only patients can rate doctors.")
    appt = get_appointment(appointment_id)
    if not appt or appt["patient_email"] != actor["email"]:
        raise PermissionDeniedError("You can only rate your own visits.")
    if appt["status"] != "completed":
        raise ClinicError("You can rate a doctor only after a completed appointment.")
    if not 1 <= int(rating) <= 5:
        raise ClinicError("Rating must be between 1 and 5.")
    try:
        ex("""INSERT INTO doctor_ratings (appointment_id, doctor_email, patient_email, rating, comment, created_at)
              VALUES (?,?,?,?,?,?)""", (appointment_id, appt["doctor_email"], actor["email"], int(rating), comment, ts()))
    except sqlite3.IntegrityError:
        raise ClinicError("You have already rated this appointment.")


# ----------------------------------------------------------------------------
# Analytics
# ----------------------------------------------------------------------------
@requires("view_system_analytics")
def analytics_snapshot(actor, start: date, end: date):
    s, e = start.isoformat(), (end + timedelta(days=1)).isoformat()
    appts = pd.DataFrame(q("""SELECT a.*, d.full_name AS doctor_name, d.specialization FROM appointments a
                              JOIN users d ON d.email = a.doctor_email WHERE a.start_dt >= ? AND a.start_dt < ?""", (s, e)))
    inv = pd.DataFrame(q("""SELECT i.*, d.specialization FROM invoices i JOIN appointments a ON a.id = i.appointment_id
                            JOIN users d ON d.email = a.doctor_email
                            WHERE i.status = 'paid' AND substr(i.paid_at,1,10) >= ? AND substr(i.paid_at,1,10) <= ?""",
                         (start.isoformat(), end.isoformat())))
    out = {"appointments": appts, "invoices": inv}
    if appts.empty:
        return out
    live = appts[appts["status"] != "cancelled"].copy()
    live["hour"] = pd.to_datetime(live["start_dt"]).dt.hour
    out["peak"] = live.groupby("hour").size().rename("appointments")
    rows = []
    for doc, g in appts.groupby("doctor_name"):
        done, missed = (g["status"] == "completed").sum(), (g["status"] == "no_show").sum()
        email = g["doctor_email"].iloc[0]
        capacity = sum(len(generate_slots(email, start + timedelta(days=k))) for k in range((end - start).days + 1))
        booked = (g["status"] != "cancelled").sum()
        rows.append({"Doctor": doc, "Booked": int(booked), "Capacity": capacity,
                     "Utilization %": round(100 * booked / capacity, 1) if capacity else 0.0,
                     "No-show rate %": round(100 * missed / (done + missed), 1) if (done + missed) else 0.0})
    out["doctors"] = pd.DataFrame(rows)
    return out


# ----------------------------------------------------------------------------
# Compliance: erasure, retention and self-audit report
# ----------------------------------------------------------------------------
@requires("process_erasure")
def erase_patient_data(actor, patient_email):
    ex("""UPDATE patient_profile SET blood_group=NULL, allergies_enc=NULL, conditions_enc=NULL, consent_given=0,
          updated_at=? WHERE patient_email=?""", (ts(), patient_email))
    ex("UPDATE medical_history SET diagnosis_enc=NULL, notes_enc=NULL WHERE patient_email=?", (patient_email,))
    audit(actor["email"], "DATA_ERASED", patient_email)
    log_access(actor["email"], patient_email, "erasure", "granted", "right to erasure")


@requires("run_retention")
def purge_old_access_logs(actor, days):
    cutoff = ts(now() - timedelta(days=days))
    con = connect()
    try:
        n = con.execute("DELETE FROM access_log WHERE created_at < ?", (cutoff,)).rowcount
        con.commit()
    finally:
        con.close()
    audit(actor["email"], "RETENTION_PURGE", f"{n} log entries older than {days} days")
    return n


def compliance_stats():
    total = q("SELECT COUNT(*) n FROM access_log", one=True)["n"]
    denied = q("SELECT COUNT(*) n FROM access_log WHERE status='denied'", one=True)["n"]
    profiles = q("SELECT COUNT(*) n FROM patient_profile", one=True)["n"]
    encrypted = q("""SELECT COUNT(*) n FROM patient_profile WHERE allergies_enc IS NOT NULL OR conditions_enc IS NOT NULL""", one=True)["n"]
    consented = q("SELECT COUNT(*) n FROM patient_profile WHERE consent_given = 1", one=True)["n"]
    pct = lambda a, b: round(100 * a / b, 1) if b else 0.0
    return {"Total access events": total, "Denied access events": denied, "Denied-access rate %": pct(denied, total),
            "Patient profiles": profiles, "Profiles with encrypted fields": encrypted,
            "Encrypted-field coverage %": pct(encrypted, profiles), "Profiles with consent": consented,
            "Consent coverage %": pct(consented, profiles)}


@requires("generate_compliance_report")
def compliance_report_pdf(actor):
    stats = compliance_stats()
    audit(actor["email"], "COMPLIANCE_REPORT", "generated")
    return build_pdf(os.path.join(PDF_DIR, "compliance_report.pdf"), "Privacy and Security Self-Audit",
                     [("p", f"Generated by {esc(actor['full_name'])} on {fmt_dt(ts())}."),
                      ("t", ["Statistic", "Value"], [[k, str(v)] for k, v in stats.items()]),
                      ("t", ["Principle", "How it is implemented"],
                       [["Consent", "Doctors cannot write to a record unless the patient has given consent."],
                        ["Access control", "Role check, then doctor-patient relationship check, on every record access."],
                        ["Encryption", "Sensitive profile and diagnosis fields are stored as Fernet (AES) ciphertext."],
                        ["Audit trail", "Account events and every granted or denied record access are logged."],
                        ["Right to erasure", "Administrators can wipe identifiable fields while keeping anonymous aggregates."],
                        ["Retention", "Access-log entries older than a chosen period can be purged."]])])


# ----------------------------------------------------------------------------
# Event handlers: notifications and billing react to scheduling and record events
# ----------------------------------------------------------------------------
def _on_booked(appointment_id):
    a = get_appointment(appointment_id)
    invoice_id = create_invoice(appointment_id)
    fee = f" Invoice total: Rs.{get_invoice(invoice_id)['total_amount']:.2f}." if invoice_id else ""
    notifier.notify(a["patient_email"], "booking_confirmed", "Appointment confirmed",
                    f"Your appointment with {doctor_label(a['doctor_email'])} is confirmed for {fmt_dt(a['start_dt'])}.{fee}",
                    channels=("email", "push"))
    notifier.notify(a["doctor_email"], "new_booking", "New appointment booked",
                    f"{get_user(a['patient_email'])['full_name']} booked {fmt_dt(a['start_dt'])}.", channels=())


def _on_cancelled(appointment_id):
    a = get_appointment(appointment_id)
    inv = q("SELECT * FROM invoices WHERE appointment_id = ?", (appointment_id,), one=True)
    note = ""
    if inv and inv["status"] == "paid":
        _do_refund(inv["id"], f"appointment #{appointment_id} cancelled")
        note = " Your payment will be refunded automatically."
    elif inv and inv["status"] == "pending":
        ex("UPDATE invoices SET status = 'cancelled' WHERE id = ?", (inv["id"],))
    notifier.notify(a["patient_email"], "appointment_cancelled", "Appointment cancelled",
                    f"Your appointment on {fmt_dt(a['start_dt'])} has been cancelled.{note}", channels=("email", "push"))
    notifier.notify(a["doctor_email"], "appointment_cancelled", "Appointment cancelled",
                    f"The appointment on {fmt_dt(a['start_dt'])} was cancelled.", channels=())


def _on_promoted(appointment_id):
    a = get_appointment(appointment_id)
    notifier.notify(a["patient_email"], "waitlist_promoted", "A slot opened up for you",
                    f"Good news: you have been booked with {doctor_label(a['doctor_email'])} on {fmt_dt(a['start_dt'])}.",
                    channels=("email", "push", "sms"))


def _on_status(appointment_id, status):
    a = get_appointment(appointment_id)
    if status == "completed":
        notifier.notify(a["patient_email"], "visit_completed", "How was your visit?",
                        f"Your visit with {doctor_label(a['doctor_email'])} is complete. You can now rate your doctor.", channels=())


def _on_queue(doctor_email):
    for i, entry in enumerate(queue_for(doctor_email), start=1):
        wait = (i - 1) * MINUTES_PER_PATIENT
        notifier.notify(entry["patient_email"], "queue_update", "Queue update",
                        f"You are number {i} in line for {doctor_label(doctor_email)}. Estimated wait: about {wait} minutes.",
                        channels=("push",))


def _on_payment(invoice_id):
    inv = get_invoice(invoice_id)
    notifier.notify(inv["patient_email"], "payment_received", "Payment received",
                    f"We received Rs.{inv['total_amount']:.2f} for invoice #{invoice_id}. Your receipt is in the Billing page.",
                    channels=("email", "push"))


def _on_refund(invoice_id):
    inv = get_invoice(invoice_id)
    notifier.notify(inv["patient_email"], "refund_issued", "Refund issued",
                    f"A refund of Rs.{inv['total_amount']:.2f} was issued for invoice #{invoice_id}.", channels=("email", "push"))


def _on_record(patient_email, doctor_email, what):
    notifier.notify(patient_email, "record_updated", "Your health record was updated",
                    f"{doctor_label(doctor_email)} added {what} to your record.", channels=("email", "push"))


@st.cache_resource
def bus():
    hub = EventBus()
    hub.subscribe("appointment_booked", _on_booked)
    hub.subscribe("appointment_cancelled", _on_cancelled)
    hub.subscribe("waitlist_promoted", _on_promoted)
    hub.subscribe("appointment_status_changed", _on_status)
    hub.subscribe("queue_changed", _on_queue)
    hub.subscribe("payment_received", _on_payment)
    hub.subscribe("refund_issued", _on_refund)
    hub.subscribe("record_updated", _on_record)
    return hub


# ----------------------------------------------------------------------------
# Demo data
# ----------------------------------------------------------------------------
DEMO_PASSWORD = "Demo@1234"
DEMO_ACCOUNTS = [
    ("Admin User", "admin@clinic.demo", "admin", {}),
    ("Riya Mehta", "reception@clinic.demo", "receptionist", {}),
    ("Priya Sharma", "priya.sharma@clinic.demo", "doctor",
     {"specialization": "Cardiology", "city": "Ghaziabad", "fee": 800, "license_number": "MC-1001"}),
    ("Aman Gupta", "aman.gupta@clinic.demo", "doctor",
     {"specialization": "Dermatology", "city": "Delhi", "fee": 600, "license_number": "MC-1002"}),
    ("Neha Verma", "neha.verma@clinic.demo", "patient", {"city": "Ghaziabad", "age": 29}),
    ("Rahul Singh", "rahul.singh@clinic.demo", "patient", {"city": "Noida", "age": 41}),
]


@st.cache_resource
def ensure_demo_data():
    init_database()
    if q("SELECT 1 FROM users LIMIT 1", one=True):
        return False
    for name, email, role, extra in DEMO_ACCOUNTS:
        create_account(name, email, DEMO_PASSWORD, role, phone=None, **extra)
        if role == "doctor":
            for day in range(5):
                ex("""INSERT INTO doctor_availability (doctor_email, day_of_week, start_time, end_time, slot_minutes, buffer_minutes)
                      VALUES (?,?,?,?,20,5)""", (email, day, "10:00", "13:00"))
    return True


@requires("view_system_analytics")
def load_sample_history(actor):
    """Adds two weeks of synthetic visits and payments so the analytics dashboard has something to show."""
    if q("SELECT 1 FROM users WHERE email = 'sample01@sample.demo'", one=True):
        raise ClinicError("Sample data has already been loaded.")
    rng = random.Random(42)
    patients = []
    for i in range(1, 13):
        email = f"sample{i:02d}@sample.demo"
        create_account(f"Sample Patient {i}", email, "Sample@1234", "patient", city="Ghaziabad")
        patients.append(email)
    doctors = q("SELECT email, consultation_fee FROM users WHERE role = 'doctor'")
    created = 0
    for back in range(14, 0, -1):
        day = now().date() - timedelta(days=back)
        for doc in doctors:
            slots = generate_slots(doc["email"], day)
            if not slots:
                continue
            for start, end in rng.sample(slots, min(len(slots), rng.randint(3, 7))):
                status = rng.choices(["completed", "no_show", "cancelled"], [70, 12, 18])[0]
                patient = rng.choice(patients)
                aid = ex("""INSERT INTO appointments (patient_email, doctor_email, start_dt, end_dt, status, created_at)
                            VALUES (?,?,?,?,?,?)""", (patient, doc["email"], slot_str(start), slot_str(end), status, ts(start)))
                created += 1
                fee = float(doc["consultation_fee"] or 0)
                if status == "completed" and fee > 0:
                    tax = round(fee * GST_RATE, 2)
                    ex("""INSERT INTO invoices (appointment_id, patient_email, subtotal, tax, total_amount, status, payment_id,
                          created_at, paid_at) VALUES (?,?,?,?,?,'paid',?,?,?)""",
                       (aid, patient, fee, tax, round(fee + tax, 2), "pay_sample" + uuid.uuid4().hex[:6], ts(start), ts(end)))
    audit(actor["email"], "SAMPLE_DATA_LOADED", f"{created} appointments")
    return created


# ----------------------------------------------------------------------------
# User interface helpers
# ----------------------------------------------------------------------------
USER_ERRORS = (ClinicError, PermissionDeniedError, AccountLockedError)
SPECIALIZATIONS = ["Cardiology", "Dermatology", "Orthopedics", "Pediatrics", "ENT", "Neurology", "Gynecology", "General Medicine"]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def attempt(fn, *args, **kwargs):
    """Run an action and show a friendly message if a business rule or permission blocks it."""
    try:
        return True, fn(*args, **kwargs)
    except USER_ERRORS as exc:
        st.error(str(exc))
    except requests.RequestException:
        st.error("A network error occurred while contacting an external service. Please try again.")
    return False, None


def money(x):
    return f"Rs.{x:,.2f}"


def doctors_list():
    return q("SELECT email, full_name, specialization, city, consultation_fee FROM users WHERE role='doctor' AND is_active=1 ORDER BY full_name")


def doctor_options():
    return {f"{d['full_name']} ({d['specialization']}, {money(d['consultation_fee'])})": d["email"] for d in doctors_list()}


def patient_options():
    return {f"{p['full_name']} ({p['email']})": p["email"] for p in
            q("SELECT email, full_name FROM users WHERE role='patient' AND is_active=1 ORDER BY full_name")}


def _dataframe(data, **kwargs):
    """Full-width table that works across Streamlit versions."""
    kwargs.pop("use_container_width", None)
    try:
        st.dataframe(data, width="stretch", **kwargs)
    except Exception:
        st.dataframe(data, use_container_width=True, **kwargs)


def show_df(rows, columns=None, **kwargs):
    df = pd.DataFrame(rows)
    if df.empty:
        st.info("Nothing to show yet.")
        return
    _dataframe(df[columns] if columns else df, hide_index=True, **kwargs)


# ----------------------------------------------------------------------------
# Sign-in and registration
# ----------------------------------------------------------------------------
def page_login():
    st.title(f":material/medical_services: {CLINIC_NAME}")
    st.caption("Appointments, health records, billing and analytics in one secure system.")
    left, right = st.columns([3, 2], gap="large")
    with left:
        tab_in, tab_reg = st.tabs(["Sign in", "Register as patient"])
        with tab_in:
            with st.form("login_form"):
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign in", type="primary")
            if submitted:
                ok, user = attempt(login, email, password)
                if ok:
                    st.session_state["user"] = user
                    st.rerun()
        with tab_reg:
            with st.form("register_form"):
                name = st.text_input("Full name")
                r_email = st.text_input("Email address")
                phone = st.text_input("Mobile number (for SMS, optional)")
                c1, c2 = st.columns(2)
                age = c1.number_input("Age", 0, 120, 25)
                city = c2.text_input("City")
                pw1 = st.text_input("Password", type="password", help="8+ characters with an uppercase letter, a digit and a symbol")
                pw2 = st.text_input("Confirm password", type="password")
                go = st.form_submit_button("Create account", type="primary")
            if go:
                if pw1 != pw2:
                    st.error("The two passwords do not match.")
                else:
                    ok, _ = attempt(register_patient, name, r_email, pw1, phone, int(age), city)
                    if ok:
                        st.success("Account created. You can now sign in.")
    with right:
        if str(secret("SHOW_DEMO_ACCOUNTS", "true")).lower() == "true":
            with st.container(border=True):
                st.subheader("Demo accounts")
                st.caption(f"All demo accounts use the password {DEMO_PASSWORD}")
                _dataframe(pd.DataFrame([{"Role": r.title(), "Email": e} for _, e, r, _ in DEMO_ACCOUNTS]), hide_index=True)


# ----------------------------------------------------------------------------
# Booking (patients and receptionists)
# ----------------------------------------------------------------------------
def booking_ui(actor, for_patient=False):
    if for_patient:
        pmap = patient_options()
        if not pmap:
            st.info("No patients are registered yet.")
            return
        patient_email = pmap[st.selectbox("Patient", list(pmap))]
    else:
        patient_email = actor["email"]
    dmap = doctor_options()
    if not dmap:
        st.info("No doctors are available.")
        return
    c1, c2 = st.columns(2)
    doctor_email = dmap[c1.selectbox("Doctor", list(dmap))]
    day = c2.date_input("Date", min_value=now().date(), value=now().date() + timedelta(days=1))
    slots = free_slots(doctor_email, day)
    if not generate_slots(doctor_email, day):
        st.warning("The doctor does not work on this day.")
    elif not slots:
        st.warning("All slots on this day are booked. You can join the waitlist and be booked automatically if one opens up.")
        if st.button("Join waitlist for this day"):
            ok, _ = attempt(join_waitlist, actor, patient_email, doctor_email, day)
            if ok:
                st.success("You are on the waitlist.")
    if slots:
        labels = {s.strftime("%I:%M %p") + f" - {e.strftime('%I:%M %p')}": s for s, e in slots}
        choice = st.selectbox("Available slots", list(labels))
        doc = get_user(doctor_email)
        fee = float(doc["consultation_fee"] or 0)
        if fee:
            st.caption(f"Consultation fee {money(fee)} + {int(GST_RATE * 100)}% GST = {money(fee * (1 + GST_RATE))}")
        weeks = 1
        if for_patient:
            weeks = st.number_input("Repeat weekly for (weeks)", 1, 12, 1, help="Creates a recurring series of appointments.")
        if st.button("Confirm booking", type="primary"):
            if weeks > 1:
                ok, res = attempt(book_recurring, actor, patient_email, doctor_email, labels[choice], int(weeks))
                if ok:
                    _, booked, skipped = res
                    st.success(f"Booked {len(booked)} appointment(s).")
                    for when, why in skipped:
                        st.warning(f"{when:%d %b %Y %I:%M %p} skipped: {why}")
            else:
                ok, _ = attempt(book_appointment, actor, patient_email, doctor_email, labels[choice])
                if ok:
                    st.success("Appointment booked. A confirmation has been sent.")
                    st.rerun()


# ----------------------------------------------------------------------------
# Patient pages
# ----------------------------------------------------------------------------
def page_patient_home(user):
    st.title(f"Welcome, {user['full_name'].split()[0]}")
    upcoming = appointment_rows("WHERE a.patient_email = ? AND a.status = 'scheduled' AND a.start_dt > ?", (user["email"], slot_str(now())))
    pending = q("SELECT COUNT(*) n FROM invoices WHERE patient_email = ? AND status = 'pending'", (user["email"],), one=True)["n"]
    unread = q("SELECT COUNT(*) n FROM notifications WHERE user_email = ? AND channel = 'in-app' AND is_read = 0", (user["email"],), one=True)["n"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Upcoming appointments", len(upcoming))
    c2.metric("Invoices to pay", pending)
    c3.metric("Unread notifications", unread)
    st.subheader("Next appointment")
    if upcoming:
        a = upcoming[0]
        st.success(f"{fmt_dt(a['start_dt'])} with {doctor_label(a['doctor_email'])} ({a['specialization']})")
    else:
        st.info("You have no upcoming appointments. Use Book Appointment to schedule one.")


def page_book(user):
    st.title("Book an Appointment")
    st.caption("Free slots are calculated live from each doctor's weekly shift.")
    booking_ui(user)


def page_my_appointments(user):
    st.title("My Appointments")
    rows = appointment_rows("WHERE a.patient_email = ?", (user["email"],))[::-1]
    if not rows:
        st.info("You have not booked any appointments yet.")
    for a in rows:
        with st.container(border=True):
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**{fmt_dt(a['start_dt'])}** with {doctor_label(a['doctor_email'])} ({a['specialization']})")
            c1.caption(f"Status: {a['status'].replace('_', ' ')}" + (" | recurring series" if a["recurrence_id"] else ""))
            if a["status"] == "scheduled":
                if c2.button("Cancel", key=f"cancel_{a['id']}"):
                    ok, _ = attempt(cancel_appointment, user, a["id"])
                    if ok:
                        st.rerun()
            if a["status"] == "completed" and not q("SELECT 1 FROM doctor_ratings WHERE appointment_id = ?", (a["id"],), one=True):
                with st.expander("Rate this visit"):
                    stars = st.slider("Rating", 1, 5, 5, key=f"stars_{a['id']}")
                    comment = st.text_input("Comment (optional)", key=f"cmt_{a['id']}")
                    if st.button("Submit rating", key=f"rate_{a['id']}"):
                        ok, _ = attempt(rate_doctor, user, a["id"], stars, comment)
                        if ok:
                            st.rerun()


def page_find_doctor(user):
    st.title("Find a Doctor")
    symptoms = st.text_input("Describe your symptoms (optional)", placeholder="e.g. skin rash and itching")
    suggestion = suggest_specialization(symptoms) if symptoms.strip() else None
    if suggestion:
        st.info(f"Suggested specialization: **{suggestion}** (matched by keywords in your description)")
    c1, c2, c3, c4 = st.columns(4)
    options = ["Any"] + SPECIALIZATIONS
    spec = c1.selectbox("Specialization", options, index=options.index(suggestion) if suggestion in options else 0)
    city = c2.text_input("City")
    min_rating = c3.slider("Minimum rating", 0.0, 5.0, 0.0, 0.5)
    max_fee = c4.number_input("Maximum fee (Rs.)", 0, 10000, 0, step=100)
    use_date = st.checkbox("Only doctors with free slots on a date")
    on_date = st.date_input("Date", min_value=now().date(), value=now().date() + timedelta(days=1)) if use_date else None
    sort = st.radio("Sort by", ["rating", "fee"], horizontal=True)
    rows = search_doctors(spec, city, min_rating, max_fee or None, on_date, sort)
    if not rows:
        st.warning("No doctors match these filters.")
        return
    table = [{"Doctor": r["full_name"], "Specialization": r["specialization"], "City": r["city"],
              "Fee (Rs.)": r["consultation_fee"], "Rating": f"{r['avg_rating']} ({r['rating_count']})"} for r in rows]
    if on_date:
        for t, r in zip(table, rows):
            t["Free slots"] = r["slots"]
    show_df(table)


def records_ui(actor, patient_email):
    """Shared by patients (own record) and doctors (assigned patients)."""
    is_patient = actor["role"] == "patient"
    tabs = st.tabs(["Profile", "Diagnoses", "Prescriptions", "Documents"])
    with tabs[0]:
        ok, prof = attempt(get_profile, actor, patient_email)
        if not ok:
            return
        if is_patient:
            with st.form("profile_form"):
                groups = ["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
                bg = st.selectbox("Blood group", groups, index=groups.index(prof["blood_group"]) if prof["blood_group"] in groups else 0)
                allergies = st.text_area("Allergies", prof["allergies"])
                conditions = st.text_area("Chronic conditions", prof["conditions"])
                consent = st.checkbox("I consent to my treating doctors adding to my health record", value=prof["consent_given"])
                if st.form_submit_button("Save profile", type="primary"):
                    ok, _ = attempt(save_profile, actor, bg, allergies, conditions, consent)
                    if ok:
                        st.success("Profile saved. Sensitive fields are stored encrypted.")
        else:
            st.write(f"**Blood group:** {prof['blood_group'] or '-'}")
            st.write(f"**Allergies:** {prof['allergies'] or '-'}")
            st.write(f"**Chronic conditions:** {prof['conditions'] or '-'}")
            st.write(f"**Patient consent for new entries:** {'Given' if prof['consent_given'] else 'Not given'}")
    with tabs[1]:
        if actor["role"] == "doctor":
            with st.form("diag_form", clear_on_submit=True):
                diagnosis = st.text_input("Diagnosis")
                notes = st.text_area("Notes")
                if st.form_submit_button("Add diagnosis", type="primary"):
                    ok, _ = attempt(add_diagnosis, actor, patient_email, diagnosis, notes)
                    if ok:
                        st.success("Diagnosis added.")
        ok, hist = attempt(get_history, actor, patient_email)
        if ok:
            show_df([{"Date": h["date"][:16], "Doctor": h["doctor"], "Diagnosis": h["diagnosis"], "Notes": h["notes"]} for h in hist])
    with tabs[2]:
        if actor["role"] == "doctor":
            with st.form("rx_form", clear_on_submit=True):
                st.caption("Add up to three medicines")
                meds = []
                for i in range(3):
                    c1, c2, c3, c4 = st.columns([3, 2, 2, 1])
                    meds.append({"name": c1.text_input("Medicine", key=f"mn{i}"), "dose": c2.text_input("Dose", key=f"md{i}"),
                                 "frequency": c3.text_input("Frequency", key=f"mf{i}"),
                                 "days": c4.number_input("Days", 1, 90, 5, key=f"mdays{i}")})
                notes = st.text_area("Instructions")
                if st.form_submit_button("Issue prescription", type="primary"):
                    ok, pid = attempt(add_prescription, actor, patient_email, meds, notes)
                    if ok:
                        st.success(f"Prescription #{pid} issued and the patient has been notified.")
        ok, rxs = attempt(get_prescriptions, actor, patient_email)
        if ok:
            for rx in rxs:
                with st.container(border=True):
                    st.markdown(f"**Prescription #{rx['id']}** by {rx['doctor']} on {rx['created_at'][:10]}")
                    st.write(", ".join(f"{m['name']} {m.get('dose', '')} ({m.get('frequency', '')}, {m.get('days', '')} days)" for m in rx["meds"]))
                    if rx["pdf_path"] and os.path.exists(rx["pdf_path"]):
                        st.download_button("Download PDF", read_bytes(rx["pdf_path"]), f"prescription_{rx['id']}.pdf",
                                           "application/pdf", key=f"rxpdf_{rx['id']}")
    with tabs[3]:
        up = st.file_uploader("Upload a lab report or document (max 5 MB)", key=f"upl_{patient_email}")
        desc = st.text_input("Description", key=f"desc_{patient_email}")
        if up and st.button("Save document"):
            ok, _ = attempt(upload_document, actor, patient_email, up.name, up.getvalue(), desc)
            if ok:
                st.success("Document saved.")
        ok, docs = attempt(get_documents, actor, patient_email)
        if ok:
            for d in docs:
                c1, c2 = st.columns([4, 1])
                c1.write(f"{d['filename']} - {d['description'] or 'no description'} ({d['created_at'][:10]})")
                if os.path.exists(d["file_path"]):
                    c2.download_button("Download", read_bytes(d["file_path"]), d["filename"], key=f"doc_{d['id']}")


def page_my_records(user):
    st.title("My Medical Records")
    records_ui(user, user["email"])


def page_patient_billing(user):
    st.title("Billing")
    invoices = invoice_rows("WHERE i.patient_email = ?", (user["email"],))
    if not invoices:
        st.info("You have no invoices yet. An invoice is created automatically when you book.")
    links = st.session_state.setdefault("pay_links", {})
    for inv in invoices:
        with st.container(border=True):
            c1, c2 = st.columns([3, 2])
            c1.markdown(f"**Invoice #{inv['id']}** - {inv['doctor_name']} on {fmt_dt(inv['start_dt'])}")
            c1.caption(f"Fee {money(inv['subtotal'])} + GST {money(inv['tax'])} = **{money(inv['total_amount'])}** | Status: {inv['status']}")
            if inv["status"] == "pending":
                if inv["id"] in links:
                    c2.link_button("Open Razorpay payment page", links[inv["id"]])
                    if c2.button("I have paid, check status", key=f"chk_{inv['id']}"):
                        ok, paid = attempt(check_razorpay_payment, inv["id"])
                        if ok and paid:
                            links.pop(inv["id"], None)
                            st.rerun()
                        elif ok:
                            st.warning("Payment not received yet.")
                else:
                    label = "Pay with Razorpay (test mode)" if razorpay_ready() else "Pay now (simulated gateway)"
                    if c2.button(label, key=f"pay_{inv['id']}", type="primary"):
                        ok, res = attempt(start_payment, user, inv["id"])
                        if ok and res["mode"] == "sandbox":
                            ok2, _ = attempt(complete_sandbox_payment, inv["id"], res["order_id"])
                            if ok2:
                                st.rerun()
                        elif ok:
                            links[inv["id"]] = res["url"]
                            st.rerun()
            elif inv["status"] == "paid":
                if inv["receipt_path"] and os.path.exists(inv["receipt_path"]):
                    c2.download_button("Download receipt", read_bytes(inv["receipt_path"]), f"receipt_{inv['id']}.pdf",
                                       "application/pdf", key=f"rcpt_{inv['id']}")
                claim = q("SELECT * FROM insurance_claims WHERE invoice_id = ?", (inv["id"],), one=True)
                if claim:
                    st.caption(f"Insurance claim: {claim['status']} (approved {money(claim['approved_amount'])})")
                else:
                    with st.expander("Submit an insurance claim"):
                        insurer = st.selectbox("Insurer", ["StarHealth (simulated)", "CareFirst (simulated)"], key=f"ins_{inv['id']}")
                        policy = st.text_input("Policy number", key=f"pol_{inv['id']}")
                        if st.button("Submit claim", key=f"claim_{inv['id']}"):
                            ok, res = attempt(submit_claim, user, inv["id"], insurer, policy)
                            if ok:
                                st.success(f"Claim {res[0]}. Approved amount: {money(res[1])}")
                                st.rerun()


def page_consent(user):
    st.title("Privacy and Consent")
    given = has_consent(user["email"])
    st.write("Your treating doctors can add diagnoses, prescriptions and documents to your record only while consent is on. "
             "Sensitive fields are stored encrypted, and every attempt to open your record is logged below.")
    if given:
        st.success("Consent is currently **given**.")
        if st.button("Withdraw consent"):
            attempt(set_consent, user, False)
            st.rerun()
    else:
        st.warning("Consent is currently **not given**, so doctors cannot add to your record.")
        if st.button("Give consent", type="primary"):
            attempt(set_consent, user, True)
            st.rerun()
    st.subheader("Who accessed your record")
    rows = q("SELECT accessor_email, action, status, reason, created_at FROM access_log WHERE patient_email = ? ORDER BY id DESC LIMIT 100",
             (user["email"],))
    show_df(rows)


# ----------------------------------------------------------------------------
# Doctor pages
# ----------------------------------------------------------------------------
def page_doctor_home(user):
    st.title(f"Good day, Dr. {user['full_name'].replace('Dr. ', '').split()[-1]}")
    today = now().date().isoformat()
    todays = appointment_rows("WHERE a.doctor_email = ? AND substr(a.start_dt,1,10) = ? AND a.status != 'cancelled'", (user["email"], today))
    rating = q("SELECT AVG(rating) a, COUNT(*) n FROM doctor_ratings WHERE doctor_email = ?", (user["email"],), one=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("Appointments today", len(todays))
    c2.metric("Patients waiting (walk-in queue)", len(queue_for(user["email"])))
    c3.metric("Average rating", f"{rating['a']:.1f} ({rating['n']})" if rating["n"] else "No ratings yet")
    st.subheader("Walk-in queue")
    queue = queue_for(user["email"])
    show_df([{"Position": i, "Patient": e["patient_name"], "Type": e["kind"].replace("_", " "), "Arrived": e["arrived_at"][11:16]}
             for i, e in enumerate(queue, start=1)])


def page_schedule(user):
    st.title("My Schedule")
    day = st.date_input("Day", value=now().date())
    rows = appointment_rows("WHERE a.doctor_email = ? AND substr(a.start_dt,1,10) = ?", (user["email"], day.isoformat()))
    if not rows:
        st.info("No appointments on this day.")
    for a in rows:
        with st.container(border=True):
            c1, c2, c3 = st.columns([4, 1, 1])
            c1.markdown(f"**{datetime.fromisoformat(a['start_dt']):%I:%M %p}** - {a['patient_name']}")
            c1.caption(f"Status: {a['status'].replace('_', ' ')}")
            if a["status"] == "scheduled":
                if c2.button("Completed", key=f"done_{a['id']}"):
                    ok, _ = attempt(set_appointment_status, user, a["id"], "completed")
                    if ok:
                        st.rerun()
                if c3.button("No-show", key=f"ns_{a['id']}"):
                    ok, _ = attempt(set_appointment_status, user, a["id"], "no_show")
                    if ok:
                        st.rerun()


def page_availability(user):
    st.title("My Availability")
    rows = q("SELECT * FROM doctor_availability WHERE doctor_email = ? ORDER BY day_of_week", (user["email"],))
    show_df([{"Day": WEEKDAYS[r["day_of_week"]], "From": r["start_time"], "To": r["end_time"],
              "Slot (min)": r["slot_minutes"], "Buffer (min)": r["buffer_minutes"]} for r in rows])
    st.subheader("Set a weekly shift")
    with st.form("shift_form"):
        days = st.multiselect("Days", WEEKDAYS, default=["Monday"])
        c1, c2, c3, c4 = st.columns(4)
        start = c1.time_input("Start", datetime.strptime("10:00", "%H:%M").time())
        end = c2.time_input("End", datetime.strptime("13:00", "%H:%M").time())
        slot = c3.number_input("Slot length (min)", 5, 120, 20)
        buf = c4.number_input("Buffer (min)", 0, 60, 5)
        if st.form_submit_button("Save shift", type="primary"):
            ok, _ = attempt(set_availability, user, [WEEKDAYS.index(d) for d in days], start.strftime("%H:%M"),
                            end.strftime("%H:%M"), int(slot), int(buf))
            if ok:
                st.success("Availability saved.")
                st.rerun()
    remove = st.selectbox("Remove a day's shift", ["-"] + WEEKDAYS)
    if remove != "-" and st.button("Remove shift"):
        attempt(clear_availability, user, WEEKDAYS.index(remove))
        st.rerun()


def page_patient_records(user):
    st.title("Patient Records")
    patients = patients_of(user["email"])
    if not patients:
        st.info("You have no patients yet. Records become available after an appointment is booked.")
        return
    pmap = {f"{p['full_name']} ({p['email']})": p["email"] for p in patients}
    records_ui(user, pmap[st.selectbox("Patient", list(pmap))])


def page_delay(user):
    st.title("Report a Delay")
    st.caption("Notifies every patient booked with you today.")
    minutes = st.slider("Running late by (minutes)", 5, 120, 15, 5)
    if st.button("Notify patients", type="primary"):
        ok, n = attempt(report_delay, user, minutes)
        if ok:
            st.success(f"Delay message sent to {n} patient(s).")


# ----------------------------------------------------------------------------
# Receptionist pages
# ----------------------------------------------------------------------------
def page_reception_home(user):
    st.title("Reception Desk")
    today = now().date().isoformat()
    todays = appointment_rows("WHERE substr(a.start_dt,1,10) = ? AND a.status != 'cancelled'", (today,))
    pending = q("SELECT COUNT(*) n FROM invoices WHERE status = 'pending'", one=True)["n"]
    waiting = q("SELECT COUNT(*) n FROM queue_entries WHERE status = 'waiting'", one=True)["n"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Appointments today", len(todays))
    c2.metric("Patients in queue", waiting)
    c3.metric("Unpaid invoices", pending)
    st.subheader("Today's appointments")
    show_df([{"Time": a["start_dt"][11:16], "Patient": a["patient_name"], "Doctor": a["doctor_name"], "Status": a["status"]} for a in todays])


def page_book_for_patient(user):
    st.title("Book for a Patient")
    booking_ui(user, for_patient=True)


def page_queue(user):
    st.title("Walk-ins and Queue")
    with st.expander("Register a new walk-in patient"):
        with st.form("walkin_form", clear_on_submit=True):
            name = st.text_input("Full name")
            email = st.text_input("Email")
            phone = st.text_input("Mobile number")
            if st.form_submit_button("Register"):
                temp = "Walk@" + secrets.token_hex(3) + "1X"
                ok, _ = attempt(register_patient, name, email, temp, phone)
                if ok:
                    audit(user["email"], "WALKIN_REGISTERED", email)
                    st.success(f"Registered. Temporary password: {temp}")
    pmap, dmap = patient_options(), doctor_options()
    if pmap and dmap:
        with st.form("queue_form"):
            c1, c2, c3 = st.columns(3)
            patient = pmap[c1.selectbox("Patient", list(pmap))]
            doctor = dmap[c2.selectbox("Doctor", list(dmap))]
            kind = c3.radio("Type", ["walk_in", "emergency"], horizontal=True, format_func=lambda k: k.replace("_", " ").title())
            if st.form_submit_button("Add to queue", type="primary"):
                ok, _ = attempt(add_to_queue, user, patient, doctor, kind)
                if ok:
                    st.rerun()
    for label, email in dmap.items():
        st.subheader(label)
        queue = queue_for(email)
        show_df([{"Position": i, "Patient": e["patient_name"], "Type": e["kind"].replace("_", " "), "Arrived": e["arrived_at"][11:16],
                  "Est. wait (min)": (i - 1) * MINUTES_PER_PATIENT} for i, e in enumerate(queue, start=1)])
        if queue and st.button("Call next patient", key=f"next_{email}"):
            ok, served = attempt(serve_next, user, email)
            if ok:
                st.success(f"Now serving {served['patient_name']}.")
                st.rerun()


def page_all_appointments(user):
    st.title("All Appointments")
    c1, c2 = st.columns(2)
    day = c1.date_input("From date", value=now().date())
    status = c2.selectbox("Status", ["all", "scheduled", "completed", "no_show", "cancelled"])
    sql, params = "WHERE substr(a.start_dt,1,10) >= ?", [day.isoformat()]
    if status != "all":
        sql += " AND a.status = ?"
        params.append(status)
    rows = appointment_rows(sql, params)
    show_df([{"ID": a["id"], "When": a["start_dt"], "Patient": a["patient_name"], "Doctor": a["doctor_name"], "Status": a["status"]} for a in rows])
    scheduled = [a for a in rows if a["status"] == "scheduled"]
    if scheduled:
        pick = st.selectbox("Cancel an appointment", [f"#{a['id']} {a['start_dt']} {a['patient_name']}" for a in scheduled])
        if st.button("Cancel selected appointment"):
            ok, _ = attempt(cancel_appointment, user, int(pick.split()[0][1:]))
            if ok:
                st.success("Cancelled. Any waiting patient is booked automatically and refunds are processed.")
                st.rerun()


def page_billing_desk(user):
    st.title("Billing Desk")
    for inv in invoice_rows("WHERE i.status IN ('pending','paid')")[:50]:
        with st.container(border=True):
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**Invoice #{inv['id']}** - {inv['patient_name']} with {inv['doctor_name']}")
            c1.caption(f"{money(inv['total_amount'])} | {inv['status']} | {fmt_dt(inv['start_dt'])}")
            if inv["status"] == "pending" and c2.button("Collect at counter", key=f"col_{inv['id']}"):
                ok, _ = attempt(collect_at_counter, user, inv["id"])
                if ok:
                    st.rerun()
            if inv["status"] == "paid" and c2.button("Refund", key=f"ref_{inv['id']}"):
                ok, _ = attempt(refund_invoice, user, inv["id"])
                if ok:
                    st.rerun()


def page_reminders(user):
    st.title("Appointment Reminders")
    hours = st.slider("Remind patients with appointments in the next (hours)", 1, 72, 24)
    if st.button("Send reminders now", type="primary"):
        ok, n = attempt(send_reminders, user, hours)
        if ok:
            st.success(f"{n} reminder(s) sent." if n else "No reminders are due.")


# ----------------------------------------------------------------------------
# Admin pages
# ----------------------------------------------------------------------------
def page_admin_home(user):
    st.title("Administration")
    today = now().date().isoformat()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Active users", q("SELECT COUNT(*) n FROM users WHERE is_active = 1", one=True)["n"])
    c2.metric("Appointments today", q("SELECT COUNT(*) n FROM appointments WHERE substr(start_dt,1,10)=? AND status != 'cancelled'", (today,), one=True)["n"])
    c3.metric("Revenue collected", money(q("SELECT COALESCE(SUM(total_amount),0) s FROM invoices WHERE status='paid'", one=True)["s"]))
    c4.metric("Denied access attempts", q("SELECT COUNT(*) n FROM access_log WHERE status='denied'", one=True)["n"])
    st.info("Use the menu to view analytics, manage users, review logs and generate the compliance report.")


def page_analytics(user):
    st.title("Analytics")
    c1, c2 = st.columns(2)
    start = c1.date_input("From", value=now().date() - timedelta(days=14))
    end = c2.date_input("To", value=now().date())
    if start > end:
        st.error("The start date must not be after the end date.")
        return
    ok, data = attempt(analytics_snapshot, user, start, end)
    if not ok:
        return
    if data["appointments"].empty:
        st.info("There are no appointments in this period.")
        if st.button("Load two weeks of sample data"):
            ok, n = attempt(load_sample_history, user)
            if ok:
                st.success(f"Loaded {n} sample appointments.")
                st.rerun()
        return
    appts, inv = data["appointments"], data["invoices"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Appointments", int((appts["status"] != "cancelled").sum()))
    done, missed = (appts["status"] == "completed").sum(), (appts["status"] == "no_show").sum()
    c2.metric("No-show rate", f"{100 * missed / (done + missed):.1f}%" if (done + missed) else "n/a")
    c3.metric("Cancellations", int((appts["status"] == "cancelled").sum()))
    c4.metric("Revenue (paid)", money(inv["total_amount"].sum()) if not inv.empty else money(0))
    st.subheader("Peak hours")
    st.bar_chart(data["peak"])
    st.subheader("Doctor utilization and no-show rate")
    _dataframe(data["doctors"], hide_index=True)
    if not inv.empty:
        inv = inv.assign(day=inv["paid_at"].str[:10])
        left, right = st.columns(2)
        left.subheader("Revenue by day")
        left.line_chart(inv.groupby("day")["total_amount"].sum())
        right.subheader("Revenue by specialization")
        right.bar_chart(inv.groupby("specialization")["total_amount"].sum())
    with st.expander("Sample data"):
        st.caption("Adds synthetic patients, visits and payments for demonstration.")
        if st.button("Load two weeks of sample data", key="sample2"):
            ok, n = attempt(load_sample_history, user)
            if ok:
                st.success(f"Loaded {n} sample appointments.")
                st.rerun()


def page_users(user):
    st.title("Users")
    ok, users = attempt(list_users, user)
    if not ok:
        return
    show_df([{k: u[k] for k in ("full_name", "email", "role", "specialization", "city", "is_active")} for u in users])
    st.subheader("Create a user")
    with st.form("new_user", clear_on_submit=True):
        c1, c2 = st.columns(2)
        name, email = c1.text_input("Full name"), c2.text_input("Email")
        c3, c4 = st.columns(2)
        role = c3.selectbox("Role", [r.value for r in Role])
        password = c4.text_input("Initial password", type="password")
        c5, c6, c7 = st.columns(3)
        spec = c5.selectbox("Specialization (doctors)", [""] + SPECIALIZATIONS)
        city = c6.text_input("City")
        fee = c7.number_input("Consultation fee (doctors)", 0, 10000, 500, step=50)
        if st.form_submit_button("Create user", type="primary"):
            ok, _ = attempt(admin_create_user, user, full_name=name, email=email, password=password, role=role,
                            specialization=spec or None, city=city, fee=fee)
            if ok:
                st.success("User created.")
                st.rerun()
    st.subheader("Manage an account")
    emails = [u["email"] for u in users if u["email"] != user["email"]]
    if emails:
        target = st.selectbox("Account", emails)
        c1, c2, c3, c4 = st.columns(4)
        if c1.button("Deactivate"):
            if attempt(deactivate_user, user, target)[0]:
                st.rerun()
        if c2.button("Reactivate"):
            if attempt(reactivate_user, user, target)[0]:
                st.rerun()
        new_role = c3.selectbox("New role", [r.value for r in Role], label_visibility="collapsed")
        if c3.button("Change role"):
            if attempt(assign_role, user, target, new_role)[0]:
                st.rerun()
        if c4.button("Reset password"):
            ok, temp = attempt(reset_user_password, user, target)
            if ok:
                st.success(f"Temporary password: {temp}")


def page_logs(user):
    st.title("Audit and Access Logs")
    if not can(user, "view_audit_log"):
        st.error("You do not have permission to view the logs.")
        return
    limit = st.slider("Rows to show", 25, 500, 100, 25)
    t1, t2 = st.tabs(["Account and system events", "Patient record access"])
    with t1:
        show_df(q("SELECT created_at, user_email, action, details FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)))
    with t2:
        show_df(q("SELECT created_at, accessor_email, patient_email, action, status, reason FROM access_log ORDER BY id DESC LIMIT ?", (limit,)))


def page_compliance(user):
    st.title("Compliance")
    ok, pdf_path = attempt(compliance_report_pdf, user)
    st.subheader("Self-audit statistics")
    _dataframe(pd.DataFrame(compliance_stats().items(), columns=["Statistic", "Value"]), hide_index=True)
    if ok:
        st.download_button("Download compliance report (PDF)", read_bytes(pdf_path), "compliance_report.pdf", "application/pdf")
    st.subheader("Right to erasure")
    pmap = patient_options()
    if pmap:
        who = pmap[st.selectbox("Patient", list(pmap))]
        confirm = st.checkbox("I confirm this patient's identifiable health data should be erased permanently")
        if st.button("Erase health data", disabled=not confirm):
            if attempt(erase_patient_data, user, who)[0]:
                st.success("Identifiable fields were wiped. Anonymous aggregates are kept.")
    st.subheader("Retention")
    days = st.number_input("Delete access-log entries older than (days)", 1, 3650, 90)
    if st.button("Run retention purge"):
        ok, n = attempt(purge_old_access_logs, user, int(days))
        if ok:
            st.success(f"{n} old access-log entries deleted.")


# ----------------------------------------------------------------------------
# Shared pages
# ----------------------------------------------------------------------------
def page_notifications(user):
    st.title("Notifications")
    rows = q("""SELECT id, created_at, subject, body, is_read FROM notifications WHERE user_email = ? AND channel = 'in-app'
                ORDER BY id DESC LIMIT 50""", (user["email"],))
    if not rows:
        st.info("You have no notifications yet.")
    for n in rows:
        with st.container(border=True):
            st.markdown(f"{'**' if not n['is_read'] else ''}{n['subject']}{'**' if not n['is_read'] else ''}  \n{n['body']}")
            st.caption(n["created_at"])
    ex("UPDATE notifications SET is_read = 1 WHERE user_email = ? AND channel = 'in-app'", (user["email"],))
    with st.expander("Delivery log for email, SMS and push"):
        show_df(q("""SELECT created_at, channel, notif_type, status, detail FROM notifications WHERE user_email = ? AND channel != 'in-app'
                     ORDER BY id DESC LIMIT 50""", (user["email"],)))


def page_account(user):
    st.title("My Account")
    st.write(f"**{user['full_name']}** - {user['email']} - {user['role'].title()}")
    with st.form("contact_form"):
        phone = st.text_input("Mobile number", user.get("phone") or "", help="Used for SMS notifications")
        city = st.text_input("City", user.get("city") or "")
        if st.form_submit_button("Save contact details"):
            update_contact(user, phone, city)
            st.session_state["user"] = get_user(user["email"])
            st.success("Saved.")
    with st.form("password_form", clear_on_submit=True):
        old = st.text_input("Current password", type="password")
        new = st.text_input("New password", type="password")
        if st.form_submit_button("Change password"):
            ok, _ = attempt(change_password, user, old, new)
            if ok:
                st.success("Password changed.")


# ----------------------------------------------------------------------------
# Navigation and application shell
# ----------------------------------------------------------------------------
MENUS = {
    "patient": {"Home": page_patient_home, "Book Appointment": page_book, "My Appointments": page_my_appointments,
                "Find a Doctor": page_find_doctor, "Medical Records": page_my_records, "Billing": page_patient_billing,
                "Notifications": page_notifications, "Privacy and Consent": page_consent, "Account": page_account},
    "doctor": {"Home": page_doctor_home, "My Schedule": page_schedule, "Availability": page_availability,
               "Patient Records": page_patient_records, "Report Delay": page_delay,
               "Notifications": page_notifications, "Account": page_account},
    "receptionist": {"Home": page_reception_home, "Book for Patient": page_book_for_patient,
                     "Walk-ins and Queue": page_queue, "All Appointments": page_all_appointments,
                     "Billing Desk": page_billing_desk, "Reminders": page_reminders,
                     "Notifications": page_notifications, "Account": page_account},
    "admin": {"Home": page_admin_home, "Analytics": page_analytics, "Users": page_users,
              "Audit and Access Logs": page_logs, "Compliance": page_compliance,
              "Notifications": page_notifications, "Account": page_account},
}


def configured(*names):
    return all(secret(n) for n in names)


def sidebar_services():
    st.sidebar.subheader("Services")
    st.sidebar.toggle("Live services", key="live_mode", help="Off: everything is simulated and works offline. On: real email, SMS, push and Razorpay test payments.")
    if is_live():
        st.sidebar.checkbox("Email (Gmail)", key="ch_email")
        st.sidebar.checkbox("Push (ntfy)", key="ch_push")
        st.sidebar.checkbox("SMS (Twilio)", key="ch_sms")
        status = {"Gmail": configured("GMAIL_USER", "GMAIL_APP_PASSWORD"), "ntfy": configured("NTFY_TOPIC"),
                  "Twilio": configured("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER"),
                  "Razorpay": configured("RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET")}
        st.sidebar.caption(" | ".join(f"{k}: {'ready' if v else 'not set'}" for k, v in status.items()))
    else:
        st.sidebar.caption("Simulated mode: messages are logged in the app and payments use a test gateway.")


def main():
    for key, default in ("live_mode", False), ("ch_email", True), ("ch_push", True), ("ch_sms", False):
        st.session_state.setdefault(key, default)
    ensure_demo_data()
    user = st.session_state.get("user")
    if not user:
        page_login()
        return
    user = get_user(user["email"]) or user
    if not user["is_active"]:
        st.session_state.pop("user", None)
        st.rerun()
    st.session_state["user"] = user
    menu = MENUS[user["role"]]
    with st.sidebar:
        st.title(CLINIC_NAME)
        st.write(f"**{user['full_name']}**")
        st.caption(user["role"].title())
        choice = st.radio("Menu", list(menu), label_visibility="collapsed")
    sidebar_services()
    if st.sidebar.button("Sign out"):
        audit(user["email"], "LOGOUT", "")
        for key in ("user", "pay_links", "toasts"):
            st.session_state.pop(key, None)
        st.rerun()
    menu[choice](user)
    for message in st.session_state.pop("toasts", []):
        st.toast(message)


main()
