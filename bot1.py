"""
Gmail OTP Telegram Bot (v6)

Requirements:
    pip install "python-telegram-bot[job-queue]>=22.7"

What's new in v6:
    - Simpler, cleaner emoji set across the whole bot.
    - Language button (বাংলা / English). Every user menu, message and button follows
      the chosen language. The choice is remembered per user.
    - 2FA button: the user sends a 2FA secret key (or an otpauth:// link) and gets a
      live 6-digit code in a clean card (countdown, copy button, refresh).
      The key is NEVER written to disk. It only lives in RAM while the card is open
      and is wiped when the card is closed / expires (TF_DELETE_SECONDS).
      No extra library needed (TOTP is implemented with the standard library).

Still included: Gmail App Password (IMAP) flow, colored inline buttons,
Admin Panel -> Manage Buttons, custom main-menu buttons, OTP polling.
"""

import asyncio
import base64
import email as email_lib
import hashlib
import hmac
import html
import imaplib
import json
import logging
import os
import random
import re
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from email import policy

from telegram import (
    Update, ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardButton, InlineKeyboardMarkup, CopyTextButton,
)
from telegram.constants import ParseMode
from telegram.error import TelegramError, BadRequest
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters,
)

# ───────────────────────── CONFIG ─────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "BOT_TOKEN")

# Put your Telegram numeric ID(s) here -> you will see the "Admin Panel" button
ADMIN_IDS = [8072417816]

# Force-join channel (the bot MUST be an admin of this channel)
CHANNEL_ID = "@MARJAN_GROUP_LTD"
CHANNEL_URL = "https://t.me/MARJAN_GROUP_LTD"
# True  = admins skip the join check (so you will NOT see it on your admin account)
# False = admins must join/verify like everybody else (handy for testing)
ADMIN_SKIP_JOIN = True

# Gmail is read over IMAP with the user's App Password (no OAuth / Google Cloud needed)
IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
APP_PASSWORD_URL = "https://myaccount.google.com/apppasswords"

OTP_DELETE_SECONDS = 40      # auto-delete OTP message after this many seconds
TF_DELETE_SECONDS = 120      # auto-delete the 2FA card (and wipe its key from RAM) after this long
CHECK_INTERVAL = 2           # how often (seconds) the bot checks every mailbox
MAX_EMAILS_PER_USER = 5
DB_FILE = "data.json"
BTN_COLOR = "primary"        # "primary" (blue) / "success" (green) / "danger" (red)
DEFAULT_LANG = "en"          # language for users who have not chosen yet: "bn" or "en"
# ──────────────────────────────────────────────────────────

MAIL_LOOKBACK_DAYS = 2       # "Refresh OTP" looks at mail from the last N days
MAX_NEW_PER_POLL = 10        # safety cap: newest N unseen mails handled per check

BTN_ADMIN = "⚙️ Admin Panel"

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("otpbot")


def ib(text, **kwargs) -> InlineKeyboardButton:
    """Inline button with the configured color applied."""
    return InlineKeyboardButton(text, style=BTN_COLOR, **kwargs)


# ───────────────────────── TRANSLATIONS ─────────────────────────
T = {
    "en": {
        "btn_gmail": "✉️ Gmail",
        "btn_2fa": "🛡 2FA",
        "btn_delete": "🗑 Delete Mail",
        "btn_support": "💬 Support",
        "btn_lang": "🌐 Language",
        "back": "‹ Back",
        "close": "✕ Close",
        "add_new": "＋ Add New Email",
        "refresh_otp": "↻ Refresh OTP",
        "random_again": "⇄ Random Again",
        "delete_all": "🗑 Delete All",

        "join_text": "🔒 Please join our channel to use this bot.\n\n1. Tap “Join Channel”\n2. Come back and tap “Verify”",
        "join_btn": "Join Channel",
        "verify_btn": "✓ Verify",
        "not_joined_alert": "You have not joined the channel yet.",
        "not_joined_retry": "You have not joined the channel yet. Please join and try again.",
        "verified": "✓ Verified",
        "welcome": ("✦ <b>Gmail OTP Bot</b>\n\n"
                    "Connect your Gmail and receive OTP codes instantly.\n"
                    "Generate random email styles and get 2FA codes.\n\n"
                    "Choose an option below."),

        "gm_none": "No Gmail connected yet.\nPlease connect your Gmail first.",
        "gm_title": "✉️ Your Gmail Accounts ({n}/{max})\n\nTap an account to open it.",
        "gm_detail": "✉️ Your Generated Gmail",
        "limit": "Email limit reached. Delete one first.",
        "otp_found": "✓ OTP Found\n✉️ {addr}",
        "otp_none": "No OTP found in recent emails.",
        "signin_removed": ("Could not sign in to {email} (App Password wrong, revoked, or the account needs "
                           "to be reconnected), so it was removed.\nPlease add it again with an App Password."),
        "signin_short": "Could not sign in to {email}. Please add it again with a valid App Password.",
        "del_select": "Select the email you want to remove:",
        "del_none": "No email connected.",
        "del_done_none": "✓ Email deleted. No email connected now.",
        "del_all_done": "✓ All emails deleted.",
        "sup_none": "Support is not set up yet.",
        "sup_title": "💬 Need help? Contact us:",

        "w_step": "Step {n}/3",
        "w1_body": ("Send the Gmail address you want to connect.\n"
                    "<i>Example:</i> <code>name@gmail.com</code>"),
        "w2_body": ("App name: <code>OTP Bot</code>\n\n"
                    "Send this name here to continue."),
        "w3_body": ("Tap <b>Create App Password</b>, create it, then copy the 16-letter password "
                    "and send it here."),
        "w_bad_name": "Please send the app name to continue.",
        "w_create_pw": "🔑 Create App Password",
        "w_bad_email": "That doesn't look like a Gmail address. Please send it again.",
        "w_bad_pw": "An App Password is exactly 16 letters (not your normal Gmail password). Please send it again.",
        "w_rejected": ("Gmail rejected this App Password. Make sure 2-Step Verification is ON and the "
                       "password is correct, then send it again."),
        "w_unreachable": "Could not reach Gmail right now. Please send the App Password again in a moment.",
        "w_expired": "Session expired. Open <b>Gmail</b> → <b>Add New Email</b> and start again.",
        "w_connecting": "Connecting <code>{addr}</code> ...",
        "w_connected": "✓ <b>Gmail connected</b>",
        "w_connected_body": "✉️ <code>{addr}</code>\nAccounts connected: {n}/{max}\n\nOTPs will appear here automatically.",

        "tf_title": "🛡 <b>Two-Step Verification</b>",
        "tf_prompt": ("Send your <b>2FA secret key</b> (the setup key shown next to the QR code).\n"
                      "<i>Example:</i> <code>JBSW Y3DP EHPK 3PXP</code>\n\n"
                      "Your key is never saved. It is only kept in memory while this card is open, "
                      "and your message is deleted right away."),
        "tf_bad": "That is not a valid 2FA key. Please check it and send it again.",
        "tf_valid": "Valid for {s}s",
        "tf_refresh": "↻ Refresh",
        "tf_newkey": "🔑 New Key",
        "tf_copy": "⧉",
        "tf_expired": "Session ended. Tap <b>2FA</b> and send your key again.",
        "tf_foot": "Not saved anywhere · auto-closes in {m} min",

        "lang_title": "🌐 <b>Language</b>\n\nChoose your language:",
        "lang_set": "✓ Language set to English.",
    },
    "bn": {
        "btn_gmail": "✉️ জিমেইল",
        "btn_2fa": "🛡 টু-ফ্যাক্টর",
        "btn_delete": "🗑 মেইল ডিলিট",
        "btn_support": "💬 সাপোর্ট",
        "btn_lang": "🌐 ভাষা",
        "back": "‹ পিছনে",
        "close": "✕ বন্ধ করুন",
        "add_new": "＋ নতুন ইমেইল যোগ করুন",
        "refresh_otp": "↻ OTP রিফ্রেশ",
        "random_again": "⇄ আবার র‍্যান্ডম",
        "delete_all": "🗑 সব ডিলিট",

        "join_text": "🔒 বটটি ব্যবহার করতে আমাদের চ্যানেলে জয়েন করুন।\n\n1. “চ্যানেলে জয়েন করুন” চাপুন\n2. ফিরে এসে “ভেরিফাই” চাপুন",
        "join_btn": "চ্যানেলে জয়েন করুন",
        "verify_btn": "✓ ভেরিফাই",
        "not_joined_alert": "আপনি এখনো চ্যানেলে জয়েন করেননি।",
        "not_joined_retry": "আপনি এখনো চ্যানেলে জয়েন করেননি। জয়েন করে আবার চেষ্টা করুন।",
        "verified": "✓ ভেরিফাই সফল",
        "welcome": ("✦ <b>Gmail OTP Bot</b>\n\n"
                    "আপনার Gmail কানেক্ট করুন এবং সাথে সাথে OTP পান।\n"
                    "র‍্যান্ডম ইমেইল স্টাইল তৈরি করুন এবং 2FA কোড পান।\n\n"
                    "নিচ থেকে একটি অপশন বেছে নিন।"),

        "gm_none": "এখনো কোনো Gmail কানেক্ট করা নেই।\nআগে আপনার Gmail কানেক্ট করুন।",
        "gm_title": "✉️ আপনার Gmail অ্যাকাউন্ট ({n}/{max})\n\nখুলতে একটি অ্যাকাউন্টে চাপুন।",
        "gm_detail": "✉️ আপনার জেনারেট করা Gmail",
        "limit": "ইমেইলের সীমা শেষ। আগে একটি ডিলিট করুন।",
        "otp_found": "✓ OTP পাওয়া গেছে\n✉️ {addr}",
        "otp_none": "সাম্প্রতিক ইমেইলে কোনো OTP পাওয়া যায়নি।",
        "signin_removed": ("{email} এ সাইন ইন করা যায়নি (App Password ভুল/বাতিল, অথবা অ্যাকাউন্টটি আবার "
                           "কানেক্ট করতে হবে), তাই এটি সরিয়ে দেওয়া হয়েছে।\nApp Password দিয়ে আবার যোগ করুন।"),
        "signin_short": "{email} এ সাইন ইন করা যায়নি। সঠিক App Password দিয়ে আবার যোগ করুন।",
        "del_select": "যে ইমেইলটি সরাতে চান সেটি বেছে নিন:",
        "del_none": "কোনো ইমেইল কানেক্ট করা নেই।",
        "del_done_none": "✓ ইমেইল ডিলিট হয়েছে। এখন কোনো ইমেইল কানেক্ট নেই।",
        "del_all_done": "✓ সব ইমেইল ডিলিট হয়েছে।",
        "sup_none": "সাপোর্ট এখনো সেট করা হয়নি।",
        "sup_title": "💬 সাহায্য দরকার? আমাদের সাথে যোগাযোগ করুন:",

        "w_step": "ধাপ {n}/3",
        "w1_body": ("যে Gmail ঠিকানা কানেক্ট করতে চান সেটি পাঠান।\n"
                    "<i>উদাহরণ:</i> <code>name@gmail.com</code>"),
        "w2_body": ("অ্যাপের নাম: <code>OTP Bot</code>\n\n"
                    "এগিয়ে যেতে এই নামটি এখানে পাঠান।"),
        "w3_body": ("<b>App Password তৈরি করুন</b> বাটনে চাপুন, পাসওয়ার্ড তৈরি করুন, তারপর "
                    "১৬ অক্ষরের পাসওয়ার্ডটি কপি করে এখানে পাঠান।"),
        "w_bad_name": "এগিয়ে যেতে অ্যাপের নামটি পাঠান।",
        "w_create_pw": "🔑 App Password তৈরি করুন",
        "w_bad_email": "এটি Gmail ঠিকানার মতো নয়। আবার পাঠান।",
        "w_bad_pw": "App Password ঠিক ১৬ অক্ষরের হয় (আপনার সাধারণ Gmail পাসওয়ার্ড নয়)। আবার পাঠান।",
        "w_rejected": ("Gmail এই App Password গ্রহণ করেনি। 2-Step Verification চালু আছে কিনা এবং "
                       "পাসওয়ার্ড ঠিক আছে কিনা দেখে আবার পাঠান।"),
        "w_unreachable": "এই মুহূর্তে Gmail এ পৌঁছানো যাচ্ছে না। একটু পরে App Password আবার পাঠান।",
        "w_expired": "সেশন শেষ হয়ে গেছে। <b>জিমেইল</b> → <b>নতুন ইমেইল যোগ করুন</b> থেকে আবার শুরু করুন।",
        "w_connecting": "<code>{addr}</code> কানেক্ট করা হচ্ছে ...",
        "w_connected": "✓ <b>Gmail কানেক্ট হয়েছে</b>",
        "w_connected_body": "✉️ <code>{addr}</code>\nকানেক্টেড অ্যাকাউন্ট: {n}/{max}\n\nOTP এখানে নিজে থেকেই আসবে।",

        "tf_title": "🛡 <b>টু-স্টেপ ভেরিফিকেশন</b>",
        "tf_prompt": ("আপনার <b>2FA সিক্রেট কী</b> পাঠান (QR কোডের পাশে দেওয়া সেটআপ কী)।\n"
                      "<i>উদাহরণ:</i> <code>JBSW Y3DP EHPK 3PXP</code>\n\n"
                      "আপনার কী কখনো সেভ করা হয় না। এই কার্ড খোলা থাকা পর্যন্ত শুধু মেমোরিতে থাকে, "
                      "আর আপনার মেসেজ সাথে সাথে মুছে ফেলা হয়।"),
        "tf_bad": "এটি সঠিক 2FA কী নয়। যাচাই করে আবার পাঠান।",
        "tf_valid": "আর {s} সেকেন্ড বৈধ",
        "tf_refresh": "↻ রিফ্রেশ",
        "tf_newkey": "🔑 নতুন কী",
        "tf_copy": "⧉",
        "tf_expired": "সেশন শেষ। <b>টু-ফ্যাক্টর</b> চেপে আবার আপনার কী পাঠান।",
        "tf_foot": "কোথাও সেভ হয় না · {m} মিনিট পরে নিজে বন্ধ হবে",

        "lang_title": "🌐 <b>ভাষা</b>\n\nআপনার ভাষা বেছে নিন:",
        "lang_set": "✓ ভাষা বাংলা করা হয়েছে।",
    },
}
LANGS = ("bn", "en")


def lang_of(uid: int) -> str:
    u = db["users"].get(str(uid))
    lg = (u or {}).get("lang", DEFAULT_LANG)
    return lg if lg in T else DEFAULT_LANG


def tr(uid: int, key: str, **kw) -> str:
    s = T[lang_of(uid)][key]
    return s.format(**kw) if kw else s


def all_labels(key: str):
    return [T[lg][key] for lg in LANGS]


# ───────────────────────── DATABASE ─────────────────────────
DEFAULT_SETTINGS = {"buttons": {"gmail": True, "twofa": True, "delete": True, "support": True, "language": True}}
db = {"users": {}, "support": [], "custom_buttons": [], "settings": DEFAULT_SETTINGS}


BUILTIN_IDS = ["gmail", "twofa", "delete", "support", "language"]
BUILTIN_TEXT = {"gmail": "btn_gmail", "twofa": "btn_2fa", "delete": "btn_delete",
                "support": "btn_support", "language": "btn_lang"}
BUILTIN_ADMIN_LABEL = {"gmail": "✉️ Gmail", "twofa": "🛡 2FA", "delete": "🗑 Delete Mail",
                       "support": "💬 Support", "language": "🌐 Language"}


def new_cid() -> str:
    return "c" + str(int(time.time() * 1000)) + str(random.randint(10, 99))


def get_order() -> list:
    """Menu order: built-in keys + custom button ids. Self-healing (adds new, drops stale)."""
    valid = BUILTIN_IDS + [c["id"] for c in db["custom_buttons"] if c.get("id")]
    cur = [x for x in db["settings"].get("order", []) if x in valid]
    cur += [x for x in valid if x not in cur]
    db["settings"]["order"] = cur
    return cur


def load_db():
    global db
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            db["users"] = data.get("users", {})
            db["support"] = data.get("support", [])
            db["custom_buttons"] = data.get("custom_buttons", [])
            db["settings"] = data.get("settings", DEFAULT_SETTINGS)
            db["settings"].setdefault("buttons", {})
            for k, v in DEFAULT_SETTINGS["buttons"].items():
                db["settings"]["buttons"].setdefault(k, v)
            for cb in db["custom_buttons"]:
                cb.setdefault("id", new_cid())
        except Exception as e:
            log.error("Could not load DB: %s", e)


def save_db():
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=1)
    os.replace(tmp, DB_FILE)


def ensure_user(tg_user) -> dict:
    key = str(tg_user.id)
    u = db["users"].get(key)
    if not u:
        u = {"joined": int(time.time()), "emails": []}
        db["users"][key] = u
    u["name"] = tg_user.full_name
    u["username"] = tg_user.username or ""
    save_db()
    return u


def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS


# ───────────────────────── TOTP (2FA) - standard library only ─────────────────────────
def parse_totp_secret(raw: str):
    """Accepts a plain key ('JBSW Y3DP ...') or an otpauth:// link. Returns clean base32 or None."""
    raw = (raw or "").strip()
    m = re.search(r"secret=([^&\s]+)", raw, re.I)
    if m:
        raw = m.group(1)
    s = re.sub(r"[\s\-=]", "", raw).upper()
    if not re.fullmatch(r"[A-Z2-7]{8,128}", s):
        return None
    try:
        base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception:
        return None
    return s


def totp_now(secret: str):
    """Return (6-digit code, seconds left in the current 30s window)."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    now = time.time()
    counter = int(now) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}", 30 - int(now) % 30


# ───────────────────────── GMAIL (IMAP + APP PASSWORD) ─────────────────────────
class AuthFailed(Exception):
    """Gmail refused the address / App Password (wrong, revoked, or 2-Step Verification off)."""


_conns = {}                  # address(lower) -> open IMAP connection, reused between polls
_locks = {}                  # address(lower) -> threading.Lock (one IMAP command stream at a time)
_locks_guard = threading.Lock()
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _is_auth_error(text) -> bool:
    t = str(text).upper()
    return any(s in t for s in ("AUTHENTICATIONFAILED", "INVALID CREDENTIALS",
                                "APPLICATION-SPECIFIC PASSWORD", "WEBLOGIN"))


def _close_quietly(conn):
    try:
        conn.logout()
    except Exception:
        try:
            conn.shutdown()
        except Exception:
            pass


def _discard_conn(key: str):
    conn = _conns.pop(key, None)
    if conn:
        _close_quietly(conn)


def _open_conn(addr: str, app_password: str):
    conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=25)
    try:
        conn.login(addr, app_password)
    except Exception as e:
        _close_quietly(conn)
        if isinstance(e, imaplib.IMAP4.error) and _is_auth_error(e):
            raise AuthFailed(str(e)) from e
        raise
    return conn


def _get_conn(em: dict):
    key = em["email"].lower()
    conn = _conns.get(key)
    if conn is None:
        if not em.get("app_password"):
            raise AuthFailed("no app password stored")  # entry from the old OAuth version
        conn = _open_conn(em["email"], em["app_password"])
        _conns[key] = conn
    return conn


def _fail(key: str, e: Exception) -> Exception:
    """Drop the (possibly broken) connection and classify the error."""
    _discard_conn(key)
    if not isinstance(e, AuthFailed) and isinstance(e, imaplib.IMAP4.error) and _is_auth_error(e):
        return AuthFailed(str(e))
    return e


def _select_inbox(conn):
    typ, _ = conn.select("INBOX", readonly=True)   # readonly -> never marks mail as read
    if typ != "OK":
        raise RuntimeError("Could not open INBOX")
    _, vals = conn.response("UIDVALIDITY")
    try:
        return int(vals[0])
    except (TypeError, ValueError, IndexError):
        return None


def _uid_search(conn, *criteria):
    typ, data = conn.uid("SEARCH", None, *criteria)
    if typ != "OK" or not data or not data[0]:
        return []
    return sorted(int(x) for x in data[0].split())


def _since_str(days: int) -> str:
    d = datetime.now(timezone.utc) - timedelta(days=days)
    return f"{d.day:02d}-{_MONTHS[d.month - 1]}-{d.year}"


def _fetch_message(conn, uid: int):
    typ, data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
    if typ != "OK":
        return None
    for part in data or []:
        if isinstance(part, tuple) and len(part) > 1:
            return email_lib.message_from_bytes(part[1], policy=policy.default)
    return None


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", "ignore")


def message_text(msg) -> str:
    subject = str(msg.get("Subject", "") or "")
    body = ""
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            body = _part_text(part)
        else:
            part = msg.get_body(preferencelist=("html",))
            if part is not None:
                t = _part_text(part)
                t = re.sub(r"(?is)<(style|script).*?</\1>", " ", t)
                t = re.sub(r"<[^>]+>", " ", t)
                body = html.unescape(t)
    except Exception:
        body = ""
    return subject + "\n" + body


def find_otp(text: str):
    m = re.search(r"(?i)(?:otp|code|verification|passcode|password|pin)\D{0,30}?(?<!\d)(\d{4,8})(?!\d)", text)
    if m:
        return m.group(1)
    m = re.search(r"(?<!\d)(\d{4,8})(?!\d)\s*(?:is|হলো)?\s*(?:your|the)", text, re.I)
    if m:
        return m.group(1)
    for m in re.finditer(r"(?<![\d.,])(\d{4,8})(?![\d.,])", text):
        n = m.group(1)
        if len(n) == 4 and 1990 <= int(n) <= 2100:  # skip years
            continue
        return n
    return None


def clean_app_password(raw: str) -> str:
    """Google shows App Passwords as 'abcd efgh ijkl mnop' - spaces are not part of it."""
    return re.sub(r"\s+", "", raw or "")


# ---- blocking workers (run in threads via asyncio.to_thread) ----
def _connect_sync(addr: str, app_password: str):
    """Test-login and return a baseline (last_uid, uidvalidity) so old mail is ignored."""
    key = addr.lower()
    with _lock_for(key):
        _discard_conn(key)
        conn = _open_conn(addr, app_password)      # raises AuthFailed if rejected
        try:
            uidv = _select_inbox(conn)
            ids = _uid_search(conn, "ALL")
        except Exception:
            _close_quietly(conn)
            raise
        _conns[key] = conn
        return (ids[-1] if ids else 0), uidv


def _poll_sync(em: dict):
    """Return list of NEW otps (oldest first) for one connected mailbox."""
    key = em["email"].lower()
    with _lock_for(key):
        try:
            conn = _get_conn(em)
            uidv = _select_inbox(conn)
            if uidv and em.get("uidv") and uidv != em["uidv"]:
                # mailbox was re-created on Google's side: just re-baseline
                ids = _uid_search(conn, "ALL")
                em["uidv"] = uidv
                em["last_uid"] = ids[-1] if ids else 0
                return []
            last = int(em.get("last_uid", 0))
            new = [i for i in _uid_search(conn, "UID", f"{last + 1}:*") if i > last]
            found = []
            for uid in new[-MAX_NEW_PER_POLL:]:
                msg = _fetch_message(conn, uid)
                if msg is not None:
                    otp = find_otp(message_text(msg))
                    if otp:
                        found.append(otp)
            if new:
                em["last_uid"] = new[-1]
            return found
        except Exception as e:
            raise _fail(key, e)


def _latest_sync(em: dict):
    key = em["email"].lower()
    with _lock_for(key):
        try:
            conn = _get_conn(em)
            _select_inbox(conn)
            ids = _uid_search(conn, "SINCE", _since_str(MAIL_LOOKBACK_DAYS))
            for uid in reversed(ids[-8:]):          # newest first
                msg = _fetch_message(conn, uid)
                if msg is not None:
                    otp = find_otp(message_text(msg))
                    if otp:
                        return otp
            return None
        except Exception as e:
            raise _fail(key, e)


def _forget_sync(addr: str):
    key = addr.lower()
    with _lock_for(key):
        _discard_conn(key)


# ---- async wrappers ----
async def connect_mailbox(addr: str, app_password: str):
    return await asyncio.to_thread(_connect_sync, addr, app_password)


async def poll_email(em: dict):
    return await asyncio.to_thread(_poll_sync, em)


async def latest_otp(em: dict):
    return await asyncio.to_thread(_latest_sync, em)


async def forget_conn(addr: str):
    await asyncio.to_thread(_forget_sync, addr)


# ───────────────────────── HELPERS ─────────────────────────
def randomize_case(text: str) -> str:
    return "".join(
        (c.upper() if random.choice([True, False]) else c.lower()) if c.isalpha() else c
        for c in text
    )


def shown_addr(em: dict) -> str:
    return f"{em['display']}@{em['domain']}"


def main_kb(uid: int) -> ReplyKeyboardMarkup:
    b = db["settings"]["buttons"]
    customs = {c["id"]: c for c in db["custom_buttons"]}
    labels = []
    for item in get_order():
        if item in BUILTIN_TEXT:
            if b.get(item, True):
                labels.append(tr(uid, BUILTIN_TEXT[item]))
        else:
            cb = customs.get(item)
            if cb and cb.get("enabled", True):
                labels.append(cb["text"])
    rows = [[KeyboardButton(x) for x in labels[i:i + 2]] for i in range(0, len(labels), 2)]
    if is_admin(uid):
        rows.append([KeyboardButton(BTN_ADMIN)])
    if not rows:
        rows = [[KeyboardButton(tr(uid, "btn_support"))]]
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)


async def edit(q, text, kb=None, parse_mode=None):
    try:
        await q.edit_message_text(text, reply_markup=InlineKeyboardMarkup(kb) if kb else None,
                                  parse_mode=parse_mode, disable_web_page_preview=True)
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            raise


def normalize_url(raw: str):
    raw = raw.strip()
    if raw.startswith("@") and len(raw) > 1:
        return "https://t.me/" + raw[1:]
    if raw.isdigit():
        return f"tg://user?id={raw}"
    if raw.lower().startswith("t.me/"):
        return "https://" + raw
    if raw.lower().startswith(("http://", "https://", "tg://")):
        return raw
    return None


# ───────────────────────── FORCE JOIN ─────────────────────────
async def is_member(bot, uid: int) -> bool:
    try:
        m = await bot.get_chat_member(CHANNEL_ID, uid)
        if m.status in ("member", "administrator", "creator", "owner"):
            return True
        if m.status == "restricted" and getattr(m, "is_member", False):
            return True
        return False
    except TelegramError as e:
        log.error("Channel check failed (is the bot admin in the channel?): %s", e)
        return False


def join_kb(uid: int):
    return InlineKeyboardMarkup([
        [ib(tr(uid, "join_btn"), url=CHANNEL_URL)],
        [ib(tr(uid, "verify_btn"), callback_data="verify")],
    ])


async def gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    if (ADMIN_SKIP_JOIN and is_admin(user.id)) or await is_member(context.bot, user.id):
        return True
    q = update.callback_query
    if q:
        await q.answer(tr(user.id, "not_joined_alert"), show_alert=True)
    else:
        await update.effective_message.reply_text(tr(user.id, "join_text"), reply_markup=join_kb(user.id))
    return False


async def send_welcome(chat_id: int, context: ContextTypes.DEFAULT_TYPE, uid: int):
    await context.bot.send_message(chat_id, tr(uid, "welcome"), parse_mode=ParseMode.HTML,
                                   reply_markup=main_kb(uid))


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    ensure_user(update.effective_user)
    if not await gate(update, context):
        return
    await send_welcome(update.effective_chat.id, context, update.effective_user.id)


async def verify_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = q.from_user.id
    ensure_user(q.from_user)
    if (ADMIN_SKIP_JOIN and is_admin(uid)) or await is_member(context.bot, uid):
        await q.answer(tr(uid, "verified"))
        try:
            await q.message.delete()
        except TelegramError:
            pass
        await send_welcome(q.message.chat_id, context, uid)
    else:
        await q.answer(tr(uid, "not_joined_retry"), show_alert=True)


# ───────────────────────── LANGUAGE ─────────────────────────
def lang_kb(uid: int):
    cur = lang_of(uid)
    names = {"bn": "বাংলা", "en": "English"}
    return [[ib(("✓ " if lg == cur else "") + names[lg], callback_data=f"lang:{lg}") for lg in LANGS]]


async def lang_btn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("state", None)
    if not await gate(update, context):
        return
    ensure_user(update.effective_user)
    uid = update.effective_user.id
    await update.message.reply_text(tr(uid, "lang_title"), parse_mode=ParseMode.HTML,
                                    reply_markup=InlineKeyboardMarkup(lang_kb(uid)))


# ───────────────────────── GMAIL MENUS ─────────────────────────
def gmail_menu(u: dict, uid: int):
    emails = u["emails"]
    if not emails:
        return tr(uid, "gm_none"), [[ib(tr(uid, "add_new"), callback_data="gm_add")]]
    kb = [[ib(f"✉️ {shown_addr(e)}", callback_data=f"em:{i}")] for i, e in enumerate(emails)]
    if len(emails) < MAX_EMAILS_PER_USER:
        kb.append([ib(tr(uid, "add_new"), callback_data="gm_add")])
    return tr(uid, "gm_title", n=len(emails), max=MAX_EMAILS_PER_USER), kb


def email_detail(em: dict, idx: int, uid: int):
    addr = shown_addr(em)
    kb = [
        [ib(f"⧉  {addr}", copy_text=CopyTextButton(text=addr))],
        [ib(tr(uid, "random_again"), callback_data=f"rnd:{idx}"),
         ib(tr(uid, "refresh_otp"), callback_data=f"otp:{idx}")],
        [ib(tr(uid, "back"), callback_data="gm")],
    ]
    return tr(uid, "gm_detail"), kb


def delete_menu(u: dict, uid: int):
    emails = u["emails"]
    if not emails:
        return tr(uid, "del_none"), None
    kb = [[ib(f"🗑 {shown_addr(e)}", callback_data=f"del:{i}")] for i, e in enumerate(emails)]
    if len(emails) > 1:
        kb.append([ib(tr(uid, "delete_all"), callback_data="delall")])
    kb.append([ib(tr(uid, "close"), callback_data="close")])
    return tr(uid, "del_select"), kb


async def gmail_btn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("state", None)
    if not await gate(update, context):
        return
    u = ensure_user(update.effective_user)
    text, kb = gmail_menu(u, update.effective_user.id)
    await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(kb))


async def delete_btn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("state", None)
    if not await gate(update, context):
        return
    u = ensure_user(update.effective_user)
    text, kb = delete_menu(u, update.effective_user.id)
    await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(kb) if kb else None)


async def support_btn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("state", None)
    if not await gate(update, context):
        return
    ensure_user(update.effective_user)
    uid = update.effective_user.id
    if not db["support"]:
        await update.message.reply_text(tr(uid, "sup_none"))
        return
    kb = [[ib(b["text"], url=b["url"])] for b in db["support"]]
    await update.message.reply_text(tr(uid, "sup_title"), reply_markup=InlineKeyboardMarkup(kb))


async def custom_btn(update: Update, context: ContextTypes.DEFAULT_TYPE, cb: dict):
    if not await gate(update, context):
        return
    ensure_user(update.effective_user)
    await update.message.reply_text(
        cb["text"], reply_markup=InlineKeyboardMarkup([[ib("↗ Open", url=cb["url"])]]))


# ───────────────────────── 2FA CARD ─────────────────────────
def tf_prompt_view(uid: int, error: str = None):
    text = (tr(uid, "tf_title") + "\n\n"
            + (f"✕ {error}\n\n" if error else "")
            + tr(uid, "tf_prompt"))
    return text, [[ib(tr(uid, "close"), callback_data="tf_close")]]


def tf_code_view(uid: int, secret: str):
    code, left = totp_now(secret)
    filled = round(left / 30 * 10)
    bar = "▰" * filled + "▱" * (10 - filled)
    text = (tr(uid, "tf_title") + "\n\n"
            f"<code>{code[:3]} {code[3:]}</code>\n\n"
            f"{bar}  {tr(uid, 'tf_valid', s=left)}\n\n"
            f"<i>{tr(uid, 'tf_foot', m=TF_DELETE_SECONDS // 60)}</i>")
    kb = [
        [ib(f"{tr(uid, 'tf_copy')}  {code}", copy_text=CopyTextButton(text=code))],
        [ib(tr(uid, "tf_refresh"), callback_data="tf_ref"),
         ib(tr(uid, "tf_newkey"), callback_data="tf_new")],
        [ib(tr(uid, "close"), callback_data="tf_close")],
    ]
    return text, kb


async def tf_expire_job(context: ContextTypes.DEFAULT_TYPE):
    """Delete the 2FA card and wipe its key from RAM."""
    d = context.job.data
    ud = context.application.user_data.get(d["uid"])
    if ud is not None and ud.get("tf_msg") == d["message_id"]:
        ud.pop("tf_key", None)
        ud.pop("tf_msg", None)
        if ud.get("state") == "await_2fa":
            ud.pop("state", None)
    try:
        await context.bot.delete_message(chat_id=d["chat_id"], message_id=d["message_id"])
    except TelegramError:
        pass


def tf_schedule(context: ContextTypes.DEFAULT_TYPE, uid: int, chat_id: int, message_id: int):
    name = f"tf{uid}"
    for j in context.job_queue.get_jobs_by_name(name):
        j.schedule_removal()
    context.job_queue.run_once(tf_expire_job, TF_DELETE_SECONDS, name=name,
                               data={"uid": uid, "chat_id": chat_id, "message_id": message_id})


def tf_wipe(context: ContextTypes.DEFAULT_TYPE, uid: int):
    context.user_data.pop("tf_key", None)
    context.user_data.pop("tf_msg", None)
    if context.user_data.get("state") == "await_2fa":
        context.user_data.pop("state", None)
    for j in context.job_queue.get_jobs_by_name(f"tf{uid}"):
        j.schedule_removal()


async def tf_btn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("state", None)
    if not await gate(update, context):
        return
    ensure_user(update.effective_user)
    uid = update.effective_user.id
    tf_wipe(context, uid)
    text, kb = tf_prompt_view(uid)
    m = await update.message.reply_text(text, parse_mode=ParseMode.HTML,
                                        reply_markup=InlineKeyboardMarkup(kb))
    context.user_data["state"] = "await_2fa"
    context.user_data["flow_msg"] = m.message_id
    context.user_data["tf_msg"] = m.message_id
    tf_schedule(context, uid, m.chat_id, m.message_id)


async def handle_2fa_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    chat_id = msg.chat_id
    uid = msg.from_user.id
    raw = msg.text or ""
    try:
        await msg.delete()   # never leave the key in the chat
    except TelegramError:
        pass

    secret = parse_totp_secret(raw)
    if not secret:
        text, kb = tf_prompt_view(uid, tr(uid, "tf_bad"))
        return await flow_show(context, chat_id, text, kb)

    text, kb = tf_code_view(uid, secret)
    context.user_data["tf_key"] = secret          # RAM only - never written to disk
    context.user_data.pop("state", None)
    await flow_show(context, chat_id, text, kb)
    mid = context.user_data.get("flow_msg")
    context.user_data["tf_msg"] = mid
    if mid:
        tf_schedule(context, uid, chat_id, mid)


# ───────────────────────── OTP SENDING ─────────────────────────
async def delete_message_job(context: ContextTypes.DEFAULT_TYPE):
    d = context.job.data
    try:
        await context.bot.delete_message(chat_id=d["chat_id"], message_id=d["message_id"])
    except TelegramError:
        pass


async def send_otp(context: ContextTypes.DEFAULT_TYPE, chat_id: int, em: dict, otp: str, uid: int):
    msg = await context.bot.send_message(
        chat_id,
        tr(uid, "otp_found", addr=shown_addr(em)),
        reply_markup=InlineKeyboardMarkup([[ib(f"⧉  {otp}", copy_text=CopyTextButton(text=otp))]]),
    )
    context.job_queue.run_once(delete_message_job, OTP_DELETE_SECONDS,
                               data={"chat_id": chat_id, "message_id": msg.message_id})


async def check_one(context, uid: int, u: dict, em: dict, sem: asyncio.Semaphore):
    otps = []
    async with sem:
        try:
            otps = await poll_email(em)
        except AuthFailed:
            if em in u["emails"]:
                u["emails"].remove(em)
            await forget_conn(em["email"])
            try:
                await context.bot.send_message(uid, "⚠️ " + tr(uid, "signin_removed", email=em["email"]))
            except TelegramError:
                pass
            return
        except Exception as e:
            log.warning("Poll failed for %s: %s", em.get("email"), e)
            return
    for otp in otps:
        try:
            await send_otp(context, uid, em, otp, uid)
        except TelegramError as e:
            log.warning("Could not send OTP to %s: %s", uid, e)


async def otp_job(context: ContextTypes.DEFAULT_TYPE):
    sem = asyncio.Semaphore(10)
    tasks = [check_one(context, int(uid), u, em, sem)
             for uid, u in list(db["users"].items()) for em in list(u["emails"])]
    if tasks:
        await asyncio.gather(*tasks)
        save_db()


# ───────────────────────── ADMIN VIEWS (English) ─────────────────────────
def admin_home():
    users = db["users"]
    total_mail = sum(len(x["emails"]) for x in users.values())
    text = (f"⚙️ Admin Panel\n\nUsers: {len(users)}\n"
            f"Connected emails: {total_mail}\nSupport buttons: {len(db['support'])}\n"
            f"Custom buttons: {len(db['custom_buttons'])}")
    kb = [
        [ib("Users", callback_data="adm_users:0"),
         ib("Broadcast", callback_data="adm_bc")],
        [ib("Message a User", callback_data="adm_dm"),
         ib("Support Buttons", callback_data="adm_sup")],
        [ib("Manage Buttons", callback_data="adm_btns")],
        [ib("✕ Close", callback_data="close")],
    ]
    return text, kb


def users_page(page: int):
    ids = sorted(db["users"], key=lambda k: db["users"][k]["joined"], reverse=True)
    per = 10
    pages = max(1, (len(ids) + per - 1) // per)
    page = max(0, min(page, pages - 1))
    lines = []
    for n, k in enumerate(ids[page * per:(page + 1) * per], start=page * per + 1):
        u = db["users"][k]
        uname = f"@{u['username']}" if u.get("username") else "-"
        lines.append(f"{n}. {u['name']} | {uname} | {k} | ✉️{len(u['emails'])}")
    text = f"Users (page {page + 1}/{pages})\n\n" + ("\n".join(lines) or "No users yet.")
    nav = []
    if page > 0:
        nav.append(ib("‹ Prev", callback_data=f"adm_users:{page - 1}"))
    if page < pages - 1:
        nav.append(ib("Next ›", callback_data=f"adm_users:{page + 1}"))
    kb = ([nav] if nav else []) + [[ib("‹ Back", callback_data="adm")]]
    return text, kb


def sup_admin_view():
    kb = []
    for i, b in enumerate(db["support"]):
        kb.append([ib(f"✎ {b['text']}", callback_data=f"adm_supedit:{i}"),
                   ib("🗑", callback_data=f"adm_supdel:{i}")])
    kb.append([ib("＋ Add Button", callback_data="adm_supadd")])
    kb.append([ib("‹ Back", callback_data="adm")])
    return "Support Buttons\n\n✎ edit • 🗑 delete • ＋ add new\n(Users see these under the Support button.)", kb


def buttons_admin_view():
    b = db["settings"]["buttons"]
    order = get_order()
    customs = {c["id"]: (i, c) for i, c in enumerate(db["custom_buttons"])}

    def mark(flag):
        return "ON ✓" if flag else "OFF ✕"

    kb = []
    last = len(order) - 1
    for pos, item in enumerate(order):
        if item in BUILTIN_TEXT:
            label = f"{BUILTIN_ADMIN_LABEL[item]} — {mark(b.get(item, True))}"
            toggle = f"adm_tgl:{item}"
        else:
            idx, cbtn = customs[item]
            label = f"{cbtn['text']} — {mark(cbtn.get('enabled', True))}"
            toggle = f"adm_ctgl:{idx}"
        kb.append([ib(label, callback_data=toggle),
                   ib("▲" if pos > 0 else "·", callback_data=f"adm_mv:{item}:-1" if pos > 0 else "adm_noop"),
                   ib("▼" if pos < last else "·", callback_data=f"adm_mv:{item}:1" if pos < last else "adm_noop")])
        if item in customs:
            idx = customs[item][0]
            kb.append([ib("✎ Edit", callback_data=f"adm_cedit:{idx}"),
                       ib("🗑 Delete", callback_data=f"adm_cdel:{idx}")])
    kb.append([ib("＋ Add Custom Button", callback_data="adm_cadd")])
    kb.append([ib("‹ Back", callback_data="adm")])
    text = ("Manage Buttons\n\n"
            "Tap a name to turn it ON/OFF for everyone.\n"
            "▲ ▼ move it up or down in the main menu (2 buttons per row).\n"
            "Custom buttons can also be edited or deleted.")
    return text, kb


CANCEL_KB = [[ib("✕ Cancel", callback_data="adm_cancel")]]


async def admin_btn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    if not is_admin(update.effective_user.id):
        return
    text, kb = admin_home()
    await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(kb))


# ───────────────────────── CALLBACK ROUTER ─────────────────────────
async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    data = q.data
    uid = q.from_user.id

    if data == "verify":
        return await verify_cb(update, context)
    if not await gate(update, context):
        return
    u = ensure_user(q.from_user)
    await q.answer()

    if data == "close":
        try:
            await q.message.delete()
        except TelegramError:
            pass

    # ---------- Language ----------
    elif data.startswith("lang:"):
        lg = data.split(":")[1]
        if lg in T:
            u["lang"] = lg
            save_db()
            try:
                await q.message.delete()
            except TelegramError:
                pass
            await context.bot.send_message(q.message.chat_id, tr(uid, "lang_set"), reply_markup=main_kb(uid))
            await send_welcome(q.message.chat_id, context, uid)

    # ---------- 2FA ----------
    elif data == "tf_close":
        tf_wipe(context, uid)
        try:
            await q.message.delete()
        except TelegramError:
            pass

    elif data == "tf_new":
        tf_wipe(context, uid)
        text, kb = tf_prompt_view(uid)
        await edit(q, text, kb, parse_mode=ParseMode.HTML)
        context.user_data["state"] = "await_2fa"
        context.user_data["flow_msg"] = q.message.message_id
        context.user_data["tf_msg"] = q.message.message_id
        tf_schedule(context, uid, q.message.chat_id, q.message.message_id)

    elif data == "tf_ref":
        secret = context.user_data.get("tf_key")
        if not secret:
            return await edit(q, tr(uid, "tf_expired"),
                              [[ib(tr(uid, "close"), callback_data="tf_close")]], parse_mode=ParseMode.HTML)
        text, kb = tf_code_view(uid, secret)
        await edit(q, text, kb, parse_mode=ParseMode.HTML)

    # ---------- Gmail ----------
    elif data == "gm":
        context.user_data.pop("state", None)
        context.user_data.pop("new_email", None)
        context.user_data.pop("flow_msg", None)
        text, kb = gmail_menu(u, uid)
        await edit(q, text, kb)

    elif data == "gm_add":
        if len(u["emails"]) >= MAX_EMAILS_PER_USER:
            return await edit(q, "⚠️ " + tr(uid, "limit"),
                              [[ib(tr(uid, "back"), callback_data="gm")]])
        context.user_data["state"] = "await_email"
        context.user_data["flow_msg"] = q.message.message_id   # the wizard lives in this one message
        context.user_data.pop("new_email", None)
        text, kb = wizard_step1(u, uid)
        await edit(q, text, kb, parse_mode=ParseMode.HTML)

    elif data.startswith("em:"):
        i = int(data.split(":")[1])
        if i < len(u["emails"]):
            text, kb = email_detail(u["emails"][i], i, uid)
            await edit(q, text, kb)

    elif data.startswith("rnd:"):
        i = int(data.split(":")[1])
        if i < len(u["emails"]):
            em = u["emails"][i]
            em["display"] = randomize_case(em["display"])
            save_db()
            text, kb = email_detail(em, i, uid)
            await edit(q, text, kb)

    elif data.startswith("otp:"):
        i = int(data.split(":")[1])
        if i >= len(u["emails"]):
            return
        em = u["emails"][i]
        try:
            otp = await latest_otp(em)
        except AuthFailed:
            u["emails"].remove(em)
            save_db()
            await forget_conn(em["email"])
            return await context.bot.send_message(uid, "⚠️ " + tr(uid, "signin_short", email=em["email"]))
        except Exception as e:
            log.warning("Refresh failed: %s", e)
            otp = None
        if otp:
            await send_otp(context, q.message.chat_id, em, otp, uid)
        else:
            m = await context.bot.send_message(q.message.chat_id, tr(uid, "otp_none"))
            context.job_queue.run_once(delete_message_job, OTP_DELETE_SECONDS,
                                       data={"chat_id": m.chat_id, "message_id": m.message_id})

    # ---------- Delete mail ----------
    elif data.startswith("del:"):
        i = int(data.split(":")[1])
        if i < len(u["emails"]):
            removed = u["emails"].pop(i)
            save_db()
            await forget_conn(removed["email"])
        text, kb = delete_menu(u, uid)
        await edit(q, text if kb else tr(uid, "del_done_none"), kb)

    elif data == "delall":
        removed = list(u["emails"])
        u["emails"].clear()
        save_db()
        for r in removed:
            await forget_conn(r["email"])
        await edit(q, tr(uid, "del_all_done"))

    # ---------- Admin ----------
    elif data.startswith("adm"):
        if not is_admin(uid):
            return
        await admin_callbacks(update, context, data)


async def admin_callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE, data: str):
    q = update.callback_query
    uid = q.from_user.id

    if data in ("adm", "adm_cancel"):
        context.user_data.clear()
        text, kb = admin_home()
        await edit(q, text, kb)

    elif data.startswith("adm_users:"):
        text, kb = users_page(int(data.split(":")[1]))
        await edit(q, text, kb)

    elif data == "adm_bc":
        context.user_data["state"] = "bc"
        await edit(q, "Broadcast\n\nSend the message you want to deliver to ALL users "
                      "(text, photo, video… anything).", CANCEL_KB)

    elif data == "adm_dm":
        context.user_data["state"] = "dm_id"
        await edit(q, "Send the Telegram ID of the user:", CANCEL_KB)

    elif data == "adm_sup":
        context.user_data.clear()
        text, kb = sup_admin_view()
        await edit(q, text, kb)

    elif data == "adm_supadd":
        context.user_data.clear()
        context.user_data["state"] = "sup_name"
        await edit(q, "New support button\n\nSend the button NAME (e.g. “💬 Contact Admin”):", CANCEL_KB)

    elif data.startswith("adm_supedit:"):
        i = int(data.split(":")[1])
        if i < len(db["support"]):
            context.user_data.clear()
            context.user_data["state"] = "sup_name"
            context.user_data["sup_idx"] = i
            await edit(q, f"Editing “{db['support'][i]['text']}”\n\nSend the new button NAME:", CANCEL_KB)

    elif data.startswith("adm_supdel:"):
        i = int(data.split(":")[1])
        if i < len(db["support"]):
            db["support"].pop(i)
            save_db()
        text, kb = sup_admin_view()
        await edit(q, text, kb)

    # ---------- Manage Buttons ----------
    elif data == "adm_btns":
        context.user_data.clear()
        text, kb = buttons_admin_view()
        await edit(q, text, kb)

    elif data == "adm_noop":
        pass

    elif data.startswith("adm_mv:"):
        _, item, d = data.split(":")
        order = get_order()
        if item in order:
            i = order.index(item)
            j = i + int(d)
            if 0 <= j < len(order):
                order[i], order[j] = order[j], order[i]
                save_db()
        text, kb = buttons_admin_view()
        await edit(q, text, kb)

    elif data.startswith("adm_tgl:"):
        key = data.split(":")[1]
        b = db["settings"]["buttons"]
        b[key] = not b.get(key, True)
        save_db()
        text, kb = buttons_admin_view()
        await edit(q, text, kb)

    elif data.startswith("adm_ctgl:"):
        i = int(data.split(":")[1])
        if i < len(db["custom_buttons"]):
            cb = db["custom_buttons"][i]
            cb["enabled"] = not cb.get("enabled", True)
            save_db()
        text, kb = buttons_admin_view()
        await edit(q, text, kb)

    elif data == "adm_cadd":
        context.user_data.clear()
        context.user_data["state"] = "cbtn_name"
        await edit(q, "New custom button\n\nSend the button TEXT exactly as it should "
                      "appear on the main menu (e.g. “🌐 Our Website”):", CANCEL_KB)

    elif data.startswith("adm_cedit:"):
        i = int(data.split(":")[1])
        if i < len(db["custom_buttons"]):
            context.user_data.clear()
            context.user_data["state"] = "cbtn_name"
            context.user_data["cbtn_idx"] = i
            await edit(q, f"Editing “{db['custom_buttons'][i]['text']}”\n\nSend the new button TEXT:", CANCEL_KB)

    elif data.startswith("adm_cdel:"):
        i = int(data.split(":")[1])
        if i < len(db["custom_buttons"]):
            db["custom_buttons"].pop(i)
            save_db()
        text, kb = buttons_admin_view()
        await edit(q, text, kb)


# ───────────────────────── TEXT / STATE ROUTER ─────────────────────────
async def run_broadcast(context: ContextTypes.DEFAULT_TYPE, admin_chat: int, from_chat: int, msg_id: int):
    ok = fail = 0
    for uid in list(db["users"].keys()):
        try:
            await context.bot.copy_message(int(uid), from_chat, msg_id)
            ok += 1
        except TelegramError:
            fail += 1
        await asyncio.sleep(0.05)
    await context.bot.send_message(admin_chat, f"Broadcast finished.\n✓ Sent: {ok}\n✕ Failed: {fail}")


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@(gmail\.com|googlemail\.com)$", re.I)


def user_back_kb(uid: int):
    return [[ib(tr(uid, "back"), callback_data="gm")]]


# ---- "Add New Email" wizard: one message that is edited step by step ----
def _bar(n: int) -> str:
    return "▰" * n + "▱" * (3 - n)


def _wiz(uid: int, n: int, body_key: str, error: str = None) -> str:
    return (f"<b>{tr(uid, 'w_step', n=n)}</b>\n\n"
            + (f"✕ {error}\n\n" if error else "")
            + tr(uid, body_key))


def wizard_step1(u: dict, uid: int, error: str = None):
    return _wiz(uid, 1, "w1_body", error), [[ib(tr(uid, "back"), callback_data="gm")]]


def wizard_step2(uid: int, error: str = None):
    return _wiz(uid, 2, "w2_body", error), [[ib(tr(uid, "back"), callback_data="gm")]]


def wizard_step3(uid: int, error: str = None):
    kb = [[ib(tr(uid, "w_create_pw"), url=APP_PASSWORD_URL)],
          [ib(tr(uid, "back"), callback_data="gm")]]
    return _wiz(uid, 3, "w3_body", error), kb


async def flow_show(context: ContextTypes.DEFAULT_TYPE, chat_id: int, text: str, kb=None):
    """Update the wizard message in place; fall back to a fresh message if it is gone."""
    markup = InlineKeyboardMarkup(kb) if kb else None
    mid = context.user_data.get("flow_msg")
    if mid:
        try:
            await context.bot.edit_message_text(text, chat_id=chat_id, message_id=mid,
                                                parse_mode=ParseMode.HTML, reply_markup=markup,
                                                disable_web_page_preview=True)
            return
        except BadRequest as e:
            if "not modified" in str(e).lower():
                return
        except TelegramError:
            pass
    m = await context.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML, reply_markup=markup,
                                       disable_web_page_preview=True)
    context.user_data["flow_msg"] = m.message_id


async def handle_email_input(update: Update, context: ContextTypes.DEFAULT_TYPE, u: dict):
    """Step 1: the user sends the Gmail address -> show step 2 (Create App Password)."""
    msg = update.message
    chat_id = msg.chat_id
    uid = msg.from_user.id
    addr = (msg.text or "").strip().lower()
    try:
        await msg.delete()   # keep the chat clean
    except TelegramError:
        pass

    if not EMAIL_RE.match(addr):
        text, kb = wizard_step1(u, uid, tr(uid, "w_bad_email"))
        return await flow_show(context, chat_id, text, kb)

    already = any(e["email"].lower() == addr for e in u["emails"])
    if not already and len(u["emails"]) >= MAX_EMAILS_PER_USER:
        context.user_data.pop("state", None)
        return await flow_show(context, chat_id, "⚠️ " + tr(uid, "limit"), user_back_kb(uid))

    context.user_data["new_email"] = addr
    context.user_data["state"] = "await_name"
    text, kb = wizard_step2(uid)
    await flow_show(context, chat_id, text, kb)


async def handle_app_name(update: Update, context: ContextTypes.DEFAULT_TYPE, u: dict):
    """Step 2: the user sends the app name -> show step 3 (App Password)."""
    msg = update.message
    chat_id = msg.chat_id
    uid = msg.from_user.id
    ok = bool((msg.text or "").strip())
    try:
        await msg.delete()
    except TelegramError:
        pass
    if not ok:
        text, kb = wizard_step2(uid, tr(uid, "w_bad_name"))
        return await flow_show(context, chat_id, text, kb)
    context.user_data["state"] = "await_pw"
    text, kb = wizard_step3(uid)
    await flow_show(context, chat_id, text, kb)


async def handle_app_password(update: Update, context: ContextTypes.DEFAULT_TYPE, u: dict):
    """Step 2 -> 3: the user sends the App Password; verify it and connect."""
    msg = update.message
    chat_id = msg.chat_id
    uid = msg.from_user.id
    raw = msg.text or ""
    try:
        await msg.delete()  # never leave the password in the chat
    except TelegramError:
        pass

    addr = context.user_data.get("new_email")
    if not addr:
        context.user_data.pop("state", None)
        return await flow_show(context, chat_id, tr(uid, "w_expired"), user_back_kb(uid))

    pw = clean_app_password(raw)
    if not re.fullmatch(r"[A-Za-z0-9]{16}", pw):
        text, kb = wizard_step3(uid, tr(uid, "w_bad_pw"))
        return await flow_show(context, chat_id, text, kb)

    existing = next((e for e in u["emails"] if e["email"].lower() == addr), None)
    if not existing and len(u["emails"]) >= MAX_EMAILS_PER_USER:
        context.user_data.pop("state", None)
        return await flow_show(context, chat_id, "⚠️ " + tr(uid, "limit"), user_back_kb(uid))

    await flow_show(context, chat_id,
                    f"<b>{tr(uid, 'w_step', n=3)}</b>\n\n"
                    + tr(uid, "w_connecting", addr=html.escape(addr)))
    try:
        last_uid, uidv = await connect_mailbox(addr, pw)
    except AuthFailed:
        text, kb = wizard_step3(uid, tr(uid, "w_rejected"))
        return await flow_show(context, chat_id, text, kb)
    except Exception as e:
        log.warning("IMAP connect failed for %s: %s", addr, e)
        text, kb = wizard_step3(uid, tr(uid, "w_unreachable"))
        return await flow_show(context, chat_id, text, kb)

    local, domain = addr.split("@")
    if existing:
        existing.pop("refresh_token", None)   # leftovers from the old OAuth version
        existing.pop("seen", None)
        existing.update({"app_password": pw, "last_uid": last_uid, "uidv": uidv})
    else:
        u["emails"].append({"email": addr, "app_password": pw, "display": local,
                            "domain": domain, "last_uid": last_uid, "uidv": uidv})
    save_db()

    await flow_show(context, chat_id,
                    f"{tr(uid, 'w_connected')}\n\n"
                    + tr(uid, "w_connected_body", addr=html.escape(addr),
                         n=len(u["emails"]), max=MAX_EMAILS_PER_USER))
    context.user_data.clear()
    text, kb = gmail_menu(u, uid)
    await context.bot.send_message(chat_id, text, reply_markup=InlineKeyboardMarkup(kb))


async def text_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    if not msg:
        return
    state = context.user_data.get("state")
    uid = msg.from_user.id

    # custom main-menu buttons (no active state needed)
    if not state:
        for cb in db["custom_buttons"]:
            if cb.get("enabled", True) and msg.text == cb["text"]:
                return await custom_btn(update, context, cb)
        return

    if not await gate(update, context):
        return
    u = ensure_user(msg.from_user)

    if state == "await_email":
        return await handle_email_input(update, context, u)

    if state == "await_name":
        return await handle_app_name(update, context, u)

    if state == "await_pw":
        return await handle_app_password(update, context, u)

    if state == "await_2fa":
        return await handle_2fa_input(update, context)

    if not is_admin(uid):
        return

    if state == "bc":
        context.user_data.clear()
        await msg.reply_text("⏳ Broadcast started...")
        context.application.create_task(run_broadcast(context, msg.chat_id, msg.chat_id, msg.message_id))

    elif state == "dm_id":
        txt = (msg.text or "").strip()
        if not txt.isdigit() or txt not in db["users"]:
            return await msg.reply_text("✕ User not found in the bot. Send a valid Telegram ID:",
                                        reply_markup=InlineKeyboardMarkup(CANCEL_KB))
        context.user_data["dm_target"] = int(txt)
        context.user_data["state"] = "dm_msg"
        await msg.reply_text(f"✓ User: {db['users'][txt]['name']}\n\nNow send the message to deliver:",
                             reply_markup=InlineKeyboardMarkup(CANCEL_KB))

    elif state == "dm_msg":
        target = context.user_data.pop("dm_target", None)
        context.user_data.clear()
        try:
            await context.bot.copy_message(target, msg.chat_id, msg.message_id)
            await msg.reply_text("✓ Message sent.")
        except TelegramError as e:
            await msg.reply_text(f"✕ Could not send: {e}")

    elif state == "sup_name":
        name = (msg.text or "").strip()
        if not name:
            return
        context.user_data["sup_name"] = name[:40]
        context.user_data["state"] = "sup_url"
        await msg.reply_text("Now send the LINK for this button.\n\nAccepted:\n"
                             "• https://t.me/yourchannel\n• @username\n• a numeric Telegram ID\n• any https:// link",
                             reply_markup=InlineKeyboardMarkup(CANCEL_KB))

    elif state == "sup_url":
        url = normalize_url(msg.text or "")
        if not url:
            return await msg.reply_text("✕ Invalid link. Try again:", reply_markup=InlineKeyboardMarkup(CANCEL_KB))
        item = {"text": context.user_data["sup_name"], "url": url}
        idx = context.user_data.get("sup_idx")
        if idx is not None and idx < len(db["support"]):
            db["support"][idx] = item
        else:
            db["support"].append(item)
        save_db()
        context.user_data.clear()
        text, kb = sup_admin_view()
        await msg.reply_text("✓ Saved.\n\n" + text, reply_markup=InlineKeyboardMarkup(kb))

    elif state == "cbtn_name":
        name = (msg.text or "").strip()
        if not name:
            return
        context.user_data["cbtn_name"] = name[:40]
        context.user_data["state"] = "cbtn_url"
        await msg.reply_text("Now send the LINK this button should open (https://... or @username):",
                             reply_markup=InlineKeyboardMarkup(CANCEL_KB))

    elif state == "cbtn_url":
        url = normalize_url(msg.text or "")
        if not url:
            return await msg.reply_text("✕ Invalid link. Try again:", reply_markup=InlineKeyboardMarkup(CANCEL_KB))
        item = {"text": context.user_data["cbtn_name"], "url": url, "enabled": True, "id": new_cid()}
        idx = context.user_data.get("cbtn_idx")
        if idx is not None and idx < len(db["custom_buttons"]):
            item["enabled"] = db["custom_buttons"][idx].get("enabled", True)
            item["id"] = db["custom_buttons"][idx].get("id", item["id"])
            db["custom_buttons"][idx] = item
        else:
            db["custom_buttons"].append(item)
        save_db()
        context.user_data.clear()
        text, kb = buttons_admin_view()
        await msg.reply_text("✓ Saved. The main menu will refresh next time the user opens it.\n\n" + text,
                             reply_markup=InlineKeyboardMarkup(kb))
        # refresh this admin's own keyboard right away
        await msg.reply_text("Menu updated:", reply_markup=main_kb(uid))


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    tf_wipe(context, uid)
    context.user_data.clear()
    await update.message.reply_text("✕", reply_markup=main_kb(uid))


# ───────────────────────── MAIN ─────────────────────────
def main():
    load_db()
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(MessageHandler(filters.Text(all_labels("btn_gmail")), gmail_btn))
    app.add_handler(MessageHandler(filters.Text(all_labels("btn_2fa")), tf_btn))
    app.add_handler(MessageHandler(filters.Text(all_labels("btn_delete")), delete_btn))
    app.add_handler(MessageHandler(filters.Text(all_labels("btn_support")), support_btn))
    app.add_handler(MessageHandler(filters.Text(all_labels("btn_lang")), lang_btn))
    app.add_handler(MessageHandler(filters.Text([BTN_ADMIN]), admin_btn))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND & ~filters.StatusUpdate.ALL, text_router))

    app.job_queue.run_repeating(otp_job, interval=CHECK_INTERVAL, first=5, name="otp_job")

    print("Bot is running successfully...")
    app.run_polling()


if __name__ == "__main__":
    main()

# NOTE on CHECK_INTERVAL = 2:
# Every 2 seconds the bot runs a cheap IMAP check (SELECT + SEARCH) per connected
# mailbox over ONE persistent connection, and fetches a message only when a truly
# new one arrives. That is fine for a moderate number of mailboxes. With a very
# large number, Gmail may throttle logins / bandwidth ("Too many simultaneous
# connections", "Account exceeded command or bandwidth limits"). If you see such
# errors in the logs, raise CHECK_INTERVAL (e.g. 5-10s).
#
# SECURITY: Gmail App Passwords are stored in plain text in data.json. Keep that file
# private and never commit it anywhere. 2FA keys are NOT stored - RAM only.
