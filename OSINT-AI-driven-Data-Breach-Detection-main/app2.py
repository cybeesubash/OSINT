import os
import time
import json
import base64
import hashlib
import re
import threading
import smtplib
import subprocess
import asyncio
import csv
import io
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from collections import deque

import cv2
import numpy as np
import requests
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ---------- CONFIG ----------
HIBP_KEY = os.environ.get('HIBP_API_KEY', '')
IMAGGA_KEY = os.environ.get('IMAGGA_API_KEY', '')
IMAGGA_SECRET = os.environ.get('IMAGGA_SECRET', '')
GOOGLE_VISION_API_KEY = os.environ.get('GOOGLE_VISION_API_KEY', '')
ALERT_EMAIL = os.environ.get('ALERT_EMAIL', '')
ALERT_PASSWORD = os.environ.get('ALERT_PASSWORD', '')

# Optional PIL for EXIF
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_OK = True
except ImportError:
    PIL_OK = False

# Optional ReportLab for PDF
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ---------- FLASK APP ----------
app = Flask(__name__, template_folder='templates')
CORS(app)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
app.secret_key = os.environ.get('SECRET_KEY', 'osint_shield_2024')

ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'webp', 'gif', 'mp4', 'avi', 'mov'}
for d in ['uploads', 'reports', 'instance']:
    os.makedirs(d, exist_ok=True)

# ---------- DATABASE ----------
_db_lock = threading.Lock()
SCANS_FILE = os.path.join('instance', 'scans.json')

def init_db():
    os.makedirs('instance', exist_ok=True)
    with _db_lock:
        if not os.path.exists(SCANS_FILE):
            with open(SCANS_FILE, 'w') as f:
                json.dump([], f)
        log("INFO", "Local JSON database initialized successfully.")

# ---------- LOGGING ----------
_logs = deque(maxlen=300)
_log_lock = threading.Lock()

def log(level, msg):
    with _log_lock:
        _logs.append({
            "time": datetime.now().strftime('%H:%M:%S'),
            "level": level,
            "msg": msg
        })

init_db()

# ---------- HELPER FUNCTIONS ----------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def save_scan(scan_type, input_data, results, risk_score, risk_level):
    with _db_lock:
        try:
            if os.path.exists(SCANS_FILE):
                with open(SCANS_FILE, 'r') as f:
                    scans = json.load(f)
            else:
                scans = []
            
            scan_id = len(scans) + 1
            data = {
                "id": scan_id,
                "scan_type": scan_type,
                "input_data": str(input_data)[:500],
                "results": json.dumps(results, default=str),
                "risk_score": float(risk_score),
                "risk_level": risk_level,
                "scanned_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "report_path": None
            }
            scans.append(data)
            with open(SCANS_FILE, 'w') as f:
                json.dump(scans, f, indent=4)
            log("INFO", f"Scan #{scan_id} saved to local storage, type={scan_type}, risk={risk_level}")
            return scan_id
        except Exception as e:
            log("ERROR", f"Failed to save scan to local storage: {e}")
            return None

def get_scan(scan_id):
    with _db_lock:
        try:
            if not os.path.exists(SCANS_FILE):
                return None
            with open(SCANS_FILE, 'r') as f:
                scans = json.load(f)
            for row in scans:
                if row['id'] == int(scan_id):
                    return {
                        'id': row['id'],
                        'type': row['scan_type'],
                        'input': row['input_data'],
                        'results': json.loads(row['results']) if isinstance(row['results'], str) else row['results'],
                        'score': row['risk_score'],
                        'risk': row['risk_level'],
                        'time': row['scanned_at'],
                        'report_path': row.get('report_path')
                    }
        except Exception as e:
            log("ERROR", f"Failed to read scan from local storage: {e}")
        return None

def update_scan_report_path(scan_id, filepath):
    with _db_lock:
        try:
            if not os.path.exists(SCANS_FILE):
                return
            with open(SCANS_FILE, 'r') as f:
                scans = json.load(f)
            for row in scans:
                if row['id'] == int(scan_id):
                    row['report_path'] = filepath
                    break
            with open(SCANS_FILE, 'w') as f:
                json.dump(scans, f, indent=4)
        except Exception as e:
            log("ERROR", f"Failed to update scan report path: {e}")

def get_all_scans():
    with _db_lock:
        try:
            if not os.path.exists(SCANS_FILE):
                return []
            with open(SCANS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log("ERROR", f"Failed to load all scans: {e}")
            return []

# ---------- GPS EXIF ----------
def get_decimal_from_dms(dms, ref):
    degrees, minutes, seconds = dms
    decimal = degrees + minutes/60 + seconds/3600
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal

def extract_gps(exif_data):
    if not exif_data:
        return None
    gps_info = {}
    for tag, value in exif_data.items():
        decoded = TAGS.get(tag, tag)
        if decoded == "GPSInfo":
            for gps_tag in value:
                sub_decoded = GPSTAGS.get(gps_tag, gps_tag)
                gps_info[sub_decoded] = value[gps_tag]
    if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
        lat = get_decimal_from_dms(gps_info['GPSLatitude'], gps_info.get('GPSLatitudeRef', 'N'))
        lon = get_decimal_from_dms(gps_info['GPSLongitude'], gps_info.get('GPSLongitudeRef', 'E'))
        alt = gps_info.get('GPSAltitude', None)
        return {
            'latitude': lat,
            'longitude': lon,
            'altitude': float(alt) if alt else None,
            'maps_url': f"https://www.google.com/maps?q={lat},{lon}"
        }
    return None

# ---------- DEEPFAKE ----------
def deepfake_image(image_path):
    img = cv2.imread(image_path)
    if img is None:
        return {"error": "Cannot read image"}
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = img.shape[:2]
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    faces = face_cascade.detectMultiScale(gray, 1.1, 5)
    laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
    noise_score = min(laplacian_var / 500, 1.0) if laplacian_var else 0.5
    edges = cv2.Canny(gray, 50, 150)
    edge_density = np.sum(edges > 0) / (h * w)
    b,g,r = cv2.split(img)
    color_anomaly = min((abs(np.std(b)-np.std(g)) + abs(np.std(g)-np.std(r))) / 30, 1.0)
    dct_vals = []
    for i in range(0, min(h,64),8):
        for j in range(0, min(w,64),8):
            block = gray[i:i+8, j:j+8].astype(np.float32)
            if block.shape == (8,8):
                dct_vals.append(float(np.std(cv2.dct(block))))
    compression = min(np.mean(dct_vals)/50 if dct_vals else 0.5, 1.0)
    face_blur = 0.5
    for (x,y,fw,fh) in faces:
        face_region = gray[y:y+fh, x:x+fw]
        if face_region.size > 0:
            face_blur = min(cv2.Laplacian(face_region, cv2.CV_64F).var() / 200, 1.0)
    score = round((
        (1-face_blur)*0.30 + color_anomaly*0.25 + (1-noise_score)*0.20 + compression*0.15 + edge_density*0.10
    )*100, 2)
    verdict = "DEEPFAKE DETECTED" if score > 55 else "LIKELY AUTHENTIC"
    if score > 80: risk = "CRITICAL"
    elif score > 60: risk = "HIGH"
    elif score > 40: risk = "MEDIUM"
    else: risk = "LOW"
    return {
        "deepfake_score": score,
        "verdict": verdict,
        "risk_level": risk,
        "face_count": len(faces),
        "type": "image",
        "metrics": {
            "blur_score": round((1-face_blur)*100,1),
            "color_anomaly": round(color_anomaly*100,1),
            "noise_score": round(noise_score*100,1),
            "compression": round(compression*100,1),
            "edge_density": round(edge_density*100,1)
        }
    }

def deepfake_video(video_path):
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return {"error": "Cannot open video"}
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    duration = round(total_frames/fps,1) if fps>0 else 0
    scores = []
    frame_count = 0
    sample_rate = max(1, total_frames//10)
    while True:
        ret, frame = cap.read()
        if not ret: break
        if frame_count % sample_rate == 0:
            temp_path = f"uploads/temp_{frame_count}.jpg"
            cv2.imwrite(temp_path, frame)
            res = deepfake_image(temp_path)
            if "deepfake_score" in res:
                scores.append(res["deepfake_score"])
            try: os.remove(temp_path)
            except: pass
        frame_count += 1
    cap.release()
    avg_score = round(float(np.mean(scores)),2) if scores else 0
    verdict = "DEEPFAKE DETECTED" if avg_score > 55 else "LIKELY AUTHENTIC"
    if avg_score > 80: risk = "CRITICAL"
    elif avg_score > 60: risk = "HIGH"
    elif avg_score > 40: risk = "MEDIUM"
    else: risk = "LOW"
    return {
        "deepfake_score": avg_score,
        "verdict": verdict,
        "risk_level": risk,
        "frames_analyzed": len(scores),
        "duration_sec": duration,
        "total_frames": total_frames,
        "type": "video"
    }

# ---------- IMAGGA (mock if no key) ----------
def imagga_analyze(image_path):
    result = {
        "tags": [],
        "face_count": 0,
        "nsfw": None,
        "colors": [],
        "api_status": "ok"
    }
    if not IMAGGA_SECRET:
        result.update({
            "api_status": "mock",
            "api_note": "Imagga not configured – mock data.",
            "tags": [{"tag":"person","confidence":98},{"tag":"selfie","confidence":85}],
            "face_count": 1,
            "nsfw": {"label":"SFW","confidence":99},
            "colors": [{"color":"#8B4513","name":"brown","percent":35}]
        })
        return result
    auth = (IMAGGA_KEY, IMAGGA_SECRET)
    try:
        with open(image_path,'rb') as f:
            upload = requests.post("https://api.imagga.com/v2/uploads", auth=auth, files={"image":f}, timeout=20)
        if upload.status_code != 200:
            result.update({"api_status":"error","api_note":f"Upload failed {upload.status_code}"})
            return result
        upload_id = upload.json()["result"]["upload_id"]
        # tags
        tags_resp = requests.get("https://api.imagga.com/v2/tags", auth=auth, params={"image_upload_id":upload_id,"limit":20}, timeout=15)
        if tags_resp.status_code==200:
            result["tags"] = [{"tag":t["tag"]["en"],"confidence":round(t["confidence"],1)} for t in tags_resp.json()["result"]["tags"]]
        # faces
        faces_resp = requests.get("https://api.imagga.com/v2/faces/detections", auth=auth, params={"image_upload_id":upload_id}, timeout=15)
        if faces_resp.status_code==200:
            faces_data = faces_resp.json()["result"]["faces"]
            result["face_count"] = len(faces_data)
        # nsfw
        nsfw_resp = requests.get("https://api.imagga.com/v2/categories/nsfw_beta", auth=auth, params={"image_upload_id":upload_id}, timeout=15)
        if nsfw_resp.status_code==200:
            for cat in nsfw_resp.json()["result"]["categories"]:
                if cat["name"]["en"] in ["nsfw","sfw"]:
                    result["nsfw"] = {"label":cat["name"]["en"].upper(), "confidence":round(cat["confidence"],1)}
        # colors
        colors_resp = requests.get("https://api.imagga.com/v2/colors", auth=auth, params={"image_upload_id":upload_id}, timeout=15)
        if colors_resp.status_code==200:
            result["colors"] = [{"color":c["html_code"],"name":c["closest_palette_color"],"percent":round(c["percent"],1)} for c in colors_resp.json()["result"]["colors"]["foreground_colors"][:5]]
        # cleanup
        requests.delete(f"https://api.imagga.com/v2/uploads/{upload_id}", auth=auth, timeout=8)
    except Exception as e:
        result.update({"api_status":"exception","api_note":str(e)})
    return result

# ---------- REVERSE IMAGE (Google Vision) ----------
def reverse_search(image_path):
    result = {
        "best_guess_labels": [],
        "pages_with_matching": [],
        "visually_similar_images": [],
        "full_matching_images": [],
        "partial_matching_images": [],
        "total_results": 0,
        "api_status": "ok",
        "engine_used": "Google Vision"
    }
    if not GOOGLE_VISION_API_KEY:
        result.update({
            "api_status": "mock",
            "api_note": "Google Vision not configured – mock data.",
            "best_guess_labels": ["person", "selfie", "portrait"],
            "pages_with_matching": [
                {"url": "https://www.instagram.com/p/abc123/", "title": "Instagram Post"},
                {"url": "https://www.facebook.com/photo.php?fbid=123", "title": "Facebook Photo"},
                {"url": "https://twitter.com/user/status/456", "title": "Tweet"}
            ],
            "visually_similar_images": [
                {"url": "https://via.placeholder.com/150?text=Sim1"},
                {"url": "https://via.placeholder.com/150?text=Sim2"}
            ],
            "total_results": 5
        })
        return result
    try:
        with open(image_path,'rb') as f:
            encoded = base64.b64encode(f.read()).decode('UTF-8')
        url = f"https://vision.googleapis.com/v1/images:annotate?key={GOOGLE_VISION_API_KEY}"
        payload = {
            "requests": [{
                "image": {"content": encoded},
                "features": [{"type": "WEB_DETECTION", "maxResults": 100}]
            }]
        }
        resp = requests.post(url, json=payload, timeout=30)
        data = resp.json()
        if resp.status_code != 200:
            result.update({"api_status":"error","api_error":data.get('error',{}).get('message','Unknown')})
            return result
        web = data['responses'][0].get('webDetection', {})
        # best guess
        result["best_guess_labels"] = [label.get('label') for label in web.get('bestGuessLabels', [])]
        # pages with matching
        for page in web.get('pagesWithMatchingImages', []):
            result["pages_with_matching"].append({
                "url": page.get('url'),
                "title": page.get('pageTitle', 'No title')
            })
        # visually similar
        for img in web.get('visuallySimilarImages', []):
            result["visually_similar_images"].append({"url": img.get('url')})
        # full matching
        for img in web.get('fullMatchingImages', []):
            result["full_matching_images"].append({"url": img.get('url')})
        # partial matching
        for img in web.get('partialMatchingImages', []):
            result["partial_matching_images"].append({"url": img.get('url')})
        result["total_results"] = len(result["pages_with_matching"]) + len(result["visually_similar_images"])
    except Exception as e:
        result.update({"api_status":"exception","api_error":str(e)})
    return result

# ---------- HIBP BREACH CHECK ----------
def check_breach(email):
    result = {
        "email": email,
        "breaches": [],
        "pastes": [],
        "breach_count": 0,
        "paste_count": 0,
        "is_leaked": False,
        "password_exposure": 0,
        "api_status": "ok"
    }
    if not HIBP_KEY:
        result.update({
            "api_status": "mock",
            "api_note": "HIBP not configured – mock data.",
            "breaches": [
                {
                    "name": "Adobe",
                    "domain": "adobe.com",
                    "breach_date": "2013-10-04",
                    "description": "In October 2013, 153 million Adobe accounts were breached...",
                    "data_classes": ["Email addresses", "Password hints", "Passwords"],
                    "logo_path": "https://haveibeenpwned.com/Content/Images/Logos/adobe.png"
                },
                {
                    "name": "LinkedIn",
                    "domain": "linkedin.com",
                    "breach_date": "2012-05-05",
                    "description": "In 2012, LinkedIn suffered a data breach...",
                    "data_classes": ["Email addresses", "Passwords"],
                    "logo_path": "https://haveibeenpwned.com/Content/Images/Logos/linkedin.png"
                }
            ],
            "pastes": [
                {"source": "Pastebin", "title": "Email dump", "date": "2020-01-01", "email_count": 5000}
            ],
            "breach_count": 2,
            "paste_count": 1,
            "is_leaked": True
        })
        return result
    headers = {"hibp-api-key": HIBP_KEY, "user-agent": "OSINTShield/1.0"}
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers, timeout=12)
        if r.status_code == 200:
            data = r.json()
            result["breaches"] = [
                {
                    "name": b.get("Name"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "description": re.sub(r'<[^>]+>', '', b.get("Description", ""))[:500],
                    "data_classes": b.get("DataClasses", []),
                    "logo_path": f"https://haveibeenpwned.com/Content/Images/Logos/{b.get('Name', '').lower()}.png"
                }
                for b in data
            ]
            result["breach_count"] = len(data)
            result["is_leaked"] = True
        elif r.status_code == 404:
            pass
        else:
            result["api_error"] = f"HIBP returned {r.status_code}"
    except Exception as e:
        result["api_error"] = str(e)

    try:
        rp = requests.get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}", headers=headers, timeout=12)
        if rp.status_code == 200:
            pastes = rp.json()
            result["pastes"] = [
                {
                    "source": p.get("Source"),
                    "title": p.get("Title", "Untitled"),
                    "date": p.get("Date", ""),
                    "email_count": p.get("EmailCount", 0)
                }
                for p in pastes
            ]
            result["paste_count"] = len(pastes)
            if result["paste_count"] > 0:
                result["is_leaked"] = True
    except:
        pass
    return result

# ---------- USERNAME OSINT (original) ----------
PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{u}", "icon": "🐙"},
    {"name": "Instagram", "url": "https://www.instagram.com/{u}", "icon": "📸"},
    {"name": "Twitter/X", "url": "https://twitter.com/{u}", "icon": "🐦"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{u}", "icon": "💼"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "icon": "🤖"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{u}", "icon": "🎵"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{u}", "icon": "▶️"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}", "icon": "📌"},
    {"name": "Tumblr", "url": "https://{u}.tumblr.com", "icon": "📝"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{u}", "icon": "🎮"},
    {"name": "Medium", "url": "https://medium.com/@{u}", "icon": "✍️"},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "icon": "💻"},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "icon": "🔑"},
    {"name": "Patreon", "url": "https://www.patreon.com/{u}", "icon": "🎨"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={u}", "icon": "📰"},
    {"name": "Facebook", "url": "https://www.facebook.com/{u}", "icon": "📘"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{u}", "icon": "👻"},
    {"name": "Telegram", "url": "https://t.me/{u}", "icon": "✈️"},
    {"name": "WhatsApp", "url": "https://wa.me/{u}", "icon": "💬"},
    {"name": "Discord", "url": "https://discord.com/users/{u}", "icon": "🎧"},
]

def check_username(username):
    found = []
    not_found = []
    errors = []
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINTShield/1.0)"}
    for p in PLATFORMS:
        url = p["url"].replace("{u}", username)
        try:
            r = requests.get(url, headers=headers, timeout=7, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 500:
                found.append({"platform": p["name"], "url": url, "icon": p["icon"], "status": "FOUND"})
            else:
                not_found.append({"platform": p["name"], "url": url, "icon": p["icon"], "status": "NOT_FOUND"})
        except Exception as e:
            errors.append({"platform": p["name"], "url": url, "icon": p["icon"], "status": "ERROR", "note": str(e)[:60]})
    found_count = len(found)
    if found_count >= 8: risk = "CRITICAL"
    elif found_count >= 5: risk = "HIGH"
    elif found_count >= 2: risk = "MEDIUM"
    else: risk = "LOW"
    return {
        "username": username,
        "found": found,
        "not_found": not_found,
        "errors": errors,
        "found_count": found_count,
        "total_checked": len(PLATFORMS),
        "risk_level": risk,
        "digital_footprint": f"{found_count}/{len(PLATFORMS)} platforms"
    }

# ---------- METADATA EXTRACTOR ----------
def extract_metadata(image_path):
    result = {
        "file": os.path.basename(image_path),
        "exif": {},
        "gps": None,
        "risk_flags": []
    }
    size = os.path.getsize(image_path)
    result["file_size_kb"] = round(size/1024,1)
    result["exif"]["FileSize"] = f"{result['file_size_kb']} KB"
    result["exif"]["FileName"] = os.path.basename(image_path)
    result["exif"]["Format"] = image_path.rsplit('.',1)[-1].upper()
    img = cv2.imread(image_path)
    if img is not None:
        h,w = img.shape[:2]
        result["exif"]["Dimensions"] = f"{w}x{h}"
    if PIL_OK:
        try:
            pil_img = Image.open(image_path)
            exif_data = pil_img._getexif()
            if exif_data:
                gps = extract_gps(exif_data)
                if gps:
                    result["gps"] = gps
                    result["risk_flags"].append("⚠️ GPS coordinates found!")
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name in ["Make","Model","Software","DateTime","DateTimeOriginal","Artist","Copyright","ExifImageWidth","ExifImageHeight"]:
                        result["exif"][tag_name] = str(value)[:100]
                if "Make" in result["exif"] or "Model" in result["exif"]:
                    result["risk_flags"].append(f"📷 Device: {result['exif'].get('Make','')} {result['exif'].get('Model','')}".strip())
                if "DateTime" in result["exif"]:
                    result["risk_flags"].append(f"🕐 Timestamp: {result['exif']['DateTime']}")
                if "Artist" in result["exif"] or "Copyright" in result["exif"]:
                    result["risk_flags"].append("👤 Author/Copyright info")
        except Exception as e:
            result["exif"]["pil_note"] = str(e)[:100]
    return result

# ---------- HOLEHE ----------
try:
    from holehe.core import launch_module, import_submodules, get_functions
except ImportError:
    from holehe.core import launch_module, import_submodules, get_functions

async def holehe_check(email):
    results = []
    modules = import_submodules('holehe.modules')
    websites = get_functions(modules)
    for module in websites:
        try:
            r = await launch_module(module, email)
            if r.get("exists"):
                results.append({
                    "name": module.__name__,
                    "website": r.get("domain", ""),
                    "method": r.get("method", ""),
                    "note": r.get("note", "")
                })
        except Exception:
            continue
    return results



def run_holehe(email):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(holehe_check(email))
    loop.close()
    return results

# ---------- SHERLOCK ----------
def run_sherlock(username):
    try:
        result = subprocess.run(
            ["sherlock", username, "--json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        data = json.loads(result.stdout)
        found = []
        for site, info in data.items():
            if info.get("status") == "Claimed":
                found.append({
                    "site": site,
                    "url": info.get("url", ""),
                    "username": info.get("username", username)
                })
        return found
    except Exception as e:
        log("ERROR", f"Sherlock failed: {e}")
        return []

# ---------- H8MAIL ----------
def run_h8mail(email):
    try:
        result = subprocess.run(
            ["h8mail", "-t", email, "-o", "/dev/stdout", "--csv"],
            capture_output=True,
            text=True,
            timeout=30
        )
        reader = csv.DictReader(io.StringIO(result.stdout))
        breaches = []
        for row in reader:
            breaches.append({
                "source": row.get("source", ""),
                "date": row.get("date", ""),
                "email": row.get("email", ""),
                "password": row.get("password", "")[:50]
            })
        return breaches
    except Exception as e:
        log("ERROR", f"H8mail failed: {e}")
        return []

# ---------- SCYLLA (optional) ----------
def query_scylla(query):
    url = f"https://scylla.so/search?q={query}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ---------- PDF GENERATION ----------
def generate_pdf(scan_id, scan_data):
    if not REPORTLAB_OK:
        return None
    filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    filepath = os.path.join('reports', filename)
    try:
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [
            Paragraph("OSINT Shield — Threat Report", styles['Title']),
            Spacer(1,12),
            Paragraph(f"Scan #{scan_id} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']),
            Spacer(1,10),
            Paragraph(f"Risk: {scan_data.get('risk','?')} | Score: {scan_data.get('score',0)}", styles['Heading2']),
            Spacer(1,12)
        ]
        results = scan_data.get('results', {})
        for key, value in results.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)[:500]
            story.append(Paragraph(str(key).replace('_',' ').title(), styles['Heading3']))
            story.append(Paragraph(str(value)[:500], styles['Normal']))
            story.append(Spacer(1,6))
        doc.build(story)
        update_scan_report_path(scan_id, filepath)
        log("INFO", f"PDF generated: {filepath}")
        return filepath
    except Exception as e:
        log("ERROR", f"PDF generation failed: {e}")
        return None

# ---------- EMAIL ALERT ----------
def send_email_alert(to_email, scan_id, risk_level, summary):
    if not ALERT_EMAIL or not ALERT_PASSWORD:
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"OSINT Alert — {risk_level} Risk (Scan #{scan_id})"
        msg['From'] = ALERT_EMAIL
        msg['To'] = to_email
        color = '#ff2d55' if risk_level in ['CRITICAL','HIGH'] else '#ffb800'
        html = f"""
        <html><body style="font-family:sans-serif">
            <h2 style="color:{color}">🛡️ OSINT Shield Alert</h2>
            <p><strong>Scan ID:</strong> #{scan_id}<br><strong>Risk:</strong> {risk_level}</p>
            <pre style="background:#f4f4f4; padding:10px;">{summary[:2000]}</pre>
            <small>Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
        </body></html>
        """
        msg.attach(MIMEText(html, 'html'))
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(ALERT_EMAIL, ALERT_PASSWORD)
        server.send_message(msg)
        server.quit()
        log("INFO", f"Email alert sent to {to_email}")
        return True
    except Exception as e:
        log("ERROR", f"Email failed: {e}")
        return False

# ---------- API ENDPOINTS ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/system/stats')
def api_system_stats():
    res = get_all_scans()
    total = 0
    high = 0
    medium = 0
    low = 0
    by_df = 0
    by_br = 0
    by_un = 0
    by_holehe = 0
    by_sherlock = 0
    by_h8mail = 0
    
    if res:
        total = len(res)
        for row in res:
            rl = str(row.get('risk_level', '')).upper()
            st = str(row.get('scan_type', '')).lower()
            if rl in ['HIGH', 'CRITICAL']:
                high += 1
            elif rl == 'MEDIUM':
                medium += 1
            elif rl in ['LOW', 'INFO']:
                low += 1
                
            if st == 'deepfake':
                by_df += 1
            elif st.startswith('breach') or st == 'leakcheck':
                by_br += 1
            elif st == 'username':
                by_un += 1
            elif st == 'holehe':
                by_holehe += 1
            elif st == 'sherlock':
                by_sherlock += 1
            elif st == 'h8mail':
                by_h8mail += 1
    upload_mb = 0
    if os.path.exists('uploads'):
        for f in os.listdir('uploads'):
            try:
                upload_mb += os.path.getsize(os.path.join('uploads',f))
            except: pass
        upload_mb = round(upload_mb/(1024*1024),2)
    api_status = {
        "hibp": "connected" if HIBP_KEY else "mock",
        "serpapi": "connected" if GOOGLE_VISION_API_KEY else "mock",
        "imagga": "connected" if IMAGGA_SECRET else "mock",
        "email": "connected" if ALERT_EMAIL else "not_configured",
    }
    return jsonify({
        "scans": {"total":total, "high":high, "medium":medium, "low":low},
        "by_type": {"deepfake":by_df, "breach":by_br, "username":by_un, "holehe":by_holehe, "sherlock":by_sherlock, "h8mail":by_h8mail},
        "storage_mb": upload_mb,
        "api_status": api_status,
        "server_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/system/logs')
def api_system_logs():
    limit = min(int(request.args.get('limit',100)),300)
    with _log_lock:
        entries = list(_logs)[-limit:]
    return jsonify({"logs": [{"time":e["time"],"level":e["level"],"msg":e["msg"]} for e in entries][::-1]})

@app.route('/api/deepfake', methods=['POST'])
def api_deepfake():
    if 'file' not in request.files:
        return jsonify({"error":"No file"}),400
    f = request.files['file']
    if not f or not f.filename or not allowed_file(f.filename):
        return jsonify({"error":"Invalid file"}),400
    filename = secure_filename(f.filename)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    save_path = os.path.join('uploads', f"{timestamp}_{filename}")
    f.save(save_path)
    ext = filename.rsplit('.',1)[-1].lower()
    if ext in {'mp4','avi','mov'}:
        res = deepfake_video(save_path)
    else:
        res = deepfake_image(save_path)
        res['imagga'] = imagga_analyze(save_path)
        with open(save_path,'rb') as imgf:
            res['image_b64'] = base64.b64encode(imgf.read()).decode()
    res['filename'] = filename
    scan_id = save_scan('deepfake', filename, res, res.get('deepfake_score',0), res.get('risk_level','UNKNOWN'))
    res['scan_id'] = scan_id
    return jsonify(res)

@app.route('/api/reverse-image', methods=['POST'])
def api_reverse():
    if 'file' not in request.files:
        return jsonify({"error":"No file"}),400
    f = request.files['file']
    if not f or not f.filename or not allowed_file(f.filename):
        return jsonify({"error":"Invalid file"}),400
    filename = secure_filename(f.filename)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    save_path = os.path.join('uploads', f"{timestamp}_{filename}")
    f.save(save_path)
    res = reverse_search(save_path)
    with open(save_path,'rb') as imgf:
        res['image_b64'] = base64.b64encode(imgf.read()).decode()
    matched = len(res.get('pages_with_matching',[]))
    if matched > 10: risk = "HIGH"
    elif matched > 3: risk = "MEDIUM"
    else: risk = "LOW"
    scan_id = save_scan('reverse_image', filename, res, matched*5, risk)
    res['scan_id'] = scan_id
    res['risk_level'] = risk
    return jsonify(res)

@app.route('/api/breach', methods=['POST'])
def api_breach():
    data = request.get_json(silent=True) or {}
    email = data.get('email','').strip()
    if not email:
        return jsonify({"error":"Email required"}),400
    res = check_breach(email)
    risk = "CRITICAL" if res['breach_count'] > 5 else "HIGH" if res['breach_count'] > 0 else "LOW"
    scan_id = save_scan('breach_email', email, res, res['breach_count']*10, risk)
    res['scan_id'] = scan_id
    res['risk_level'] = risk
    return jsonify(res)

@app.route('/api/username', methods=['POST'])
def api_username():
    data = request.get_json(silent=True) or {}
    username = data.get('username','').strip()
    if not username:
        return jsonify({"error":"Username required"}),400
    res = check_username(username)
    scan_id = save_scan('username', username, res, res['found_count']*8, res['risk_level'])
    res['scan_id'] = scan_id
    return jsonify(res)

@app.route('/api/metadata', methods=['POST'])
def api_metadata():
    if 'file' not in request.files:
        return jsonify({"error":"No file"}),400
    f = request.files['file']
    if not f or not f.filename or not allowed_file(f.filename):
        return jsonify({"error":"Invalid file"}),400
    filename = secure_filename(f.filename)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    save_path = os.path.join('uploads', f"{timestamp}_{filename}")
    f.save(save_path)
    res = extract_metadata(save_path)
    with open(save_path,'rb') as imgf:
        res['image_b64'] = base64.b64encode(imgf.read()).decode()
    flags = len(res.get('risk_flags',[]))
    if res.get('gps') or flags >= 2: risk = "HIGH"
    elif flags >= 1: risk = "MEDIUM"
    else: risk = "LOW"
    scan_id = save_scan('metadata', filename, res, flags*20, risk)
    res['scan_id'] = scan_id
    res['risk_level'] = risk
    return jsonify(res)

# ---------- HOLEHE ENDPOINT ----------
@app.route('/api/holehe', methods=['POST'])
def api_holehe():
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    try:
        results = run_holehe(email)
        risk_level = "HIGH" if len(results) > 5 else "MEDIUM" if len(results) > 0 else "LOW"
        scan_id = save_scan('holehe', email, results, len(results) * 5, risk_level)
        return jsonify({
            "email": email,
            "found": results,
            "count": len(results),
            "risk_level": risk_level,
            "scan_id": scan_id
        })
    except Exception as e:
        log("ERROR", f"Holehe failed: {e}")
        return jsonify({"error": str(e)}), 500

# ---------- SHERLOCK ENDPOINT ----------
@app.route('/api/sherlock', methods=['POST'])
def api_sherlock():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    if not username:
        return jsonify({"error": "Username required"}), 400
    try:
        found = run_sherlock(username)
        risk_level = "CRITICAL" if len(found) > 10 else "HIGH" if len(found) > 5 else "MEDIUM" if len(found) > 0 else "LOW"
        scan_id = save_scan('sherlock', username, found, len(found) * 3, risk_level)
        return jsonify({
            "username": username,
            "found": found,
            "count": len(found),
            "risk_level": risk_level,
            "scan_id": scan_id
        })
    except Exception as e:
        log("ERROR", f"Sherlock failed: {e}")
        return jsonify({"error": str(e)}), 500

# ---------- H8MAIL ENDPOINT ----------
@app.route('/api/h8mail', methods=['POST'])
def api_h8mail():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    try:
        breaches = run_h8mail(email)
        risk_level = "CRITICAL" if len(breaches) > 0 else "LOW"
        scan_id = save_scan('h8mail', email, breaches, len(breaches) * 10, risk_level)
        return jsonify({
            "email": email,
            "breaches": breaches,
            "count": len(breaches),
            "risk_level": risk_level,
            "scan_id": scan_id
        })
    except Exception as e:
        log("ERROR", f"H8mail failed: {e}")
        return jsonify({"error": str(e)}), 500

# ---------- SCYLLA ENDPOINT (optional) ----------
@app.route('/api/scylla', methods=['POST'])
def api_scylla():
    data = request.get_json() or {}
    query = data.get('query', '').strip()
    if not query:
        return jsonify({"error": "Query required"}), 400
    try:
        results = query_scylla(query)
        scan_id = save_scan('scylla', query, results, 0, "UNKNOWN")
        return jsonify({
            "query": query,
            "results": results,
            "scan_id": scan_id
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------- REPORT ENDPOINTS ----------
@app.route('/api/report', methods=['POST'])
def api_report():
    data = request.get_json(silent=True) or {}
    scan_id = data.get('scan_id')
    email = data.get('email','').strip()
    if not scan_id:
        return jsonify({"error":"scan_id required"}),400
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error":f"Scan #{scan_id} not found"}),404
    pdf_path = generate_pdf(scan_id, scan)
    sent = False
    if email:
        summary = json.dumps(scan['results'], indent=2, default=str)
        sent = send_email_alert(email, scan_id, scan['risk'], summary)
    alert_data = {
        "scan_id": scan_id,
        "email": email,
        "sent_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "status": 'sent' if sent else 'failed'
    }
    try:
        alerts_file = os.path.join('instance', 'alerts.json')
        with _db_lock:
            if os.path.exists(alerts_file):
                with open(alerts_file, 'r') as af:
                    alerts = json.load(af)
            else:
                alerts = []
            alert_data['id'] = len(alerts) + 1
            alerts.append(alert_data)
            with open(alerts_file, 'w') as af:
                json.dump(alerts, af, indent=4)
    except Exception as e:
        log("ERROR", f"Failed to save alert locally: {e}")
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "email_sent": sent,
        "pdf_available": pdf_path is not None,
        "message": f"Report #{scan_id} generated."
    })

@app.route('/api/report/download/<int:scan_id>')
def api_download_report(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error":"Scan not found"}),404
    pdf_path = scan.get('report_path')
    if not pdf_path or not os.path.exists(pdf_path):
        pdf_path = generate_pdf(scan_id, scan)
        if not pdf_path:
            return jsonify({"error":"PDF generation failed"}),500
    return send_file(pdf_path, as_attachment=True, download_name=f"report_{scan_id}.pdf")

@app.route('/api/history')
def api_history():
    limit = min(int(request.args.get('limit',30)),100)
    res = get_all_scans()
    res_sorted = sorted(res, key=lambda x: x.get('id', 0), reverse=True)[:limit]
    history = []
    for r in res_sorted:
        history.append({
            "id": r['id'],
            "type": r['scan_type'],
            "input": r['input_data'][:50] if r['input_data'] else "",
            "score": r['risk_score'],
            "risk": r['risk_level'],
            "time": r['scanned_at']
        })
    return jsonify(history)

# ---------- ERROR HANDLERS ----------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"error":"Endpoint not found"}),404
    return render_template('index.html'),200

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error":"File too large (max 32MB)"}),413

@app.errorhandler(500)
def internal_error(e):
    log("ERROR", f"500: {str(e)}")
    return jsonify({"error":"Internal server error"}),500

if __name__ == '__main__':
    log("INFO", "OSINT Shield v2 started (with Holehe, Sherlock, H8mail)")
    app.run(debug=True, host='0.0.0.0', port=5000)