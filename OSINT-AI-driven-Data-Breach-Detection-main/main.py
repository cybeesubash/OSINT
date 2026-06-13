import os
import sys
import json
import base64
import hashlib
import re
import threading
import smtplib
import subprocess
import csv
import io
import shutil
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

# Load environment variables — supports both .env and _env filenames
import pathlib
BASE_DIR = pathlib.Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / '_env', override=False)
load_dotenv(dotenv_path=BASE_DIR / '.env', override=True)

# ---------- CONFIG ----------
LEAKCHECK_API_KEY = os.environ.get('LEAKCHECK_API_KEY', '')
IMAGGA_KEY = os.environ.get('IMAGGA_API_KEY', 'acc_df4208cbcff1ed5')
IMAGGA_SECRET = os.environ.get('IMAGGA_SECRET', 'e33ac6af8cbd6917a785f68592343024')
GOOGLE_VISION_API_KEY = os.environ.get('GOOGLE_VISION_API_KEY', '')
BING_SEARCH_KEY = os.environ.get('BING_SEARCH_KEY', '')  # Optional
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'AIzaSyA2juQVCwATxBpQPbIwDvUkP4dPH1_DWDc')  # Google Gemini for deepfake AI
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
# NOTE: index.html must be placed in a 'templates/' folder next to main.py
# Run: mkdir -p templates && cp index.html templates/
app = Flask(__name__, template_folder='templates')

# Debug: print loaded keys on startup
print(f"[CONFIG] IMAGGA_KEY    = '{IMAGGA_KEY}'")
print(f"[CONFIG] IMAGGA_SECRET = '{IMAGGA_SECRET}'")
print(f"[CONFIG] LEAKCHECK_KEY = {'set (' + LEAKCHECK_API_KEY[:8] + '...)' if LEAKCHECK_API_KEY else 'NOT SET'}")
print(f"[CONFIG] GOOGLE_KEY    = '{GOOGLE_VISION_API_KEY[:10]}...' " if GOOGLE_VISION_API_KEY else "[CONFIG] GOOGLE_KEY = NOT SET")
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

# init_db will be called after logging setup

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
def opencv_analyze(image_path):
    """Basic OpenCV analysis as fallback"""
    img = cv2.imread(image_path)
    if img is None:
        return None
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = img.shape[:2]
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    faces = face_cascade.detectMultiScale(gray, 1.1, 5)
    laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
    noise_score = min(laplacian_var / 500, 1.0) if laplacian_var else 0.5
    edges = cv2.Canny(gray, 50, 150)
    edge_density = np.sum(edges > 0) / (h * w)
    b, g, r = cv2.split(img)
    color_anomaly = min((abs(np.std(b)-np.std(g)) + abs(np.std(g)-np.std(r))) / 30, 1.0)
    dct_vals = []
    for i in range(0, min(h,64), 8):
        for j in range(0, min(w,64), 8):
            block = gray[i:i+8, j:j+8].astype(np.float32)
            if block.shape == (8,8):
                dct_vals.append(float(np.std(cv2.dct(block))))
    compression = min(np.mean(dct_vals)/50 if dct_vals else 0.5, 1.0)
    face_blur = 0.5
    for (x, y, fw, fh) in faces:
        face_region = gray[y:y+fh, x:x+fw]
        if face_region.size > 0:
            face_blur = min(cv2.Laplacian(face_region, cv2.CV_64F).var() / 200, 1.0)
    score = round((
        (1-face_blur)*0.30 + color_anomaly*0.25 +
        (1-noise_score)*0.20 + compression*0.15 + edge_density*0.10
    )*100, 2)
    return {
        "face_count": len(faces),
        "opencv_score": score,
        "metrics": {
            "blur_score": round((1-face_blur)*100, 1),
            "color_anomaly": round(color_anomaly*100, 1),
            "noise_score": round(noise_score*100, 1),
            "compression": round(compression*100, 1),
            "edge_density": round(edge_density*100, 1)
        }
    }

def gemini_deepfake_analyze(image_path):
    """Use Google Gemini Vision to detect deepfakes/AI-edited images"""
    if not GEMINI_API_KEY:
        return None
    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()
        img_b64 = base64.b64encode(image_data).decode()

        # Detect image mime type
        ext = image_path.rsplit('.', 1)[-1].lower()
        mime_map = {'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 'webp': 'image/webp', 'gif': 'image/gif'}
        mime_type = mime_map.get(ext, 'image/jpeg')

        prompt = """You are an expert forensic image analyst specializing in deepfake and AI-generated image detection.

Analyze this image carefully and respond ONLY in this exact JSON format:
{
  "verdict": "DEEPFAKE DETECTED" or "AI EDITED" or "LIKELY AUTHENTIC" or "UNCERTAIN",
  "deepfake_score": <number 0-100>,
  "risk_level": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
  "analysis": {
    "face_manipulation": "<description of any face manipulation>",
    "lighting_consistency": "<lighting analysis>",
    "background_artifacts": "<background analysis>",
    "skin_texture": "<skin/texture analysis>",
    "edge_blending": "<edge and blending analysis>",
    "overall_assessment": "<overall conclusion>"
  },
  "indicators": ["<indicator1>", "<indicator2>", ...],
  "confidence": "<HIGH/MEDIUM/LOW confidence in this assessment>"
}

Rules:
- deepfake_score 0 = definitely real, 100 = definitely fake
- Be accurate — real camera photos should score LOW (0-30)
- AI generated/edited images should score HIGH (60-100)
- Look for: unnatural skin, blurry edges around face, inconsistent lighting, artifacts"""

        payload = {
            "contents": [{
                "parts": [
                    {"text": prompt},
                    {"inline_data": {"mime_type": mime_type, "data": img_b64}}
                ]
            }],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 1000
            }
        }

        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}",
            json=payload,
            timeout=30
        )

        if resp.status_code != 200:
            log("WARN", f"Gemini API error: {resp.status_code} - {resp.text[:200]}")
            return None

        response_text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]

        # Parse JSON from response
        import re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            result["engine"] = "Google Gemini AI"
            return result
        return None

    except Exception as e:
        log("WARN", f"Gemini analysis failed: {e}")
        return None

def deepfake_image(image_path):
    img = cv2.imread(image_path)
    if img is None:
        return {"error": "Cannot read image"}

    # Run OpenCV analysis
    cv_result = opencv_analyze(image_path)

    # Run Gemini AI analysis (primary if available)
    gemini_result = gemini_deepfake_analyze(image_path)

    if gemini_result:
        # Use Gemini result as primary
        score = gemini_result.get("deepfake_score", 50)
        verdict = gemini_result.get("verdict", "UNCERTAIN")
        risk = gemini_result.get("risk_level", "MEDIUM")
        analysis = gemini_result.get("analysis", {})
        indicators = gemini_result.get("indicators", [])
        confidence = gemini_result.get("confidence", "MEDIUM")

        return {
            "deepfake_score": score,
            "verdict": verdict,
            "risk_level": risk,
            "face_count": cv_result["face_count"] if cv_result else 0,
            "type": "image",
            "engine": "Google Gemini AI",
            "confidence": confidence,
            "ai_analysis": analysis,
            "indicators": indicators,
            "metrics": cv_result["metrics"] if cv_result else {},
        }
    else:
        # Fallback to OpenCV only
        if not cv_result:
            return {"error": "Cannot analyze image"}
        score = cv_result["opencv_score"]
        verdict = "DEEPFAKE DETECTED" if score > 55 else "LIKELY AUTHENTIC"
        if score > 80: risk = "CRITICAL"
        elif score > 60: risk = "HIGH"
        elif score > 40: risk = "MEDIUM"
        else: risk = "LOW"
        return {
            "deepfake_score": score,
            "verdict": verdict,
            "risk_level": risk,
            "face_count": cv_result["face_count"],
            "type": "image",
            "engine": "OpenCV (Gemini not configured)",
            "metrics": cv_result["metrics"]
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

# ---------- IMAGGA (no mock) ----------
def imagga_analyze(image_path):
    if not IMAGGA_SECRET:
        raise Exception("Imagga secret not configured. Set IMAGGA_SECRET in .env")
    auth = (IMAGGA_KEY, IMAGGA_SECRET)
    try:
        with open(image_path,'rb') as f:
            upload = requests.post("https://api.imagga.com/v2/uploads", auth=auth, files={"image":f}, timeout=20)
        if upload.status_code != 200:
            raise Exception(f"Imagga upload failed: {upload.status_code}")
        upload_id = upload.json()["result"]["upload_id"]
        result = {"tags": [], "face_count": 0, "nsfw": None, "colors": []}
        # Tags
        tags_resp = requests.get("https://api.imagga.com/v2/tags", auth=auth, params={"image_upload_id":upload_id,"limit":20}, timeout=15)
        if tags_resp.status_code == 200:
            result["tags"] = [{"tag":t["tag"]["en"],"confidence":round(t["confidence"],1)} for t in tags_resp.json()["result"]["tags"]]
        # Faces
        faces_resp = requests.get("https://api.imagga.com/v2/faces/detections", auth=auth, params={"image_upload_id":upload_id}, timeout=15)
        if faces_resp.status_code == 200:
            faces_data = faces_resp.json()["result"]["faces"]
            result["face_count"] = len(faces_data)
        # NSFW
        nsfw_resp = requests.get("https://api.imagga.com/v2/categories/nsfw_beta", auth=auth, params={"image_upload_id":upload_id}, timeout=15)
        if nsfw_resp.status_code == 200:
            for cat in nsfw_resp.json()["result"]["categories"]:
                if cat["name"]["en"] in ["nsfw","sfw"]:
                    result["nsfw"] = {"label":cat["name"]["en"].upper(), "confidence":round(cat["confidence"],1)}
        # Colors
        colors_resp = requests.get("https://api.imagga.com/v2/colors", auth=auth, params={"image_upload_id":upload_id}, timeout=15)
        if colors_resp.status_code == 200:
            result["colors"] = [{"color":c["html_code"],"name":c["closest_palette_color"],"percent":round(c["percent"],1)} for c in colors_resp.json()["result"]["colors"]["foreground_colors"][:5]]
        requests.delete(f"https://api.imagga.com/v2/uploads/{upload_id}", auth=auth, timeout=8)
        return result
    except Exception as e:
        raise Exception(f"Imagga analysis failed: {str(e)}")

# ---------- REVERSE IMAGE (Google Vision) ----------
def reverse_search(image_path):
    result = {
        "best_guess_labels": ["Upload image to search engines below"],
        "pages_with_matching": [],
        "visually_similar_images": [],
        "full_matching_images": [],
        "partial_matching_images": [],
        "total_results": 0,
        "engine_used": "Multi-Engine (Direct Upload)"
    }
    try:
        with open(image_path, "rb") as f:
            image_data = f.read()

        img_b64 = base64.b64encode(image_data).decode()
        result["image_b64"] = img_b64

        # Try uploading to multiple free hosts
        img_url = None

        # Method 1: freeimage.host
        try:
            fi_resp = requests.post(
                "https://freeimage.host/api/1/upload",
                data={"key": "6d207e02198a847aa98d0a2a901485a5", "action": "upload", "source": img_b64, "format": "json"},
                timeout=15
            )
            if fi_resp.status_code == 200 and fi_resp.json().get("status_code") == 200:
                img_url = fi_resp.json()["image"]["url"]
                log("INFO", f"Uploaded to freeimage.host: {img_url}")
        except Exception as e:
            log("WARN", f"freeimage.host failed: {e}")

        # Method 2: imgbb.com free API
        if not img_url:
            try:
                imgbb_resp = requests.post(
                    "https://api.imgbb.com/1/upload",
                    data={"key": "2e46ced7e8b3c8e1c8e8d4e0b3c8e1c8", "image": img_b64},
                    timeout=15
                )
                if imgbb_resp.status_code == 200 and imgbb_resp.json().get("success"):
                    img_url = imgbb_resp.json()["data"]["url"]
                    log("INFO", f"Uploaded to imgbb: {img_url}")
            except Exception as e:
                log("WARN", f"imgbb failed: {e}")

        # Build search links — with or without URL
        if img_url:
            result["image_url"] = img_url
            result["best_guess_labels"] = ["Image uploaded — click links below to search"]
            result["pages_with_matching"] = [
                {"url": f"https://lens.google.com/uploadbyurl?url={img_url}", "title": "🔍 Google Lens"},
                {"url": f"https://yandex.com/images/search?url={img_url}&rpt=imageview", "title": "🔍 Yandex Images"},
                {"url": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{img_url}", "title": "🔍 Bing Visual Search"},
                {"url": f"https://tineye.com/search?url={img_url}", "title": "🔍 TinEye"},
            ]
        else:
            # No upload succeeded — give manual upload links
            result["best_guess_labels"] = ["Auto-upload failed — use manual search links below"]
            result["pages_with_matching"] = [
                {"url": "https://lens.google.com/", "title": "🔍 Google Lens (upload manually)"},
                {"url": "https://yandex.com/images/", "title": "🔍 Yandex Images (upload manually)"},
                {"url": "https://tineye.com/", "title": "🔍 TinEye (upload manually)"},
                {"url": "https://www.bing.com/visualsearch", "title": "🔍 Bing Visual Search (upload manually)"},
            ]
            log("WARN", "All image hosts failed — returning manual search links")

        result["total_results"] = len(result["pages_with_matching"])
        return result

    except Exception as e:
        raise Exception(f"Reverse image search failed: {str(e)}")

# ---------- LEAKCHECK BREACH CHECK ----------
LEAKCHECK_V2_URL = "https://leakcheck.io/api/v2/query"
LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"
LEAKCHECK_TIMEOUT = 60
LEAKCHECK_RESULT_LIMIT = 50


def _leakcheck_not_found(data):
    """LeakCheck returns success=false with error 'Not found' when email is clean."""
    err = str(data.get("error", "")).lower()
    return err in ("not found", "no results found")


def _cap_leakcheck_results(results, total_found):
    """Limit payload size so the frontend stays responsive."""
    capped = results[:LEAKCHECK_RESULT_LIMIT]
    return {
        "results": capped,
        "found": total_found,
        "showing": len(capped),
        "truncated": total_found > len(capped),
    }


def _parse_leakcheck_pro(data, email):
    """Normalize LeakCheck Pro API v2 response."""
    results = []
    for item in data.get("result", []):
        entry = {"email": item.get("email", email)}
        source = item.get("source") or {}
        if isinstance(source, dict):
            entry["source"] = source.get("name", "Unknown")
            entry["breach_date"] = source.get("breach_date", "Unknown")
        else:
            entry["source"] = str(source)
        for field in (
            "username", "password", "first_name", "last_name",
            "phone", "address", "dob", "ip", "origin",
        ):
            if item.get(field):
                entry[field] = item[field]
        if item.get("fields"):
            entry["exposed_fields"] = ", ".join(item["fields"])
        results.append(entry)
    return results


def _parse_leakcheck_public(data, email):
    """Normalize LeakCheck public API response (sources only, no passwords)."""
    results = []
    fields = ", ".join(data.get("fields", []))
    for src in data.get("sources", []):
        results.append({
            "email": email,
            "source": src.get("name", "Unknown"),
            "breach_date": src.get("date", "Unknown"),
            "exposed_fields": fields,
        })
    return results


def check_leakcheck(email):
    """Check email via LeakCheck.io Pro API v2, with public API fallback."""
    headers = {
        "Accept": "application/json",
        "User-Agent": "OSINT-Shield/1.0",
    }
    if LEAKCHECK_API_KEY:
        headers["X-API-Key"] = LEAKCHECK_API_KEY

    api_note = None
    if LEAKCHECK_API_KEY:
        api_note = (
            "Pro plan inactive — activate at leakcheck.io for passwords and full records. "
            "Showing breach sources via public API."
        )

    # Pro API v2 — full breach data including passwords when plan is active
    if LEAKCHECK_API_KEY:
        try:
            resp = requests.get(
                f"{LEAKCHECK_V2_URL}/{requests.utils.quote(email)}",
                params={"type": "email"},
                headers=headers,
                timeout=LEAKCHECK_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    parsed = _parse_leakcheck_pro(data, email)
                    total_found = data.get("found", len(parsed))
                    capped = _cap_leakcheck_results(parsed, total_found)
                    log("INFO", f"LeakCheck Pro: {total_found} result(s), quota={data.get('quota')}")
                    return {
                        "email": email,
                        "found": capped["found"],
                        "showing": capped["showing"],
                        "truncated": capped["truncated"],
                        "results": capped["results"],
                        "quota_remaining": data.get("quota"),
                        "api_source": "LeakCheck.io Pro API v2",
                    }
                if _leakcheck_not_found(data):
                    return {
                        "email": email,
                        "found": 0,
                        "showing": 0,
                        "truncated": False,
                        "results": [],
                        "api_source": "LeakCheck.io Pro API v2",
                    }
                raise Exception(data.get("error", "LeakCheck query failed"))
            if resp.status_code == 401:
                raise Exception("LeakCheck API key is missing or invalid")
            if resp.status_code == 429:
                raise Exception("LeakCheck rate limit exceeded — wait a moment and retry")
            if resp.status_code in (400, 422):
                err = resp.json().get("error", resp.text[:120]) if resp.text else "Invalid request"
                raise Exception(f"LeakCheck: {err}")
            if resp.status_code == 403:
                err = resp.json().get("error", "Plan inactive or quota exceeded")
                log("WARN", f"LeakCheck Pro unavailable ({err}) — using public API")
            else:
                raise Exception(f"LeakCheck API error ({resp.status_code})")
        except requests.RequestException as e:
            raise Exception(f"LeakCheck connection failed: {e}") from e
        except Exception as e:
            if "connection failed" in str(e).lower():
                raise
            log("WARN", f"LeakCheck Pro failed: {e}")

    # Public API fallback — breach source names (no passwords)
    try:
        resp = requests.get(
            LEAKCHECK_PUBLIC_URL,
            params={"check": email},
            headers={"Accept": "application/json", "User-Agent": "OSINT-Shield/1.0"},
            timeout=LEAKCHECK_TIMEOUT,
        )
        if resp.status_code != 200:
            raise Exception(f"LeakCheck public API error ({resp.status_code})")
        data = resp.json()
        if not data.get("success"):
            if _leakcheck_not_found(data):
                log("INFO", "LeakCheck public: no breaches")
                return {
                    "email": email,
                    "found": 0,
                    "showing": 0,
                    "truncated": False,
                    "results": [],
                    "api_source": "LeakCheck.io Public API",
                    "api_note": api_note if LEAKCHECK_API_KEY else None,
                }
            raise Exception(data.get("error", "LeakCheck public query failed"))
        parsed = _parse_leakcheck_public(data, email)
        total_found = data.get("found", len(parsed)) or len(parsed)
        capped = _cap_leakcheck_results(parsed, total_found)
        log("INFO", f"LeakCheck public: {total_found} source(s), showing {capped['showing']}")
        return {
            "email": email,
            "found": capped["found"],
            "showing": capped["showing"],
            "truncated": capped["truncated"],
            "results": capped["results"],
            "api_source": "LeakCheck.io Public API",
            "api_note": api_note if LEAKCHECK_API_KEY else None,
        }
    except requests.RequestException as e:
        raise Exception(f"LeakCheck connection failed: {e}") from e

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
def _holehe_executable():
    """Resolve holehe CLI — Scripts folder is often not on Windows PATH."""
    exe = shutil.which("holehe")
    if exe:
        return exe
    py_dir = pathlib.Path(sys.executable).resolve().parent
    for candidate in (py_dir / "Scripts" / "holehe.exe", py_dir / "holehe.exe"):
        if candidate.exists():
            return str(candidate)
    return "holehe"


def run_holehe(email):
    try:
        result = subprocess.run(
            [_holehe_executable(), email, "--only-used"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=120
        )
        if result.returncode != 0:
            raise Exception(f"Holehe exited with code {result.returncode}")
        lines = result.stdout.splitlines()
        found = []
        for line in lines:
            if line.startswith("[+]"):
                site = line[3:].strip()
                found.append({"name": site, "website": f"https://{site.lower()}.com", "method": "email", "note": ""})
        return found
    except FileNotFoundError:
        raise Exception("Holehe not installed. Run: pip install holehe")
    except Exception as e:
        raise Exception(f"Holehe failed: {str(e)}")

# ---------- SHERLOCK ----------
def run_sherlock(username):
    """Built-in username checker — no external tool needed"""
    SHERLOCK_SITES = [
        {"site": "GitHub", "url": "https://github.com/{}", "check": 200},
        {"site": "GitLab", "url": "https://gitlab.com/{}", "check": 200},
        {"site": "Instagram", "url": "https://www.instagram.com/{}/", "check": 200},
        {"site": "Twitter/X", "url": "https://twitter.com/{}", "check": 200},
        {"site": "Reddit", "url": "https://www.reddit.com/user/{}", "check": 200},
        {"site": "TikTok", "url": "https://www.tiktok.com/@{}", "check": 200},
        {"site": "YouTube", "url": "https://www.youtube.com/@{}", "check": 200},
        {"site": "Twitch", "url": "https://www.twitch.tv/{}", "check": 200},
        {"site": "Pinterest", "url": "https://www.pinterest.com/{}/", "check": 200},
        {"site": "Tumblr", "url": "https://{}.tumblr.com", "check": 200},
        {"site": "Medium", "url": "https://medium.com/@{}", "check": 200},
        {"site": "Dev.to", "url": "https://dev.to/{}", "check": 200},
        {"site": "Keybase", "url": "https://keybase.io/{}", "check": 200},
        {"site": "Patreon", "url": "https://www.patreon.com/{}", "check": 200},
        {"site": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "check": 200},
        {"site": "ProductHunt", "url": "https://www.producthunt.com/@{}", "check": 200},
        {"site": "Replit", "url": "https://replit.com/@{}", "check": 200},
        {"site": "Kaggle", "url": "https://www.kaggle.com/{}", "check": 200},
        {"site": "Steam", "url": "https://steamcommunity.com/id/{}", "check": 200},
        {"site": "Spotify", "url": "https://open.spotify.com/user/{}", "check": 200},
        {"site": "SoundCloud", "url": "https://soundcloud.com/{}", "check": 200},
        {"site": "Flickr", "url": "https://www.flickr.com/people/{}", "check": 200},
        {"site": "Vimeo", "url": "https://vimeo.com/{}", "check": 200},
        {"site": "500px", "url": "https://500px.com/p/{}", "check": 200},
        {"site": "Behance", "url": "https://www.behance.net/{}", "check": 200},
        {"site": "Dribbble", "url": "https://dribbble.com/{}", "check": 200},
        {"site": "Fiverr", "url": "https://www.fiverr.com/{}", "check": 200},
        {"site": "Freelancer", "url": "https://www.freelancer.com/u/{}", "check": 200},
        {"site": "Wattpad", "url": "https://www.wattpad.com/user/{}", "check": 200},
        {"site": "Quora", "url": "https://www.quora.com/profile/{}", "check": 200},
    ]

    found = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    import concurrent.futures

    def check_site(site_info):
        url = site_info["url"].format(username)
        try:
            resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 500:
                return {"site": site_info["site"], "url": url, "username": username, "status": "Claimed"}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_site, s) for s in SHERLOCK_SITES]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return found

# ---------- H8MAIL ----------
def run_h8mail(email):
    try:
        result = subprocess.run(
            ["h8mail", "-t", email, "-o", "/dev/stdout", "--csv"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=30
        )
        if result.returncode != 0:
            raise Exception(f"H8mail exited with code {result.returncode}")
        if not result.stdout:
            return []
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
    except FileNotFoundError:
        raise Exception("H8mail not installed. Run: pip install h8mail")
    except Exception as e:
        raise Exception(f"H8mail failed: {str(e)}")

# ---------- SCYLLA ----------
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
        <html><body>
            <h2 style="color:{color}">🛡️ OSINT Shield Alert</h2>
            <p><strong>Scan ID:</strong> #{scan_id}<br><strong>Risk:</strong> {risk_level}</p>
            <pre>{summary[:2000]}</pre>
            <small>Generated {datetime.now()}</small>
        </body></html>
        """
        msg.attach(MIMEText(html, 'html'))
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(ALERT_EMAIL, ALERT_PASSWORD)
        server.send_message(msg)
        server.quit()
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
    by_lc = 0
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
            elif st == 'leakcheck':
                by_lc += 1
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
        "leakcheck": "connected" if LEAKCHECK_API_KEY else "not_configured",
        "google_vision": "connected" if GOOGLE_VISION_API_KEY else "not_configured",
        "imagga": "connected" if (IMAGGA_KEY and IMAGGA_SECRET) else "not_configured",
        "email": "connected" if ALERT_EMAIL else "not_configured",
    }
    return jsonify({
        "scans": {"total":total, "high":high, "medium":medium, "low":low},
        "by_type": {"deepfake":by_df, "leakcheck":by_lc, "username":by_un, "holehe":by_holehe, "sherlock":by_sherlock, "h8mail":by_h8mail},
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
    try:
        ext = filename.rsplit('.',1)[-1].lower()
        if ext in {'mp4','avi','mov'}:
            res = deepfake_video(save_path)
        else:
            res = deepfake_image(save_path)
            # FIX 1: Imagga is optional - don't crash if key missing or API fails
            if IMAGGA_KEY and IMAGGA_SECRET:
                try:
                    res['imagga'] = imagga_analyze(save_path)
                    res['imagga']['api_status'] = 'connected'
                except Exception as imagga_err:
                    res['imagga'] = {'api_status': 'error', 'error': str(imagga_err)}
                    log("WARN", f"Imagga failed (non-fatal): {imagga_err}")
            else:
                res['imagga'] = {'api_status': 'not_configured'}
            with open(save_path,'rb') as imgf:
                res['image_b64'] = base64.b64encode(imgf.read()).decode()
        res['filename'] = filename
        scan_id = save_scan('deepfake', filename, res, res.get('deepfake_score',0), res.get('risk_level','UNKNOWN'))
        res['scan_id'] = scan_id
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    try:
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/leakcheck', methods=['POST'])
def api_leakcheck():
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    try:
        res = check_leakcheck(email)
        risk = "CRITICAL" if res['found'] > 5 else "HIGH" if res['found'] > 0 else "LOW"
        scan_id = save_scan('leakcheck', email, res, res['found'] * 10, risk)
        res['scan_id'] = scan_id
        res['risk_level'] = risk
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    try:
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/holehe', methods=['POST'])
def api_holehe():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    try:
        results = run_holehe(email)
        risk = "HIGH" if len(results) > 5 else "MEDIUM" if len(results) > 0 else "LOW"
        scan_id = save_scan('holehe', email, results, len(results)*5, risk)
        return jsonify({"email": email, "found": results, "count": len(results), "risk_level": risk, "scan_id": scan_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/sherlock', methods=['POST'])
def api_sherlock():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    if not username:
        return jsonify({"error": "Username required"}), 400
    try:
        found = run_sherlock(username)
        risk = "CRITICAL" if len(found) > 10 else "HIGH" if len(found) > 5 else "MEDIUM" if len(found) > 0 else "LOW"
        scan_id = save_scan('sherlock', username, found, len(found)*3, risk)
        return jsonify({"username": username, "found": found, "count": len(found), "risk_level": risk, "scan_id": scan_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/h8mail', methods=['POST'])
def api_h8mail():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    try:
        breaches = run_h8mail(email)
        risk = "CRITICAL" if len(breaches) > 0 else "LOW"
        scan_id = save_scan('h8mail', email, breaches, len(breaches)*10, risk)
        return jsonify({"email": email, "breaches": breaches, "count": len(breaches), "risk_level": risk, "scan_id": scan_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scylla', methods=['POST'])
def api_scylla():
    data = request.get_json() or {}
    query = data.get('query', '').strip()
    if not query:
        return jsonify({"error": "Query required"}), 400
    try:
        results = query_scylla(query)
        scan_id = save_scan('scylla', query, results, 0, "UNKNOWN")
        return jsonify({"query": query, "results": results, "scan_id": scan_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report', methods=['POST'])
def api_report():
    data = request.get_json() or {}
    scan_id = data.get('scan_id')
    email = data.get('email', '').strip()
    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan #{scan_id} not found"}), 404
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
    return jsonify({"success": True, "scan_id": scan_id, "email_sent": sent, "pdf_available": pdf_path is not None})

@app.route('/api/report/download/<int:scan_id>')
def api_download_report(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    pdf_path = scan.get('report_path')
    if not pdf_path or not os.path.exists(pdf_path):
        pdf_path = generate_pdf(scan_id, scan)
        if not pdf_path:
            return jsonify({"error": "PDF generation failed"}), 500
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
        return jsonify({"error": "Endpoint not found"}), 404
    return render_template('index.html'), 200

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large (max 32MB)"}), 413

@app.errorhandler(500)
def internal_error(e):
    log("ERROR", f"500: {str(e)}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    log("INFO", "OSINT Shield started (LeakCheck integrated)")
    app.run(debug=True, host='0.0.0.0', port=5000)