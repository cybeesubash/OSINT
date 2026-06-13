# OSINT-AI-driven-Data-Breach-Detection
<div align="center">

# 🛡️ OSINT Shield
### AI-Driven Identity & Data Leak Detection System

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![OpenCV](https://img.shields.io/badge/OpenCV-4.9-5C3EE8?style=flat-square&logo=opencv&logoColor=white)](https://opencv.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Subash%20Kumar-7b2fff?style=flat-square)](https://github.com/masssubash240)

**Detect data leaks · Reverse-search images · Track fake profiles · Get instant alerts**

[Live Demo](#) · [Report Bug](../../issues) · [Request Feature](../../issues)

</div>

---

## 📌 About

**OSINT Shield** is an AI-powered open-source intelligence platform built by **Subash Kumar** ([@masssubash240](https://github.com/masssubash240))
that helps individuals, researchers and security teams detect **data leaks**, **image misuse**
and **fake profiles** in real time — all from a single dashboard.

> Built with Python · Flask · OpenCV · HaveIBeenPwned · SerpAPI Google Lens · Imagga AI · Google Vision API

---

## ✨ Features

| Feature | Description | API |
|---|---|---|
| 🔴 **Deepfake Detection** | OpenCV + Imagga AI multi-model analysis | Imagga |
| 🔍 **Reverse Image Search** | Find your photo across the entire internet | SerpAPI |
| 💀 **Data Breach Check** | 10B+ compromised accounts checked | HIBP v3 |
| 👤 **Identity OSINT** | 20+ platforms searched in parallel | HTTP probing |
| 📋 **Metadata Extractor** | GPS, device model, timestamps from EXIF | Pillow |
| 📧 **Email Alerts** | Instant HTML alerts for HIGH/CRITICAL scans | Gmail SMTP |
| 📄 **PDF Reports** | One-click downloadable scan report | ReportLab |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/masssubash240/OSINT-AI-driven-Data-Breach-Detection.git
cd OSINT-AI-driven-Data-Breach-Detection

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export ALERT_EMAIL=your@gmail.com
export ALERT_PASSWORD=your_app_password
export SERPAPI_KEY=your_serpapi_key
export IMGUR_CLIENT_ID=your_imgur_client_id
export IMAGGA_SECRET=your_imagga_secret

# Run
python app.py
```

Open browser → **http://localhost:5000**

---

## 📁 Project Structure

```
osint-shield/
├── app.py                 ← Flask backend (all 6 modules)
├── requirements.txt       ← Python dependencies
├── google_credentials.json← (optional) Google Vision API
├── uploads/               ← Uploaded files
├── reports/               ← Generated PDF reports
└── templates/
    └── index.html         ← Full frontend dashboard
```

---

## ⚙️ Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SUPABASE_URL` | **Required** | Supabase project API URL |
| `SUPABASE_KEY` | **Required** | Supabase anon key or service role key |
| `HIBP_API_KEY` | Optional | HaveIBeenPwned API key |
| `SERPAPI_KEY` | Recommended | Google Lens reverse image search |
| `IMGUR_CLIENT_ID` | Recommended | Image upload for SerpAPI |
| `IMAGGA_SECRET` | Optional | AI tagging & face detection |
| `ALERT_EMAIL` | Optional | Gmail for sending alerts |
| `ALERT_PASSWORD` | Optional | Gmail 16-char App Password |

---

## 🛠️ Tech Stack

- **Backend** — Python 3.11 · Flask 3.0 · Supabase · Celery
- **AI / CV** — OpenCV 4.9 · Pillow · NumPy · FaceNet · CLIP
- **APIs** — HaveIBeenPwned v3 · SerpAPI · Imagga · Google Vision
- **Frontend** — HTML5 · CSS3 · Vanilla JavaScript
- **Infra** — Docker-ready · Redis-compatible · ReportLab PDF

---

## 🔒 Privacy & Security

- No personal data permanently stored — uploads auto-expire
- Passwords **never stored** — k-anonymity SHA1 prefix only sent to HIBP
- All API calls via HTTPS
- Deepfake & metadata analysis runs entirely locally

---

## 🤝 Contributing

Contributions, issues and feature requests are welcome!

1. Fork the project
2. Create your branch: `git checkout -b feature/AmazingFeature`
3. Commit: `git commit -m 'Add AmazingFeature'`
4. Push: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

---

<div align="center">
Made with ❤️ by <b>Subash Kumar</b> (<a href="https://github.com/masssubash240">@masssubash240</a>) &nbsp;·&nbsp; Built for the cybersecurity community
<br><br>
⭐ Star this repo if it helped you!
</div>
