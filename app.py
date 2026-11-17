import os
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set SECRET_KEY in the hosting environment.")
db_url = os.environ.get("DATABASE_URL", "sqlite:///tahaqqaq.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
VT_API = "https://www.virustotal.com/api/v3"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    scans = db.relationship("Scan", backref="user", lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    kind = db.Column(db.String(20), nullable=False)
    item = db.Column(db.String(500), nullable=False)
    verdict = db.Column(db.String(120), nullable=False)
    malicious = db.Column(db.Integer, default=0)
    suspicious = db.Column(db.Integer, default=0)
    harmless = db.Column(db.Integer, default=0)
    undetected = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class RegisterForm(FlaskForm):
    username = StringField("اسم المستخدم", validators=[DataRequired(), Length(min=3, max=40)])
    email = StringField("البريد الإلكتروني", validators=[DataRequired(), Length(max=254)])
    password = PasswordField("كلمة المرور", validators=[DataRequired(), Length(min=12, max=128)])
    confirm = PasswordField("تأكيد كلمة المرور", validators=[DataRequired(), EqualTo("password")])

class LoginForm(FlaskForm):
    email = StringField("البريد الإلكتروني", validators=[DataRequired(), Length(max=254)])
    password = PasswordField("كلمة المرور", validators=[DataRequired()])

class URLForm(FlaskForm):
    url = StringField("الرابط", validators=[DataRequired(), Length(max=2048)])
    consent = BooleanField("أوافق على إرسال الرابط إلى VirusTotal وفق سياسة الخدمة", validators=[DataRequired()])

class FileConsentForm(FlaskForm):
    consent = BooleanField("أوافق على رفع الملف إلى VirusTotal، وقد يُخزن أو يُشارك وفق سياسة الخدمة", validators=[DataRequired()])

def headers():
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        raise RuntimeError("مسؤول المنصة لم يضبط مفتاح VirusTotal على الخادم.")
    return {"x-apikey": key, "accept": "application/json"}

def stats_result(stats):
    m = int(stats.get("malicious", 0) or 0)
    s = int(stats.get("suspicious", 0) or 0)
    h = int(stats.get("harmless", 0) or 0)
    u = int(stats.get("undetected", 0) or 0)
    total = sum(int(stats.get(k, 0) or 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout", "failure"))
    percent = round(100 * (m + s) / total, 1) if total else 0
    verdict = "ضار" if m else ("مشبوه" if s else "لم ترصد المحركات مؤشرات ضارة")
    return m, s, h, u, percent, verdict

def poll_analysis(analysis_id):
    import time
    for _ in range(18):
        r = requests.get(f"{VT_API}/analyses/{analysis_id}", headers=headers(), timeout=25)
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        if attrs.get("status") == "completed":
            return attrs.get("stats", {})
        time.sleep(5)
    raise RuntimeError("لم يكتمل التحليل خلال وقت الانتظار.")

def save_scan(kind, item, stats, verdict):
    m, s, h, u, _, _ = stats_result(stats)
    db.session.add(Scan(user_id=current_user.id, kind=kind, item=item[:500],
                        verdict=verdict, malicious=m, suspicious=s,
                        harmless=h, undetected=u))
    db.session.commit()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username, email = form.username.data.strip(), form.email.data.strip().lower()
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("اسم المستخدم أو البريد مستخدم بالفعل.", "error")
        else:
            user = User(username=username, email=email,
                        password_hash=generate_password_hash(form.password.data))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("dashboard"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("بيانات الدخول غير صحيحة.", "error")
    return render_template("login.html", form=form)

@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(30).all()
    return render_template("dashboard.html", scans=scans)

@app.route("/scan/url", methods=["GET", "POST"])
@login_required
def scan_url():
    form = URLForm()
    if form.validate_on_submit():
        raw = form.url.data.strip()
        parsed = urlsplit(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            flash("الرابط غير صالح.", "error")
            return render_template("scan_url.html", form=form)
        try:
            r = requests.post(f"{VT_API}/urls", headers=headers(), data={"url": raw}, timeout=30)
            r.raise_for_status()
            stats = poll_analysis(r.json()["data"]["id"])
            m, s, h, u, percent, verdict = stats_result(stats)
            save_scan("رابط", raw, stats, verdict)
            return render_template("result.html", item=raw, kind="رابط", malicious=m,
                                   suspicious=s, harmless=h, undetected=u,
                                   percent=percent, verdict=verdict)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            flash(f"رفضت VirusTotal الطلب (HTTP {code}). تحقق من صلاحية API وحدود الحساب.", "error")
        except (requests.RequestException, RuntimeError, KeyError) as e:
            flash(f"تعذر إكمال الفحص: {e}", "error")
    return render_template("scan_url.html", form=form)

@app.route("/scan/file", methods=["GET", "POST"])
@login_required
def scan_file():
    form = FileConsentForm()
    if request.method == "POST" and form.validate_on_submit():
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("اختر ملفاً أولاً.", "error")
            return render_template("scan_file.html", form=form)
        filename = uploaded.filename.replace("/", "_").replace("\\", "_")[:180]
        data = uploaded.read(32 * 1024 * 1024 + 1)
        if not data or len(data) > 32 * 1024 * 1024:
            flash("الملف فارغ أو يتجاوز 32 ميجابايت.", "error")
            return render_template("scan_file.html", form=form)
        digest = hashlib.sha256(data).hexdigest()
        try:
            lookup = requests.get(f"{VT_API}/files/{digest}", headers=headers(), timeout=25)
            if lookup.status_code == 200:
                stats = lookup.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            elif lookup.status_code == 404:
                up = requests.post(f"{VT_API}/files", headers=headers(),
                                   files={"file": (filename, data)}, timeout=90)
                up.raise_for_status()
                stats = poll_analysis(up.json()["data"]["id"])
            else:
                lookup.raise_for_status()
                stats = {}
            m, s, h, u, percent, verdict = stats_result(stats)
            save_scan("ملف", filename, stats, verdict)
            return render_template("result.html", item=filename, kind="ملف",
                                   malicious=m, suspicious=s, harmless=h,
                                   undetected=u, percent=percent, verdict=verdict,
                                   digest=digest)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            flash(f"رفضت VirusTotal الطلب (HTTP {code}). تحقق من API وحدود الحساب.", "error")
        except (requests.RequestException, RuntimeError, KeyError) as e:
            flash(f"تعذر إكمال الفحص: {e}", "error")
    return render_template("scan_file.html", form=form)

@app.errorhandler(413)
def too_large(_):
    flash("الملف أكبر من الحد المسموح.", "error")
    return redirect(url_for("scan_file"))

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
