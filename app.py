
import os
import time
import hashlib
from collections import deque
from threading import Lock
from urllib.parse import urlsplit

import requests

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash
)

from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, BooleanField
from wtforms.validators import DataRequired, Length


# ==========================================
# T A H A Q Q A Q  7.0
# منصة تَحَقَّق للأمن السيبراني
# تصميم: محروس باحسين
# ==========================================

APP_NAME = "تَحَقَّق"
VERSION = "7.0"
AUTHOR = "محروس باحسين"

VT_API = "https://www.virustotal.com/api/v3"

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY غير مضبوط في Render.")

app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

csrf = CSRFProtect(app)


# ==========================================
# VIRUSTOTAL API REQUEST LIMITER
# ==========================================
# الحد هنا على طلبات API الفعلية، وليس عمليات الفحص.
# 4 طلبات في الدقيقة و500 طلب خلال 24 ساعة.
# العدادات مؤقتة داخل عملية الخادم الحالية.

RATE_LOCK = Lock()
minute_requests = deque()
daily_requests = deque()

MINUTE_LIMIT = 4
DAILY_LIMIT = 500


def wait_for_api_slot():

    while True:

        with RATE_LOCK:

            now = time.time()

            while minute_requests and now - minute_requests[0] >= 60:
                minute_requests.popleft()

            while daily_requests and now - daily_requests[0] >= 86400:
                daily_requests.popleft()

            if len(daily_requests) >= DAILY_LIMIT:
                raise RuntimeError(
                    "تم بلوغ الحد اليومي لطلبات الفحص. حاول لاحقاً."
                )

            if len(minute_requests) < MINUTE_LIMIT:

                minute_requests.append(now)
                daily_requests.append(now)
                return

            wait_time = max(
                1,
                60 - (now - minute_requests[0]) + 0.2
            )

        time.sleep(wait_time)


# ==========================================
# FORMS
# ==========================================

class URLForm(FlaskForm):

    url = StringField(
        "الرابط",
        validators=[
            DataRequired(),
            Length(max=2048)
        ]
    )

    consent = BooleanField(
        "أوافق",
        validators=[DataRequired()]
    )


class FileConsentForm(FlaskForm):

    consent = BooleanField(
        "أوافق",
        validators=[DataRequired()]
    )


# ==========================================
# API CONFIGURATION
# ==========================================

def vt_headers():

    key = os.environ.get("VT_API_KEY", "").strip()

    if not key:
        raise RuntimeError(
            "خدمة الفحص الخارجي غير مفعّلة حالياً."
        )

    return {
        "x-apikey": key,
        "accept": "application/json"
    }


def vt_request(method, endpoint, **kwargs):

    wait_for_api_slot()

    response = requests.request(
        method,
        f"{VT_API}/{endpoint.lstrip('/')}",
        headers=vt_headers(),
        timeout=kwargs.pop("timeout", 30),
        **kwargs
    )

    response.raise_for_status()

    return response


# ==========================================
# REAL SCAN STATISTICS
# ==========================================

def stats_result(stats):

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    # إجمالي المحركات التي أعطت إحدى النتائج الأربع.
    # لا نحتسب timeout أو failure كمحركات أصدرت حكماً.

    total = (
        malicious +
        suspicious +
        harmless +
        undetected
    )

    percentage = (
        round(
            ((malicious + suspicious) / total) * 100,
            1
        )
        if total else 0
    )

    if total == 0:
        verdict = "لا توجد نتائج مكتملة"
        risk_level = "غير محسوم"

    elif malicious > 0:
        verdict = "تم اكتشاف مؤشرات ضارة"
        risk_level = "خطورة مرتفعة"

    elif suspicious > 0:
        verdict = "تم اكتشاف مؤشرات مشبوهة"
        risk_level = "يحتاج إلى الحذر"

    else:
        verdict = "لم ترصد المحركات مؤشرات ضارة"
        risk_level = "لم ترصد مؤشرات ضارة"

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "percent": percentage,
        "verdict": verdict,
        "risk_level": risk_level
    }


# ==========================================
# WAIT FOR ANALYSIS
# ==========================================

def poll_analysis(analysis_id):

    for _ in range(18):

        response = vt_request(
            "GET",
            f"analyses/{analysis_id}",
            timeout=30
        )

        attributes = response.json().get(
            "data", {}
        ).get(
            "attributes", {}
        )

        if attributes.get("status") == "completed":

            return attributes.get("stats", {})

        time.sleep(5)

    raise RuntimeError(
        "لم يكتمل الفحص خلال وقت الانتظار."
    )


# ==========================================
# RESULT PAGE
# ==========================================

def show_result(item, kind, stats, digest=None):

    result = stats_result(stats)

    return render_template(
        "result.html",
        item=item,
        kind=kind,
        malicious=result["malicious"],
        suspicious=result["suspicious"],
        harmless=result["harmless"],
        undetected=result["undetected"],
        total=result["total"],
        percent=result["percent"],
        verdict=result["verdict"],
        risk_level=result["risk_level"],
        digest=digest
    )


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def index():

    return render_template("index.html")


# ==========================================
# DISABLE OLD ACCOUNT PAGES
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():

    return redirect(url_for("index"))


@app.route("/logout", methods=["GET", "POST"])
def logout():

    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():

    return redirect(url_for("index"))


# ==========================================
# URL SCANNER
# ==========================================

@app.route("/scan/url", methods=["GET", "POST"])
def scan_url():

    form = URLForm()

    if form.validate_on_submit():

        raw_url = form.url.data.strip()

        try:

            parsed = urlsplit(raw_url)

            if (
                parsed.scheme.lower() not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                flash("الرابط غير صالح.", "error")
                return render_template(
                    "scan_url.html",
                    form=form
                )

        except ValueError:
            flash("الرابط غير صالح.", "error")
            return render_template(
                "scan_url.html",
                form=form
            )

        try:

            response = vt_request(
                "POST",
                "urls",
                data={"url": raw_url},
                timeout=30
            )

            analysis_id = response.json()["data"]["id"]

            stats = poll_analysis(analysis_id)

            return show_result(
                raw_url,
                "رابط",
                stats
            )

        except requests.HTTPError as error:

            code = (
                error.response.status_code
                if error.response is not None
                else "?"
            )

            flash(
                f"تعذر إكمال الفحص (HTTP {code}). "
                "تحقق من صلاحية الخدمة وحدود الاستخدام.",
                "error"
            )

        except (
            requests.RequestException,
            RuntimeError,
            KeyError,
            ValueError
        ) as error:

            flash(
                f"تعذر إكمال الفحص: {error}",
                "error"
            )

    return render_template(
        "scan_url.html",
        form=form
    )


# ==========================================
# FILE SCANNER
# ==========================================

@app.route("/scan/file", methods=["GET", "POST"])
def scan_file():

    form = FileConsentForm()

    if request.method == "POST" and form.validate_on_submit():

        uploaded = request.files.get("file")

        if not uploaded or not uploaded.filename:

            flash("اختر ملفاً أولاً.", "error")

            return render_template(
                "scan_file.html",
                form=form
            )

        filename = (
            uploaded.filename
            .replace("/", "_")
            .replace("\\", "_")
        )[:180]

        data = uploaded.read(32 * 1024 * 1024 + 1)

        if not data or len(data) > 32 * 1024 * 1024:

            flash(
                "الملف فارغ أو يتجاوز 32 ميجابايت.",
                "error"
            )

            return render_template(
                "scan_file.html",
                form=form
            )

        digest = hashlib.sha256(data).hexdigest()

        try:

            # البحث أولاً عن بصمة الملف.
            lookup = vt_request(
                "GET",
                f"files/{digest}",
                timeout=30
            )

            stats = lookup.json().get(
                "data", {}
            ).get(
                "attributes", {}
            ).get(
                "last_analysis_stats", {}
            )

            return show_result(
                filename,
                "ملف",
                stats,
                digest
            )

        except requests.HTTPError as error:

            code = (
                error.response.status_code
                if error.response is not None
                else "?"
            )

            if code != 404:

                flash(
                    f"تعذر البحث عن الملف (HTTP {code}).",
                    "error"
                )

                return render_template(
                    "scan_file.html",
                    form=form
                )

        try:

            # رفع الملف إذا لم تكن له نتيجة سابقة.
            upload = vt_request(
                "POST",
                "files",
                files={
                    "file": (filename, data)
                },
                timeout=120
            )

            analysis_id = upload.json()["data"]["id"]

            stats = poll_analysis(analysis_id)

            return show_result(
                filename,
                "ملف",
                stats,
                digest
            )

        except requests.HTTPError as error:

            code = (
                error.response.status_code
                if error.response is not None
                else "?"
            )

            flash(
                f"تعذر رفع الملف أو فحصه (HTTP {code}).",
                "error"
            )

        except (
            requests.RequestException,
            RuntimeError,
            KeyError,
            ValueError
        ) as error:

            flash(
                f"تعذر إكمال فحص الملف: {error}",
                "error"
            )

    return render_template(
        "scan_file.html",
        form=form
    )


# ==========================================
# FILE SIZE ERROR
# ==========================================

@app.errorhandler(413)
def too_large(error):

    flash(
        "الملف أكبر من الحد المسموح.",
        "error"
    )

    return redirect(url_for("scan_file"))


# ==========================================
# ERROR HANDLER
# ==========================================

@app.errorhandler(500)
def internal_error(error):

    app.logger.exception("Internal server error")

    return (
        "حدث خطأ داخلي. حاول مرة أخرى لاحقاً.",
        500
    )


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
