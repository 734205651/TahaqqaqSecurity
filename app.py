import os
import hashlib
import time
from collections import deque
from threading import Lock
from urllib.parse import urlsplit

import requests

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, BooleanField
from wtforms.validators import DataRequired, Length


# ==========================================
# T A H A Q Q A Q  6.0
# منصة تَحَقَّق للأمن السيبراني
# تصميم: محروس باحسين
# دخول مباشر بدون حسابات
# ==========================================

APP_NAME = "تَحَقَّق"
VERSION = "6.0"
AUTHOR = "محروس باحسين"

VT_API = "https://www.virustotal.com/api/v3"


# ==========================================
# APPLICATION
# ==========================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "SECRET_KEY غير مضبوط في إعدادات Render."
    )

# الحد الأقصى لحجم الملف: 32 ميجابايت
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

csrf = CSRFProtect(app)


# ==========================================
# RATE LIMITING
# ==========================================
# 4 طلبات كحد أقصى في الدقيقة
# 500 طلب كحد أقصى في اليوم
#
# هذه النسخة تستخدم ذاكرة الخادم فقط.
# عند إعادة تشغيل Render يتم تصفير العدادات.

RATE_LOCK = Lock()

MINUTE_LIMIT = 4
DAILY_LIMIT = 500

minute_requests = deque()
daily_requests = deque()


def check_rate_limit():

    now = time.time()

    with RATE_LOCK:

        # حذف طلبات أقدم من دقيقة
        while minute_requests and (
            now - minute_requests[0] > 60
        ):
            minute_requests.popleft()

        # حذف طلبات أقدم من 24 ساعة
        while daily_requests and (
            now - daily_requests[0] > 86400
        ):
            daily_requests.popleft()

        if len(minute_requests) >= MINUTE_LIMIT:
            return False, (
                "تم الوصول إلى الحد المؤقت: "
                "4 فحوصات في الدقيقة. "
                "انتظر قليلاً ثم حاول مرة أخرى."
            )

        if len(daily_requests) >= DAILY_LIMIT:
            return False, (
                "تم الوصول إلى الحد اليومي "
                "للفحوصات. حاول غداً."
            )

        minute_requests.append(now)
        daily_requests.append(now)

    return True, None


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
        "أوافق على إرسال الرابط إلى VirusTotal",
        validators=[DataRequired()]
    )


class FileConsentForm(FlaskForm):

    consent = BooleanField(
        "أوافق على رفع الملف إلى VirusTotal",
        validators=[DataRequired()]
    )


# ==========================================
# VIRUSTOTAL CONFIGURATION
# ==========================================

def vt_headers():

    key = os.environ.get(
        "VT_API_KEY",
        ""
    ).strip()

    if not key:

        raise RuntimeError(
            "فحص VirusTotal غير مفعّل حالياً. "
            "أضف VT_API_KEY في إعدادات Render."
        )

    return {
        "x-apikey": key,
        "accept": "application/json"
    }


# ==========================================
# ANALYSIS RESULTS
# ==========================================

def stats_result(stats):

    malicious = int(
        stats.get("malicious", 0) or 0
    )

    suspicious = int(
        stats.get("suspicious", 0) or 0
    )

    harmless = int(
        stats.get("harmless", 0) or 0
    )

    undetected = int(
        stats.get("undetected", 0) or 0
    )

    total = sum(
        int(stats.get(k, 0) or 0)
        for k in (
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "timeout",
            "failure"
        )
    )

    percentage = (
        round(
            100 * (malicious + suspicious) / total,
            1
        )
        if total else 0
    )

    if malicious:
        verdict = "ضار"

    elif suspicious:
        verdict = "مشبوه"

    else:
        verdict = "لم ترصد المحركات مؤشرات ضارة"

    return (
        malicious,
        suspicious,
        harmless,
        undetected,
        percentage,
        verdict
    )


# ==========================================
# WAIT FOR VIRUSTOTAL ANALYSIS
# ==========================================

def poll_analysis(analysis_id):

    for _ in range(18):

        response = requests.get(
            f"{VT_API}/analyses/{analysis_id}",
            headers=vt_headers(),
            timeout=25
        )

        response.raise_for_status()

        attributes = response.json().get(
            "data",
            {}
        ).get(
            "attributes",
            {}
        )

        if attributes.get("status") == "completed":

            return attributes.get(
                "stats",
                {}
            )

        time.sleep(5)

    raise RuntimeError(
        "لم يكتمل التحليل خلال وقت الانتظار."
    )


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ==========================================
# OLD ACCOUNT ROUTES
# ==========================================
# لا يوجد تسجيل أو دخول.
# هذه المسارات موجودة فقط حتى لا تظهر
# أخطاء إذا كانت هناك روابط قديمة في القوالب.

@app.route("/register", methods=["GET", "POST"])
def register():

    return redirect(
        url_for("index")
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    return redirect(
        url_for("index")
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():

    return redirect(
        url_for("index")
    )


@app.route("/dashboard")
def dashboard():

    return redirect(
        url_for("index")
    )


# ==========================================
# URL SCANNER
# ==========================================

@app.route(
    "/scan/url",
    methods=["GET", "POST"]
)
def scan_url():

    form = URLForm()

    if form.validate_on_submit():

        allowed, message = check_rate_limit()

        if not allowed:

            flash(
                message,
                "error"
            )

            return render_template(
                "scan_url.html",
                form=form
            )

        raw_url = form.url.data.strip()

        parsed = urlsplit(
            raw_url
        )

        if (
            parsed.scheme not in (
                "http",
                "https"
            )
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):

            flash(
                "الرابط غير صالح.",
                "error"
            )

            return render_template(
                "scan_url.html",
                form=form
            )

        try:

            response = requests.post(
                f"{VT_API}/urls",
                headers=vt_headers(),
                data={
                    "url": raw_url
                },
                timeout=30
            )

            response.raise_for_status()

            analysis_id = response.json()[
                "data"
            ]["id"]

            stats = poll_analysis(
                analysis_id
            )

            (
                malicious,
                suspicious,
                harmless,
                undetected,
                percentage,
                verdict
            ) = stats_result(stats)

            return render_template(
                "result.html",
                item=raw_url,
                kind="رابط",
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                percent=percentage,
                verdict=verdict
            )

        except requests.HTTPError as error:

            code = (
                error.response.status_code
                if error.response is not None
                else "?"
            )

            flash(
                f"رفضت VirusTotal الطلب "
                f"(HTTP {code}). "
                "تحقق من صلاحية API وحدود الحساب.",
                "error"
            )

        except (
            requests.RequestException,
            RuntimeError,
            KeyError
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

@app.route(
    "/scan/file",
    methods=["GET", "POST"]
)
def scan_file():

    form = FileConsentForm()

    if (
        request.method == "POST"
        and form.validate_on_submit()
    ):

        allowed, message = check_rate_limit()

        if not allowed:

            flash(
                message,
                "error"
            )

            return render_template(
                "scan_file.html",
                form=form
            )

        uploaded = request.files.get(
            "file"
        )

        if (
            not uploaded
            or not uploaded.filename
        ):

            flash(
                "اختر ملفاً أولاً.",
                "error"
            )

            return render_template(
                "scan_file.html",
                form=form
            )

        filename = (
            uploaded.filename
            .replace("/", "_")
            .replace("\\", "_")
        )[:180]

        data = uploaded.read(
            32 * 1024 * 1024 + 1
        )

        if (
            not data
            or len(data)
            > 32 * 1024 * 1024
        ):

            flash(
                "الملف فارغ أو يتجاوز "
                "32 ميجابايت.",
                "error"
            )

            return render_template(
                "scan_file.html",
                form=form
            )

        digest = hashlib.sha256(
            data
        ).hexdigest()

        try:

            lookup = requests.get(
                f"{VT_API}/files/{digest}",
                headers=vt_headers(),
                timeout=25
            )

            if lookup.status_code == 200:

                stats = (
                    lookup.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get(
                        "last_analysis_stats",
                        {}
                    )
                )

            elif lookup.status_code == 404:

                upload = requests.post(
                    f"{VT_API}/files",
                    headers=vt_headers(),
                    files={
                        "file": (
                            filename,
                            data
                        )
                    },
                    timeout=90
                )

                upload.raise_for_status()

                analysis_id = (
                    upload.json()
                    ["data"]
                    ["id"]
                )

                stats = poll_analysis(
                    analysis_id
                )

            else:

                lookup.raise_for_status()

                stats = {}

            (
                malicious,
                suspicious,
                harmless,
                undetected,
                percentage,
                verdict
            ) = stats_result(stats)

            return render_template(
                "result.html",
                item=filename,
                kind="ملف",
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                percent=percentage,
                verdict=verdict,
                digest=digest
            )

        except requests.HTTPError as error:

            code = (
                error.response.status_code
                if error.response is not None
                else "?"
            )

            flash(
                f"رفضت VirusTotal الطلب "
                f"(HTTP {code}). "
                "تحقق من صلاحية API وحدود الحساب.",
                "error"
            )

        except (
            requests.RequestException,
            RuntimeError,
            KeyError
        ) as error:

            flash(
                f"تعذر إكمال الفحص: {error}",
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

    return redirect(
        url_for("scan_file")
    )


# ==========================================
# ERROR HANDLER
# ==========================================

@app.errorhandler(500)
def internal_error(error):

    return render_template(
        "index.html"
    ), 500


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False
    )
