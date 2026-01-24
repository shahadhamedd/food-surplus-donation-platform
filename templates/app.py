from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import or_
import re
from urllib.parse import quote_plus  # ✅ keep one import only

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)

app.secret_key = "mysecret123"
app.permanent_session_lifetime = timedelta(days=7)

# ============================
# ADMIN PIN (Only this PIN)
# ============================
ADMIN_PIN = "4444"

# ----------------------------
# Database + Uploads
# ----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "project.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)

# ----------------------------
# Models
# ----------------------------
class Provider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    verification_status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.String(50))
    image = db.Column(db.String(200))

    email_verified = db.Column(db.Boolean, default=True)

    verification_code = db.Column(db.String(10))
    code_expires_at = db.Column(db.String(50))

    # ============================================================
    # ✅ ADDED ONLY — Security Question (Forgot Password via Q/A)
    # ============================================================
    security_question = db.Column(db.String(250))
    security_answer_hash = db.Column(db.String(300))


class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.String(50))
    document = db.Column(db.String(200))

    email_verified = db.Column(db.Boolean, default=True)

    verification_code = db.Column(db.String(10))
    code_expires_at = db.Column(db.String(50))

    # ============================================================
    # ✅ ADDED ONLY — Security Question (Forgot Password via Q/A)
    # ============================================================
    security_question = db.Column(db.String(250))
    security_answer_hash = db.Column(db.String(300))


class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey("provider.id"), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(400))
    quantity = db.Column(db.String(80))
    category = db.Column(db.String(100))
    status = db.Column(db.String(30), default="Pending")
    created_at = db.Column(db.String(50))

    provider = db.relationship("Provider", backref=db.backref("donations", lazy=True))


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey("donation.id"), nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey("beneficiary.id"), nullable=False)
    status = db.Column(db.String(30), default="Pending")
    created_at = db.Column(db.String(50))

    # ============================================================
    # ✅ ADDED ONLY (No change to existing)
    # ============================================================
    approved_at = db.Column(db.String(50))                 # وقت الموافقة
    pickup_time = db.Column(db.String(50))                 # موعد الاستلام
    provider_pickup_location = db.Column(db.String(250))   # لوكيشن الاستلام من المزود
    started_at = db.Column(db.String(50))                  # وقت الضغط على Start

    donation = db.relationship("Donation", backref=db.backref("requests", lazy=True))
    beneficiary = db.relationship("Beneficiary", backref=db.backref("requests", lazy=True))


# ============================================================
# ✅ ADDED ONLY — Provider Location table (Address + lat/lng)
# ============================================================
class ProviderLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey("provider.id"), nullable=False, unique=True)

    address_line1 = db.Column(db.String(200), nullable=False)
    address_line2 = db.Column(db.String(200))
    city = db.Column(db.String(120), nullable=False)
    state = db.Column(db.String(120), nullable=False)
    notes = db.Column(db.String(400))

    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

    provider = db.relationship("Provider", backref=db.backref("location", uselist=False))


with app.app_context():
    db.create_all()


# ============================================================
# ✅ ADDED ONLY — SQLite auto-migrate new columns (safe ALTER)
# create_all() won't add new columns in SQLite
# ============================================================
def _sqlite_has_column(table_name: str, column_name: str) -> bool:
    try:
        rows = db.session.execute(db.text(f"PRAGMA table_info({table_name})")).fetchall()
        cols = [r[1] for r in rows]
        return column_name in cols
    except Exception:
        return False


def _sqlite_add_column(table_name: str, column_name: str, column_def: str):
    try:
        db.session.execute(db.text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}"))
        db.session.commit()
    except Exception:
        db.session.rollback()


with app.app_context():
    # Provider
    if not _sqlite_has_column("provider", "security_question"):
        _sqlite_add_column("provider", "security_question", "VARCHAR(250)")
    if not _sqlite_has_column("provider", "security_answer_hash"):
        _sqlite_add_column("provider", "security_answer_hash", "VARCHAR(300)")

    # Beneficiary
    if not _sqlite_has_column("beneficiary", "security_question"):
        _sqlite_add_column("beneficiary", "security_question", "VARCHAR(250)")
    if not _sqlite_has_column("beneficiary", "security_answer_hash"):
        _sqlite_add_column("beneficiary", "security_answer_hash", "VARCHAR(300)")


# ----------------------------
# Helpers
# ----------------------------
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def build_google_maps_urls(location_text: str):
    loc = (location_text or "").strip()
    if not loc:
        return None, None

    if loc.startswith("http://") or loc.startswith("https://"):
        open_url = loc
        if "/maps/embed" in loc:
            return loc, open_url
        q = quote_plus(loc)
        return f"https://www.google.com/maps?q={q}&output=embed", open_url

    q = quote_plus(loc)
    open_url = f"https://www.google.com/maps?q={q}"
    embed_url = f"https://www.google.com/maps?q={q}&output=embed"
    return embed_url, open_url


# ✅ ADDED ONLY — build from lat/lng
def build_google_maps_urls_from_coords(lat, lng):
    try:
        lat = float(lat)
        lng = float(lng)
    except Exception:
        return None, None
    open_url = f"https://www.google.com/maps?q={lat},{lng}"
    embed_url = f"https://www.google.com/maps?q={lat},{lng}&output=embed"
    return embed_url, open_url


# ✅ ADDED ONLY — fetch provider location + formatted text
def get_provider_location(provider_id: int):
    if not provider_id:
        return None
    return ProviderLocation.query.filter_by(provider_id=provider_id).first()


def provider_location_text(loc: ProviderLocation):
    if not loc:
        return ""
    parts = []
    if loc.address_line1:
        parts.append(loc.address_line1)
    if loc.address_line2:
        parts.append(loc.address_line2)
    if loc.city:
        parts.append(loc.city)
    if loc.state:
        parts.append(loc.state)
    return ", ".join([p for p in parts if p])


def save_uploaded_file(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    filename = secure_filename(file_storage.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file_storage.save(path)
    return filename


def redirect_if_logged_in():
    if session.get("user_id"):
        role = session.get("role")
        if role == "provider":
            return redirect(url_for("provider_dashboard"))
        if role == "beneficiary":
            return redirect(url_for("beneficiary_dashboard"))
    return None


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login", role=role) if role else url_for("login"))
            if role and session.get("role") != role:
                session.clear()
                return redirect(url_for("login", role=role))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper


def template_exists(name: str) -> bool:
    return os.path.exists(os.path.join(app.root_path, "templates", name))


def is_valid_email(email: str) -> bool:
    email = (email or "").strip().lower()
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None


def is_strong_password(pw: str) -> bool:
    if not pw or len(pw) < 12:
        return False
    if re.search(r"\s", pw):
        return False
    has_lower = re.search(r"[a-z]", pw) is not None
    has_upper = re.search(r"[A-Z]", pw) is not None
    has_digit = re.search(r"\d", pw) is not None
    has_symbol = re.search(r"[^\w\s]", pw) is not None
    return has_lower and has_upper and has_digit and has_symbol


def normalize_security_answer(ans: str) -> str:
    return (ans or "").strip().lower()


# ----------------------------
# Static uploads route
# ----------------------------
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ============================================================
# MAIN PAGE
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard_redirect():
    r = redirect_if_logged_in()
    if r:
        return r
    return redirect(url_for("login"))


@app.route("/home")
def home():
    return redirect(url_for("index"))


@app.route("/main")
def main_page():
    return redirect(url_for("index"))


# ----------------------------
# Choose Role
# ----------------------------
@app.route("/choose-role")
def choose_role():
    return render_template("choose_role.html")


@app.route("/switch-role")
def switch_role():
    admin_flag = session.get("admin")
    session.clear()
    if admin_flag:
        session["admin"] = True
    return redirect(url_for("choose_role"))


# ----------------------------
# Provider options + register
# ----------------------------
@app.route("/provider/options")
def provider_options():
    r = redirect_if_logged_in()
    if r and session.get("role") == "provider":
        return r
    return render_template("provider_options.html")


@app.route("/register/provider/<category>", methods=["GET", "POST"])
def register_provider(category):
    if session.get("user_id"):
        session.clear()

    error = None

    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]

        email = (request.form.get("provider_email") or request.form.get("email") or "").strip().lower()
        raw_password = request.form.get("provider_password") or request.form.get("password") or ""

        security_question = (request.form.get("security_question") or "").strip()
        security_answer = normalize_security_answer(request.form.get("security_answer") or "")

        address = request.form["address"]
        created_at = now_str()

        if not is_valid_email(email):
            error = "Invalid email format"
            return render_template("provider_register.html", category=category, error=error)

        if not is_strong_password(raw_password):
            error = "Password must be 12+ with upper/lower/number/symbol"
            return render_template("provider_register.html", category=category, error=error)

        if not security_question:
            error = "Please choose a security question"
            return render_template("provider_register.html", category=category, error=error)

        if not security_answer or len(security_answer) < 2:
            error = "Please enter a valid security answer"
            return render_template("provider_register.html", category=category, error=error)

        password = generate_password_hash(raw_password)

        existing = Provider.query.filter_by(email=email).first()
        if existing:
            return redirect(url_for("login", role="provider"))

        file = request.files.get("store_image")
        filename = save_uploaded_file(file)

        new_user = Provider(
            full_name=full_name,
            phone=phone,
            email=email,
            password=password,
            address=address,
            category=category,
            verification_status="Pending",
            created_at=created_at,
            image=filename,
            email_verified=True,
            security_question=security_question,
            security_answer_hash=generate_password_hash(security_answer)
        )
        db.session.add(new_user)
        db.session.commit()

        session.permanent = True
        session["user_id"] = new_user.id
        session["role"] = "provider"
        return redirect(url_for("provider_dashboard"))

    return render_template("provider_register.html", category=category, error=error)


# ----------------------------
# Beneficiary options + register
# ----------------------------
@app.route("/beneficiary/options")
def beneficiary_options():
    r = redirect_if_logged_in()
    if r and session.get("role") == "beneficiary":
        return r
    return render_template("beneficiary_options.html")


@app.route("/register/beneficiary/<category>", methods=["GET", "POST"])
def register_beneficiary(category):
    if session.get("user_id"):
        session.clear()

    error = None

    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]

        email = (request.form.get("beneficiary_email") or request.form.get("email") or "").strip().lower()
        raw_password = request.form.get("beneficiary_password") or request.form.get("password") or ""

        security_question = (request.form.get("security_question") or "").strip()
        security_answer = normalize_security_answer(request.form.get("security_answer") or "")

        address = request.form["address"]
        created_at = now_str()

        if not is_valid_email(email):
            error = "Invalid email format"
            return render_template("beneficiary_register.html", category=category, error=error)

        if not is_strong_password(raw_password):
            error = "Password must be 12+ with upper/lower/number/symbol"
            return render_template("beneficiary_register.html", category=category, error=error)

        if not security_question:
            error = "Please choose a security question"
            return render_template("beneficiary_register.html", category=category, error=error)

        if not security_answer or len(security_answer) < 2:
            error = "Please enter a valid security answer"
            return render_template("beneficiary_register.html", category=category, error=error)

        password = generate_password_hash(raw_password)

        existing = Beneficiary.query.filter_by(email=email).first()
        if existing:
            return redirect(url_for("login", role="beneficiary"))

        file = request.files.get("document") or request.files.get("beneficiary_image")
        filename = save_uploaded_file(file)

        new_user = Beneficiary(
            full_name=full_name,
            phone=phone,
            email=email,
            password=password,
            address=address,
            category=category,
            created_at=created_at,
            document=filename,
            email_verified=True,
            security_question=security_question,
            security_answer_hash=generate_password_hash(security_answer)
        )
        db.session.add(new_user)
        db.session.commit()

        session.permanent = True
        session["user_id"] = new_user.id
        session["role"] = "beneficiary"
        return redirect(url_for("beneficiary_dashboard"))

    return render_template("beneficiary_register.html", category=category, error=error)


# ----------------------------
# Login (provider/beneficiary)
# ----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    r = redirect_if_logged_in()
    if r:
        return r

    error = None
    role = request.args.get("role")

    register_link = url_for("choose_role")
    if role == "provider":
        register_link = url_for("provider_options")
    elif role == "beneficiary":
        register_link = url_for("beneficiary_options")

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if role == "provider":
            provider = Provider.query.filter_by(email=email).first()
            if provider and check_password_hash(provider.password, password):
                session.permanent = True
                session["user_id"] = provider.id
                session["role"] = "provider"
                return redirect(url_for("provider_dashboard"))
            error = "Invalid email or password"
            return render_template("login.html", error=error, role=role, register_link=register_link)

        if role == "beneficiary":
            beneficiary = Beneficiary.query.filter_by(email=email).first()
            if beneficiary and check_password_hash(beneficiary.password, password):
                session.permanent = True
                session["user_id"] = beneficiary.id
                session["role"] = "beneficiary"
                return redirect(url_for("beneficiary_dashboard"))
            error = "Invalid email or password"
            return render_template("login.html", error=error, role=role, register_link=register_link)

        provider = Provider.query.filter_by(email=email).first()
        if provider and check_password_hash(provider.password, password):
            session.permanent = True
            session["user_id"] = provider.id
            session["role"] = "provider"
            return redirect(url_for("provider_dashboard"))

        beneficiary = Beneficiary.query.filter_by(email=email).first()
        if beneficiary and check_password_hash(beneficiary.password, password):
            session.permanent = True
            session["user_id"] = beneficiary.id
            session["role"] = "beneficiary"
            return redirect(url_for("beneficiary_dashboard"))

        error = "Invalid email or password"

    return render_template("login.html", error=error, role=role, register_link=register_link)


# ============================================================
# ✅ Forgot Password (Security Question flow)
# ============================================================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    r = redirect_if_logged_in()
    if r:
        return r

    role = (request.args.get("role") or "").strip().lower()
    if role not in ["provider", "beneficiary"]:
        role = "provider"

    error = None
    info = None
    user_email = ""
    question = ""

    if request.method == "POST":
        user_email = (request.form.get("email") or "").strip().lower()

        if not is_valid_email(user_email):
            error = "Invalid email format"
            return render_template("forgot_password.html", role=role, error=error, info=info, email=user_email, question=question)

        if role == "provider":
            u = Provider.query.filter_by(email=user_email).first()
        else:
            u = Beneficiary.query.filter_by(email=user_email).first()

        if not u:
            error = "Account not found"
            return render_template("forgot_password.html", role=role, error=error, info=info, email=user_email, question=question)

        if not (u.security_question and u.security_answer_hash):
            error = "No security question set for this account"
            return render_template("forgot_password.html", role=role, error=error, info=info, email=user_email, question=question)

        question = u.security_question
        info = "Please answer the security question to reset your password."
        return render_template("forgot_password.html", role=role, error=error, info=info, email=user_email, question=question)

    return render_template("forgot_password.html", role=role, error=error, info=info, email=user_email, question=question)


@app.route("/reset-password", methods=["POST"])
def reset_password():
    r = redirect_if_logged_in()
    if r:
        return r

    role = (request.form.get("role") or "").strip().lower()
    if role not in ["provider", "beneficiary"]:
        role = "provider"

    email = (request.form.get("email") or "").strip().lower()
    security_answer = normalize_security_answer(request.form.get("security_answer") or "")
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    error = None
    info = None
    question = ""

    if not is_valid_email(email):
        error = "Invalid email format"
        return render_template("forgot_password.html", role=role, error=error, info=info, email=email, question=question)

    if role == "provider":
        u = Provider.query.filter_by(email=email).first()
    else:
        u = Beneficiary.query.filter_by(email=email).first()

    if not u:
        error = "Account not found"
        return render_template("forgot_password.html", role=role, error=error, info=info, email=email, question=question)

    question = u.security_question or ""

    if not (u.security_question and u.security_answer_hash):
        error = "No security question set for this account"
        return render_template("forgot_password.html", role=role, error=error, info=info, email=email, question=question)

    if not security_answer:
        error = "Please enter your security answer"
        return render_template("forgot_password.html", role=role, error=error, info=info, email=email, question=question)

    if not check_password_hash(u.security_answer_hash, security_answer):
        error = "Security answer is incorrect"
        return render_template("forgot_password.html", role=role, error=error, info=info, email=email, question=question)

    if new_password != confirm_password:
        error = "Passwords do not match"
        return render_template("forgot_password.html", role=role, error=error, info=info, email=email, question=question)

    if not is_strong_password(new_password):
        error = "Password must be 12+ with upper/lower/number/symbol"
        return render_template("forgot_password.html", role=role, error=error, info=info, email=email, question=question)

    u.password = generate_password_hash(new_password)
    db.session.commit()

    return redirect(url_for("login", role=role))


# ============================================================
# ADMIN (PIN ONLY)
# ============================================================
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if session.get("admin"):
        return redirect(url_for("admin_panel"))

    error = None
    if request.method == "POST":
        pin = (request.form.get("pin") or "").strip()

        if (not pin.isdigit()) or (len(pin) != 4):
            error = "PIN must be exactly 4 digits"
        elif pin != ADMIN_PIN:
            error = "Wrong PIN"
        else:
            session.permanent = True
            session.pop("user_id", None)
            session.pop("role", None)
            session["admin"] = True
            return redirect(url_for("admin_panel"))

    return render_template("admin_login.html", error=error)


@app.route("/admin/panel")
@admin_required
def admin_panel():
    return render_template("admin_panel.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/reports")
@admin_required
def admin_reports():
    stats = {
        "total_donations": Donation.query.count(),
        "pending_donations": Donation.query.filter_by(status="Pending").count(),
        "approved_donations": Donation.query.filter_by(status="Approved").count(),
        "requests_received": Request.query.count(),
        "req_pending": Request.query.filter_by(status="Pending").count(),
        "req_approved": Request.query.filter_by(status="Approved").count(),
        "req_completed": Request.query.filter_by(status="Completed").count(),
    }
    return render_template("admin_dashboard.html", stats=stats)


# ============================================================
# PROVIDER ROUTES
# ============================================================
@app.route("/provider/dashboard")
@login_required(role="provider")
def provider_dashboard():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    total_donations = Donation.query.filter_by(provider_id=user.id).count()
    pending_donations = Donation.query.filter_by(provider_id=user.id, status="Pending").count()
    approved_donations = Donation.query.filter_by(provider_id=user.id, status="Approved").count()

    requests_received = (
        db.session.query(Request)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Donation.provider_id == user.id)
        .count()
    )

    latest_donations = (
        Donation.query
        .filter_by(provider_id=user.id)
        .order_by(Donation.id.desc())
        .limit(6)
        .all()
    )

    rows = (
        db.session.query(Request, Donation, Beneficiary)
        .join(Donation, Request.donation_id == Donation.id)
        .join(Beneficiary, Request.beneficiary_id == Beneficiary.id)
        .filter(Donation.provider_id == user.id)
        .order_by(Request.id.desc())
        .limit(6)
        .all()
    )

    latest_requests = []
    for r, d, b in rows:
        latest_requests.append({
            "id": r.id,
            "beneficiary_name": b.full_name,
            "donation_title": d.title,
            "status": r.status,
            "created_at": r.created_at
        })

    stats = {
        "total_donations": total_donations,
        "pending_donations": pending_donations,
        "approved_donations": approved_donations,
        "total_requests": requests_received
    }

    # ✅ ADDED ONLY — send provider_location to dashboard
    provider_location = get_provider_location(user.id)

    return render_template(
        "provider_dashboard.html",
        user=user,
        stats=stats,
        latest_donations=latest_donations,
        latest_requests=latest_requests,
        provider_location=provider_location
    )


# ============================================================
# ✅ ADDED ONLY — Provider Location Page (GET/POST)
# ============================================================
@app.route("/provider/location", methods=["GET", "POST"])
@login_required(role="provider")
def provider_location():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    error = None
    loc = get_provider_location(user.id)

    if request.method == "POST":
        address_line1 = (request.form.get("address_line1") or "").strip()
        address_line2 = (request.form.get("address_line2") or "").strip()
        city = (request.form.get("city") or "").strip()
        state = (request.form.get("state") or "").strip()
        notes = (request.form.get("notes") or "").strip()

        lat_raw = (request.form.get("latitude") or "").strip()
        lng_raw = (request.form.get("longitude") or "").strip()

        if not address_line1 or not city or not state:
            error = "Please fill Address Line 1, City, and State."
            return render_template("provider_location.html", user=user, provider_location=loc, error=error)

        try:
            lat = float(lat_raw)
            lng = float(lng_raw)
        except Exception:
            error = "Please pin your location on the map before saving."
            return render_template("provider_location.html", user=user, provider_location=loc, error=error)

        if loc:
            loc.address_line1 = address_line1
            loc.address_line2 = address_line2
            loc.city = city
            loc.state = state
            loc.notes = notes
            loc.latitude = lat
            loc.longitude = lng
        else:
            loc = ProviderLocation(
                provider_id=user.id,
                address_line1=address_line1,
                address_line2=address_line2,
                city=city,
                state=state,
                notes=notes,
                latitude=lat,
                longitude=lng
            )
            db.session.add(loc)

        db.session.commit()
        return redirect(url_for("provider_dashboard"))

    return render_template("provider_location.html", user=user, provider_location=loc, error=error)


@app.route("/provider/requests/<int:request_id>/detail")
@login_required(role="provider")
def provider_request_detail(request_id):
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    req = Request.query.get_or_404(request_id)
    donation = Donation.query.get(req.donation_id) if req.donation_id else None
    beneficiary = Beneficiary.query.get(req.beneficiary_id) if req.beneficiary_id else None

    if not donation or donation.provider_id != user.id:
        return redirect(url_for("provider_requests_received"))

    # ✅ UPDATED LOGIC (still safe): prefer request pickup location, else provider saved coords, else provider.address
    loc_obj = get_provider_location(user.id)
    embed_map_url = None
    open_map_url = None

    if (req.provider_pickup_location or "").strip():
        location_text = (req.provider_pickup_location or "").strip()
        embed_map_url, open_map_url = build_google_maps_urls(location_text)
    elif loc_obj and loc_obj.latitude is not None and loc_obj.longitude is not None:
        embed_map_url, open_map_url = build_google_maps_urls_from_coords(loc_obj.latitude, loc_obj.longitude)
    else:
        location_text = (user.address or "").strip()
        embed_map_url, open_map_url = build_google_maps_urls(location_text)

    return render_template(
        "provider_request_detail.html",
        user=user,
        req=req,
        donation=donation,
        beneficiary=beneficiary,
        embed_map_url=embed_map_url,
        open_map_url=open_map_url
    )


@app.route("/dev/provider-seed")
@login_required(role="provider")
def dev_provider_seed():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        return "No provider logged in"

    donation = Donation.query.filter_by(provider_id=user.id).first()
    if not donation:
        donation = Donation(
            provider_id=user.id,
            title="Demo Donation Box",
            description="Rice, bread, vegetables",
            quantity="10 boxes",
            category="Food",
            status="Approved",
            created_at=now_str()
        )
        db.session.add(donation)
        db.session.commit()

    beneficiary = Beneficiary.query.filter_by(email="demo_beneficiary@fsdp.com").first()
    if not beneficiary:
        beneficiary = Beneficiary(
            full_name="Demo Beneficiary",
            phone="99998888",
            email="demo_beneficiary@fsdp.com",
            password=generate_password_hash("DemoPassword123!"),
            address="Muscat",
            category="Family",
            created_at=now_str(),
            email_verified=True
        )
        db.session.add(beneficiary)
        db.session.commit()

    req = Request.query.filter_by(donation_id=donation.id, beneficiary_id=beneficiary.id).first()
    if not req:
        req = Request(
            donation_id=donation.id,
            beneficiary_id=beneficiary.id,
            status="Approved",
            created_at=now_str(),
            approved_at=now_str(),
            pickup_time="2026-01-10 10:00",
            provider_pickup_location=user.address
        )
        db.session.add(req)
        db.session.commit()

    return redirect(url_for("provider_dashboard"))


@app.route("/provider/donation/add", methods=["GET", "POST"])
@login_required(role="provider")
def provider_add_donation():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    msg = None
    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
        quantity = request.form.get("quantity", "").strip()
        category = request.form.get("category", "").strip()

        d = Donation(
            provider_id=user.id,
            title=title,
            description=description,
            quantity=quantity,
            category=category,
            status="Pending",
            created_at=now_str()
        )
        db.session.add(d)
        db.session.commit()
        msg = "Donation saved successfully (Status: Pending)"

    return render_template("provider_add_donation.html", user=user, msg=msg)


@app.route("/provider/my-donations")
@login_required(role="provider")
def provider_my_donations():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    donations = Donation.query.filter_by(provider_id=user.id).order_by(Donation.id.desc()).all()

    if template_exists("provider_my_donations.html"):
        return render_template("provider_my_donations.html", user=user, donations=donations)

    html = "<h2>My Donations</h2><p><a href='/provider/dashboard'>Back</a></p><ul>"
    for d in donations:
        html += f"<li><b>{d.title}</b> - {d.status} - {d.created_at}</li>"
    html += "</ul>"
    return html


@app.route("/provider/requests-received")
@login_required(role="provider")
def provider_requests_received():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    rows = (
        db.session.query(Request, Donation, Beneficiary)
        .join(Donation, Request.donation_id == Donation.id)
        .join(Beneficiary, Request.beneficiary_id == Beneficiary.id)
        .filter(Donation.provider_id == user.id)
        .order_by(Request.id.desc())
        .all()
    )

    if template_exists("provider_requests_received.html"):
        return render_template("provider_requests_received.html", user=user, rows=rows)

    html = "<h2>Requests Received</h2><p><a href='/provider/dashboard'>Back</a></p><ul>"
    for r, d, b in rows:
        html += f"<li><b>{b.full_name}</b> requested <b>{d.title}</b> - {r.status} - {r.created_at}</li>"
    html += "</ul>"
    return html


@app.route("/provider/reports")
@login_required(role="provider")
def provider_reports():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    total_d = Donation.query.filter_by(provider_id=user.id).count()
    pending_d = Donation.query.filter_by(provider_id=user.id, status="Pending").count()
    approved_d = Donation.query.filter_by(provider_id=user.id, status="Approved").count()

    req_received = (
        db.session.query(Request)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Donation.provider_id == user.id)
        .count()
    )

    req_pending = (
        db.session.query(Request)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Donation.provider_id == user.id, Request.status == "Pending")
        .count()
    )
    req_approved = (
        db.session.query(Request)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Donation.provider_id == user.id, Request.status == "Approved")
        .count()
    )
    req_completed = (
        db.session.query(Request)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Donation.provider_id == user.id, Request.status == "Completed")
        .count()
    )

    stats = {
        "total_donations": total_d,
        "pending_donations": pending_d,
        "approved_donations": approved_d,
        "requests_received": req_received,
        "req_pending": req_pending,
        "req_approved": req_approved,
        "req_completed": req_completed,
        "total": total_d,
        "pending": pending_d,
        "approved": approved_d,
        "requests": req_received
    }

    if template_exists("provider_reports.html"):
        return render_template("provider_reports.html", user=user, stats=stats)

    return f"""
    <h2>Reports / Stats</h2>
    <p><a href="/provider/dashboard">Back</a></p>
    <ul>
      <li>Total Donations: {stats["total"]}</li>
      <li>Pending: {stats["pending"]}</li>
      <li>Approved: {stats["approved"]}</li>
      <li>Requests Received: {stats["requests"]}</li>
    </ul>
    """


@app.route("/provider/profile/edit", methods=["GET", "POST"])
@login_required(role="provider")
def provider_profile_edit():
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    if request.method == "POST":
        user.full_name = request.form.get("full_name", user.full_name)
        user.phone = request.form.get("phone", user.phone)
        user.address = request.form.get("address", user.address)

        file = request.files.get("store_image")
        filename = save_uploaded_file(file)
        if filename:
            user.image = filename

        db.session.commit()
        return redirect(url_for("provider_dashboard"))

    return render_template("provider_edit_profile.html", user=user)


@app.route("/provider/requests/<int:request_id>/approve", methods=["POST"])
@login_required(role="provider")
def provider_approve_request(request_id):
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    req = Request.query.get_or_404(request_id)
    donation = Donation.query.get(req.donation_id) if req.donation_id else None

    if not donation or donation.provider_id != user.id:
        return redirect(url_for("provider_requests_received"))

    req.status = "Approved"
    req.approved_at = now_str()
    db.session.commit()
    return redirect(url_for("provider_requests_received"))


@app.route("/provider/requests/<int:request_id>/reject", methods=["POST"])
@login_required(role="provider")
def provider_reject_request(request_id):
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    req = Request.query.get_or_404(request_id)
    donation = Donation.query.get(req.donation_id) if req.donation_id else None

    if not donation or donation.provider_id != user.id:
        return redirect(url_for("provider_requests_received"))

    req.status = "Rejected"
    db.session.commit()
    return redirect(url_for("provider_requests_received"))


@app.route("/provider/requests/<int:request_id>/schedule", methods=["GET", "POST"])
@login_required(role="provider")
def provider_request_schedule(request_id):
    user = Provider.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="provider"))

    req_obj = Request.query.get_or_404(request_id)
    donation = Donation.query.get(req_obj.donation_id) if req_obj.donation_id else None
    beneficiary = Beneficiary.query.get(req_obj.beneficiary_id) if req_obj.beneficiary_id else None

    if not donation or donation.provider_id != user.id:
        return redirect(url_for("provider_requests_received"))

    if request.method == "POST":
        pickup_time = (request.form.get("pickup_time") or "").strip()
        location = (request.form.get("provider_pickup_location") or "").strip()

        req_obj.pickup_time = pickup_time if pickup_time else req_obj.pickup_time
        req_obj.provider_pickup_location = location if location else req_obj.provider_pickup_location

        db.session.commit()
        return redirect(url_for("provider_requests_received"))

    if template_exists("provider_request_schedule.html"):
        return render_template(
            "provider_request_schedule.html",
            user=user,
            req=req_obj,
            donation=donation,
            beneficiary=beneficiary
        )

    return f"""
    <h2>Schedule Pickup</h2>
    <p><a href="{url_for('provider_requests_received')}">Back</a></p>
    <form method="post">
      <label>Pickup time</label><br>
      <input name="pickup_time" value="{req_obj.pickup_time or ''}" placeholder="YYYY-MM-DD HH:MM"><br><br>
      <label>Pickup location</label><br>
      <input name="provider_pickup_location" value="{req_obj.provider_pickup_location or ''}" placeholder="Location"><br><br>
      <button type="submit">Save</button>
    </form>
    """


# ============================================================
# BENEFICIARY ROUTES
# ============================================================
@app.route("/beneficiary/dashboard")
@login_required(role="beneficiary")
def beneficiary_dashboard():
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    available_count = Donation.query.filter_by(status="Approved").count()

    my_requests_total = Request.query.filter_by(beneficiary_id=user.id).count()
    my_requests_pending = Request.query.filter_by(beneficiary_id=user.id, status="Pending").count()
    my_requests_approved = Request.query.filter_by(beneficiary_id=user.id, status="Approved").count()
    my_requests_completed = Request.query.filter_by(beneficiary_id=user.id, status="Completed").count()

    latest_available = (
        Donation.query
        .filter_by(status="Approved")
        .order_by(Donation.id.desc())
        .limit(6)
        .all()
    )

    rows = (
        db.session.query(Request, Donation)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Request.beneficiary_id == user.id)
        .order_by(Request.id.desc())
        .limit(6)
        .all()
    )

    my_latest_requests = []
    for r, d in rows:
        my_latest_requests.append({
            "id": r.id,
            "donation_title": d.title,
            "status": r.status,
            "created_at": r.created_at
        })

    stats = {
        "available_count": available_count,
        "my_requests_total": my_requests_total,
        "my_requests_pending": my_requests_pending,
        "my_requests_approved": my_requests_approved,
        "my_requests_completed": my_requests_completed,
    }

    return render_template(
        "beneficiary_dashboard.html",
        user=user,
        stats=stats,
        latest_available=latest_available,
        my_latest_requests=my_latest_requests
    )


@app.route("/beneficiary/available")
@login_required(role="beneficiary")
def beneficiary_available_donations():
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    q = (request.args.get("q") or "").strip()
    cat = (request.args.get("cat") or "").strip()

    base_query = (
        db.session.query(Donation)
        .join(Provider, Donation.provider_id == Provider.id)
        .filter(Donation.status == "Approved")
        .order_by(Donation.id.desc())
    )

    if q:
        like = f"%{q}%"
        base_query = base_query.filter(
            or_(
                Donation.title.ilike(like),
                Donation.category.ilike(like),
                Provider.full_name.ilike(like),
            )
        )

    if cat:
        base_query = base_query.filter(Donation.category == cat)

    donations = base_query.all()

    categories = (
        db.session.query(Donation.category)
        .filter(Donation.status == "Approved")
        .filter(Donation.category.isnot(None))
        .distinct()
        .order_by(Donation.category.asc())
        .all()
    )
    categories = [c[0] for c in categories if c[0]]

    return render_template(
        "beneficiary_available_donations.html",
        user=user,
        donations=donations,
        categories=categories,
        q=q,
        cat=cat
    )


@app.route("/beneficiary/donations/<int:donation_id>/details")
@login_required(role="beneficiary")
def beneficiary_donation_details(donation_id):
    return redirect(url_for("beneficiary_available_donations"))


@app.route("/beneficiary/requests")
@login_required(role="beneficiary")
def beneficiary_requests():
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    sort = (request.args.get("sort") or "new").strip()
    page = int(request.args.get("page") or 1)
    per_page = 6

    query = (
        db.session.query(Request, Donation)
        .join(Donation, Request.donation_id == Donation.id)
        .filter(Request.beneficiary_id == user.id)
    )

    if q:
        like = f"%{q}%"
        query = query.filter(Donation.title.ilike(like))

    if status:
        query = query.filter(Request.status == status)

    if sort == "old":
        query = query.order_by(Request.id.asc())
    else:
        query = query.order_by(Request.id.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    requests_list = []
    for r, d in pagination.items:
        requests_list.append({
            "id": r.id,
            "donation_title": d.title,
            "status": r.status,
            "created_at": r.created_at,
            "donation_category": d.category,
            "donation_quantity": d.quantity,
            "donation_description": d.description,
            "approved_at": r.approved_at,
            "pickup_time": r.pickup_time,
            "provider_pickup_location": r.provider_pickup_location,
        })

    base = Request.query.filter_by(beneficiary_id=user.id)
    summary = {
        "total": base.count(),
        "pending": base.filter(Request.status == "Pending").count(),
        "approved": base.filter(Request.status == "Approved").count(),
        "completed": base.filter(Request.status == "Completed").count(),
        "rejected": base.filter(Request.status == "Rejected").count(),
    }

    if template_exists("beneficiary_requests.html"):
        return render_template(
            "beneficiary_requests.html",
            user=user,
            requests=requests_list,
            summary=summary,
            page=pagination.page,
            pages=(pagination.pages or 1),
            q=q,
            status=status,
            sort=sort
        )

    return render_template("success.html", message="Template beneficiary_requests.html not found.")


@app.route("/beneficiary/requests/<int:request_id>/detail")
@login_required(role="beneficiary")
def beneficiary_request_detail(request_id):
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    req = Request.query.get_or_404(request_id)

    if req.beneficiary_id != user.id:
        return redirect(url_for("beneficiary_requests"))

    donation = Donation.query.get(req.donation_id) if req.donation_id else None
    provider = Provider.query.get(donation.provider_id) if donation and donation.provider_id else None

    duration = "-"
    try:
        if req.created_at:
            created_dt = datetime.strptime(req.created_at, "%Y-%m-%d %H:%M")
            diff = datetime.now() - created_dt
            days = diff.days
            hours = diff.seconds // 3600
            minutes = (diff.seconds % 3600) // 60
            duration = f"{days}d {hours}h {minutes}m" if days else f"{hours}h {minutes}m"
    except Exception:
        duration = "-"

    return render_template(
        "beneficiary_request_detail.html",
        user=user,
        req=req,
        donation=donation,
        provider=provider,
        duration=duration
    )


@app.route("/beneficiary/requests/<int:request_id>/state")
@login_required(role="beneficiary")
def beneficiary_request_state(request_id):
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    req = Request.query.get_or_404(request_id)

    if req.beneficiary_id != user.id:
        return redirect(url_for("beneficiary_requests"))

    donation = Donation.query.get(req.donation_id) if req.donation_id else None
    provider = Provider.query.get(donation.provider_id) if donation and donation.provider_id else None

    # ✅ ADDED ONLY — prefer request pickup location, else provider saved coords, else provider.address
    embed_map_url = None
    open_map_url = None

    if (req.provider_pickup_location or "").strip():
        location_text = (req.provider_pickup_location or "").strip()
        embed_map_url, open_map_url = build_google_maps_urls(location_text)
    else:
        prov_loc = get_provider_location(provider.id if provider else None)
        if prov_loc and prov_loc.latitude is not None and prov_loc.longitude is not None:
            embed_map_url, open_map_url = build_google_maps_urls_from_coords(prov_loc.latitude, prov_loc.longitude)
        else:
            location_text = ((provider.address if provider else "") or "").strip()
            embed_map_url, open_map_url = build_google_maps_urls(location_text)

    if template_exists("beneficiary_request_state.html"):
        return render_template(
            "beneficiary_request_state.html",
            user=user,
            req=req,
            donation=donation,
            provider=provider,
            embed_map_url=embed_map_url,
            open_map_url=open_map_url
        )

    return f"<h3>Status: {req.status}</h3>"


@app.route("/beneficiary/requests/<int:request_id>/start", methods=["POST"])
@login_required(role="beneficiary")
def beneficiary_request_start(request_id):
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    req_obj = Request.query.get_or_404(request_id)

    if req_obj.beneficiary_id != user.id:
        return redirect(url_for("beneficiary_requests"))

    if (req_obj.status or "").lower() != "approved":
        return redirect(url_for("beneficiary_request_state", request_id=request_id))

    req_obj.started_at = now_str()
    req_obj.status = "Completed"
    db.session.commit()
    return redirect(url_for("beneficiary_request_state", request_id=request_id))


@app.route("/beneficiary/requests/<int:request_id>/cancel", methods=["POST"])
@login_required(role="beneficiary")
def cancel_request(request_id):
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    req = Request.query.get_or_404(request_id)

    if req.beneficiary_id != user.id:
        return redirect(url_for("beneficiary_requests"))

    if (req.status or "Pending").lower() != "pending":
        return redirect(url_for("beneficiary_requests"))

    req.status = "Rejected"
    db.session.commit()
    return redirect(url_for("beneficiary_requests"))


@app.route("/beneficiary/request/<int:donation_id>", methods=["POST"])
@login_required(role="beneficiary")
def beneficiary_request_donation(donation_id):
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    donation = Donation.query.get(donation_id)
    if not donation or donation.status != "Approved":
        return redirect(url_for("beneficiary_dashboard"))

    existing = Request.query.filter_by(donation_id=donation_id, beneficiary_id=user.id).first()
    if existing:
        return redirect(url_for("beneficiary_dashboard"))

    r = Request(
        donation_id=donation_id,
        beneficiary_id=user.id,
        status="Pending",
        created_at=now_str()
    )
    db.session.add(r)
    db.session.commit()
    return redirect(url_for("beneficiary_dashboard"))


@app.route("/beneficiary/profile/edit", methods=["GET", "POST"])
@login_required(role="beneficiary")
def edit_beneficiary_profile():
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        session.clear()
        return redirect(url_for("login", role="beneficiary"))

    if request.method == "POST":
        user.full_name = request.form.get("full_name", user.full_name)
        user.phone = request.form.get("phone", user.phone)
        user.address = request.form.get("address", user.address)

        file = request.files.get("document")
        filename = save_uploaded_file(file)
        if filename:
            user.document = filename

        db.session.commit()
        return redirect(url_for("beneficiary_dashboard"))

    return render_template("beneficiary_edit_profile.html", user=user)


# ----------------------------
# Logout (provider/beneficiary)
# ----------------------------
@app.route("/logout")
def logout():
    admin_flag = session.get("admin")
    session.clear()
    if admin_flag:
        session["admin"] = True
    return redirect(url_for("index"))


# ============================================================
# ✅ DEV – SEED DEMO DATA (ADDED ONLY)
# ============================================================
@app.route("/dev/seed")
@login_required(role="beneficiary")
def dev_seed_data():
    user = Beneficiary.query.get(session.get("user_id"))
    if not user:
        return "No beneficiary logged in"

    provider = Provider.query.filter_by(email="demo_provider@fsdp.com").first()
    if not provider:
        provider = Provider(
            full_name="Demo Provider",
            phone="99999999",
            email="demo_provider@fsdp.com",
            password=generate_password_hash("DemoPassword123!"),
            address="Muscat",
            category="Restaurant",
            verification_status="Approved",
            created_at=now_str(),
            email_verified=True
        )
        db.session.add(provider)
        db.session.commit()

    donation = Donation.query.filter_by(title="Demo Food Box").first()
    if not donation:
        donation = Donation(
            provider_id=provider.id,
            title="Demo Food Box",
            description="Rice, bread, vegetables",
            quantity="5 boxes",
            category="Food",
            status="Approved",
            created_at=now_str()
        )
        db.session.add(donation)
        db.session.commit()

    existing = Request.query.filter_by(donation_id=donation.id, beneficiary_id=user.id).first()
    if not existing:
        r = Request(
            donation_id=donation.id,
            beneficiary_id=user.id,
            status="Pending",
            created_at=now_str()
        )
        db.session.add(r)
        db.session.commit()

    return redirect(url_for("beneficiary_requests"))


# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
